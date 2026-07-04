//! CLI command definitions and their implementations.

use std::io::IsTerminal;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use secrets_crypto::{generate_token, hash_token};

use crate::app::{self, AppState};
use crate::audit::AuditLog;
use crate::config::{acquire_passphrase, Config};
use crate::{crypto_state, db, lock, repo};

#[derive(Parser)]
#[command(
    name = "secrets-server",
    about = "Secrets Manager server and admin CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the HTTP server (binds loopback only).
    Serve,
    /// Manage access tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Change the master passphrase and re-encrypt every stored secret.
    Rekey,
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Issue a new token. The value is printed once and never stored.
    Create {
        #[arg(long)]
        name: String,
        /// Restrict the token to a single project (omit for all projects).
        #[arg(long)]
        project: Option<String>,
        /// Days until the token expires.
        #[arg(long, default_value_t = 90, conflicts_with = "no_expiry")]
        ttl_days: u32,
        /// Issue a token that never expires (requires manual revocation).
        #[arg(long)]
        no_expiry: bool,
    },
    /// Revoke all active tokens with the given name.
    Revoke {
        #[arg(long)]
        name: String,
    },
    /// List tokens (names/scopes only; never the token or its hash).
    List,
}

/// Parse arguments and dispatch. Called from `main`.
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve => serve(),
        Command::Token { cmd } => match cmd {
            TokenCmd::Create {
                name,
                project,
                ttl_days,
                no_expiry,
            } => token_create(
                &name,
                project.as_deref(),
                (!no_expiry).then_some(ttl_days),
            ),
            TokenCmd::Revoke { name } => token_revoke(&name),
            TokenCmd::List => token_list(),
        },
        Command::Rekey => rekey(),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn serve() -> Result<()> {
    let cfg = Config::from_env()?;

    // Exclusive DB lock for the server's lifetime: prevents a concurrent
    // `rekey` from swapping the master key under a running process.
    let _db_lock = lock::acquire(
        &cfg.db_path,
        "another secrets-server appears to be running on this database",
    )?;

    let passphrase = acquire_passphrase()?;

    let conn = db::open(&cfg.db_path)?;
    // Derive + verify the key BEFORE binding the socket. A wrong
    // passphrase aborts here rather than serving with a bad key.
    let key = crypto_state::init_or_verify(&conn, &passphrase)?;
    drop(passphrase);

    let audit = AuditLog::open(&cfg.audit_path)?;

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        key: Arc::new(key),
        audit: Arc::new(audit),
    };
    let router = app::router(state);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(cfg.bind_addr).await?;
        eprintln!("[info] listening on http://{}", cfg.bind_addr);
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        Ok::<(), anyhow::Error>(())
    })?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("[info] shutting down");
}

fn token_create(name: &str, project: Option<&str>, ttl_days: Option<u32>) -> Result<()> {
    if !valid_name(name) {
        bail!("invalid token name (allowed: alphanumeric, '-', '_')");
    }
    if let Some(p) = project {
        if !valid_name(p) {
            bail!("invalid project scope name");
        }
    }
    if ttl_days == Some(0) {
        bail!("--ttl-days must be at least 1 (or use --no-expiry)");
    }

    let expires_at = ttl_days
        .map(|days| {
            (time::OffsetDateTime::now_utc() + time::Duration::days(i64::from(days)))
                .format(&time::format_description::well_known::Rfc3339)
                .context("failed to format expiry timestamp")
        })
        .transpose()?;

    let cfg = Config::from_env()?;
    let conn = db::open(&cfg.db_path)?;

    let token = generate_token();
    let hash = hash_token(token.expose_secret());
    repo::insert_token(&conn, name, &hash, project, expires_at.as_deref())?;

    // Printed exactly once, to stdout. Never logged or stored in plaintext.
    println!("Token created (name: {name}).");
    match project {
        Some(p) => println!("Scope: project '{p}'"),
        None => println!("Scope: all projects"),
    }
    match &expires_at {
        Some(exp) => println!("Expires: {exp}"),
        None => println!("Expires: never (revoke manually when no longer needed)"),
    }
    println!("Store it now — it is shown only once:");
    println!("{}", token.expose_secret());
    Ok(())
}

fn token_revoke(name: &str) -> Result<()> {
    let cfg = Config::from_env()?;
    let conn = db::open(&cfg.db_path)?;
    let n = repo::revoke_token(&conn, name)?;
    println!("Revoked {n} token(s) named '{name}'.");
    Ok(())
}

fn token_list() -> Result<()> {
    let cfg = Config::from_env()?;
    let conn = db::open(&cfg.db_path)?;
    let tokens = repo::list_tokens(&conn)?;
    if tokens.is_empty() {
        println!("(no tokens)");
        return Ok(());
    }
    println!(
        "{:<20} {:<16} {:<26} {:<26} REVOKED",
        "NAME", "SCOPE", "CREATED", "EXPIRES"
    );
    for t in tokens {
        println!(
            "{:<20} {:<16} {:<26} {:<26} {}",
            t.name,
            t.scope.as_deref().unwrap_or("(all)"),
            t.created_at,
            t.expires_at.as_deref().unwrap_or("(never)"),
            if t.revoked { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn rekey() -> Result<()> {
    let cfg = Config::from_env()?;

    // Refuse to rekey while a server holds the database. A running server
    // caches the old master key in memory and would keep writing old-key
    // ciphertext after the rekey, corrupting those secrets.
    let _db_lock = lock::acquire(
        &cfg.db_path,
        "stop the running secrets-server before rekeying",
    )?;

    let current = acquire_passphrase()?;
    let new_passphrase = acquire_new_passphrase(&current)?;

    let conn = db::open(&cfg.db_path)?;
    let count = crypto_state::rekey(&conn, &current, &new_passphrase)?;
    println!("Re-encrypted {count} secret(s) with a new master passphrase.");
    Ok(())
}

fn acquire_new_passphrase(current: &SecretString) -> Result<SecretString> {
    if let Ok(p) = std::env::var("SECRETS_NEW_PASSPHRASE") {
        if p.is_empty() {
            bail!("SECRETS_NEW_PASSPHRASE is set but empty");
        }
        if p == current.expose_secret() {
            bail!("new passphrase must differ from the current passphrase");
        }
        return Ok(SecretString::from(p));
    }

    if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("New master passphrase: ")
            .context("failed to read new passphrase from terminal")?;
        if first.is_empty() {
            bail!("new passphrase must not be empty");
        }
        let second = rpassword::prompt_password("Confirm new master passphrase: ")
            .context("failed to read passphrase confirmation from terminal")?;
        if first != second {
            bail!("new passphrase confirmation did not match");
        }
        if first == current.expose_secret() {
            bail!("new passphrase must differ from the current passphrase");
        }
        Ok(SecretString::from(first))
    } else {
        bail!(
            "no new passphrase available: set SECRETS_NEW_PASSPHRASE or run attached to a terminal"
        )
    }
}
