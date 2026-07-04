//! CLI command definitions and their implementations.

use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use secrecy::ExposeSecret;
use secrets_crypto::{generate_token, hash_token};

use crate::app::{self, AppState};
use crate::audit::AuditLog;
use crate::config::{acquire_passphrase, Config};
use crate::{crypto_state, db, repo};

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
            TokenCmd::Create { name, project } => token_create(&name, project.as_deref()),
            TokenCmd::Revoke { name } => token_revoke(&name),
            TokenCmd::List => token_list(),
        },
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

fn token_create(name: &str, project: Option<&str>) -> Result<()> {
    if !valid_name(name) {
        bail!("invalid token name (allowed: alphanumeric, '-', '_')");
    }
    if let Some(p) = project {
        if !valid_name(p) {
            bail!("invalid project scope name");
        }
    }

    let cfg = Config::from_env()?;
    let conn = db::open(&cfg.db_path)?;

    let token = generate_token();
    let hash = hash_token(token.expose_secret());
    repo::insert_token(&conn, name, &hash, project)?;

    // Printed exactly once, to stdout. Never logged or stored in plaintext.
    println!("Token created (name: {name}).");
    match project {
        Some(p) => println!("Scope: project '{p}'"),
        None => println!("Scope: all projects"),
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
        "{:<20} {:<16} {:<26} REVOKED",
        "NAME", "SCOPE", "CREATED"
    );
    for t in tokens {
        println!(
            "{:<20} {:<16} {:<26} {}",
            t.name,
            t.scope.as_deref().unwrap_or("(all)"),
            t.created_at,
            if t.revoked { "yes" } else { "no" }
        );
    }
    Ok(())
}
