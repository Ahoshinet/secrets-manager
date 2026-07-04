//! Runtime configuration and passphrase acquisition.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use secrecy::SecretString;

/// Server/runtime configuration, sourced from environment variables with
/// safe local-dev defaults. Production (systemd) supplies these via the
/// unit's `Environment=` / `LoadCredential=`.
pub struct Config {
    pub db_path: PathBuf,
    pub audit_path: PathBuf,
    pub bind_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let db_path = std::env::var_os("SECRETS_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("secrets.db"));

        let audit_path = std::env::var_os("SECRETS_AUDIT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("audit.jsonl"));

        // Default to loopback only. TLS is terminated by nginx in front.
        let bind_str =
            std::env::var("SECRETS_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
        let bind_addr: SocketAddr = bind_str
            .parse()
            .with_context(|| "SECRETS_BIND is not a valid socket address")?;

        if !bind_addr.ip().is_loopback() {
            eprintln!(
                "[warn] binding to non-loopback address {bind_addr}; the server \
                 must only be exposed via a TLS-terminating reverse proxy"
            );
        }

        Ok(Config {
            db_path,
            audit_path,
            bind_addr,
        })
    }
}

/// Obtain the master passphrase.
///
/// Priority: `SECRETS_PASSPHRASE` (systemd credential) → interactive TTY
/// prompt. Fails loudly if neither is available (never silently proceed).
pub fn acquire_passphrase() -> Result<SecretString> {
    if let Ok(p) = std::env::var("SECRETS_PASSPHRASE") {
        if p.is_empty() {
            bail!("SECRETS_PASSPHRASE is set but empty");
        }
        return Ok(SecretString::from(p));
    }

    if std::io::stdin().is_terminal() {
        let entered = rpassword::prompt_password("Master passphrase: ")
            .context("failed to read passphrase from terminal")?;
        if entered.is_empty() {
            bail!("passphrase must not be empty");
        }
        Ok(SecretString::from(entered))
    } else {
        bail!(
            "no passphrase available: set SECRETS_PASSPHRASE or run attached to a terminal"
        )
    }
}
