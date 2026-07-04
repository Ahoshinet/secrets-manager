//! Client configuration loading and token resolution.
//!
//! Config file: `~/.config/secrets/config.toml` (override with
//! `SECRETS_CONFIG`). On Unix its permissions are checked and a warning is
//! emitted if they are more permissive than `600`.
//!
//! Token precedence: `SECRETS_TOKEN` env (for CI) > config file.
//! Server URL precedence: `SECRETS_SERVER_URL` env > config file.

use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Deserialize;

use crate::error::{Error, Result};

pub struct Config {
    pub server_url: String,
    pub token: SecretString,
}

#[derive(Deserialize, Default)]
struct FileConfig {
    server_url: Option<String>,
    token: Option<String>,
}

/// Resolve the path to the config file.
pub fn config_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SECRETS_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| Error::Config("cannot determine home directory".to_string()))?;
    Ok(home.join(".config").join("secrets").join("config.toml"))
}

/// Load configuration, applying env overrides.
pub fn load() -> Result<Config> {
    let path = config_path()?;
    let file: FileConfig = if path.exists() {
        check_permissions(&path);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            Error::Config(format!("failed to read config at {}: {e}", path.display()))
        })?;
        toml::from_str(&text).map_err(|e| {
            Error::Config(format!("failed to parse config at {}: {e}", path.display()))
        })?
    } else {
        FileConfig::default()
    };

    let server_url = std::env::var("SECRETS_SERVER_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .or(file.server_url)
        .ok_or_else(|| {
            Error::Config(
                "no server_url configured (set it in the config file or SECRETS_SERVER_URL)"
                    .to_string(),
            )
        })?;

    let token = std::env::var("SECRETS_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .or(file.token)
        .ok_or_else(|| {
            Error::Config("no token configured (set SECRETS_TOKEN or the config file)".to_string())
        })?;

    Ok(Config {
        server_url: server_url.trim_end_matches('/').to_string(),
        token: SecretString::from(token),
    })
}

#[cfg(unix)]
fn check_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            eprintln!(
                "[warn] {} has permissions {:04o}; it should be 600 to protect the token",
                path.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) {
    // File permission model differs on Windows; skipped.
}
