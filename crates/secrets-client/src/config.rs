//! Client configuration loading and token resolution.
//!
//! Config file: `~/.config/secrets/config.toml` (override with
//! `SECRETS_CONFIG`). On Unix its permissions are checked and a warning is
//! emitted if they are more permissive than `600`.
//!
//! Token precedence: `SECRETS_TOKEN` env (for CI) > config file.
//! Server URL precedence: `SECRETS_SERVER_URL` env > config file.
//!
//! The server URL must use `https`. Plain `http` is accepted only for
//! loopback hosts (`127.0.0.0/8`, `::1`, `localhost`) to support the
//! same-host deployment where TLS is terminated by a reverse proxy and
//! the server itself listens on loopback.

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

    validate_server_url(&server_url)?;

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

/// Enforce the transport contract: `https` everywhere, plain `http` only
/// to loopback. Rejects URLs with userinfo, query, or fragment parts so a
/// malformed base URL can never smuggle extra request components.
fn validate_server_url(raw: &str) -> Result<()> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| Error::Config(format!("invalid server_url: {e}")))?;

    match parsed.scheme() {
        "https" => {}
        "http" => {
            if !is_loopback_host(&parsed) {
                return Err(Error::Config(
                    "server_url must use https (plain http is allowed only for loopback \
                     addresses such as http://127.0.0.1)"
                        .to_string(),
                ));
            }
        }
        other => {
            return Err(Error::Config(format!(
                "server_url has unsupported scheme `{other}` (expected https)"
            )));
        }
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::Config(
            "server_url must not contain userinfo".to_string(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(Error::Config(
            "server_url must not contain a query or fragment".to_string(),
        ));
    }
    Ok(())
}

fn is_loopback_host(parsed: &url::Url) -> bool {
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        // The url crate lowercases registered names.
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
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

#[cfg(test)]
mod tests {
    use super::validate_server_url;

    #[test]
    fn https_urls_are_accepted() {
        assert!(validate_server_url("https://secrets.example.com").is_ok());
        assert!(validate_server_url("https://secrets.example.com:8443/base").is_ok());
    }

    #[test]
    fn http_is_accepted_only_for_loopback() {
        assert!(validate_server_url("http://127.0.0.1:18787").is_ok());
        assert!(validate_server_url("http://127.9.8.7").is_ok());
        assert!(validate_server_url("http://[::1]:18787").is_ok());
        assert!(validate_server_url("http://localhost:18787").is_ok());
        assert!(validate_server_url("http://LOCALHOST:18787").is_ok());

        assert!(validate_server_url("http://192.168.1.10").is_err());
        assert!(validate_server_url("http://secrets.example.com").is_err());
        assert!(validate_server_url("http://localhost.evil.com").is_err());
        assert!(validate_server_url("http://[::2]").is_err());
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        assert!(validate_server_url("ftp://127.0.0.1").is_err());
        assert!(validate_server_url("file:///etc/passwd").is_err());
        assert!(validate_server_url("not a url").is_err());
    }

    #[test]
    fn userinfo_query_fragment_are_rejected() {
        assert!(validate_server_url("https://user@secrets.example.com").is_err());
        assert!(validate_server_url("https://user:pw@secrets.example.com").is_err());
        assert!(validate_server_url("https://secrets.example.com/?q=1").is_err());
        assert!(validate_server_url("https://secrets.example.com/#frag").is_err());
    }
}
