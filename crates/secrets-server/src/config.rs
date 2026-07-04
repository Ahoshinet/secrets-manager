//! Runtime configuration and passphrase acquisition.

use std::fs;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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

const SYSTEMD_PASSPHRASE_CREDENTIAL: &str = "secrets-passphrase";

/// Obtain the master passphrase.
///
/// Priority: `SECRETS_PASSPHRASE` -> `SECRETS_PASSPHRASE_FILE` -> systemd
/// `LoadCredential=secrets-passphrase` -> interactive TTY prompt. Fails
/// loudly if none is available (never silently proceed).
pub fn acquire_passphrase() -> Result<SecretString> {
    if let Ok(p) = std::env::var("SECRETS_PASSPHRASE") {
        if p.is_empty() {
            bail!("SECRETS_PASSPHRASE is set but empty");
        }
        return Ok(SecretString::from(p));
    }

    if let Some(path) = std::env::var_os("SECRETS_PASSPHRASE_FILE") {
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() {
            bail!("SECRETS_PASSPHRASE_FILE is set but empty");
        }
        return read_passphrase_file(&path, "SECRETS_PASSPHRASE_FILE");
    }

    if let Some(path) = systemd_credential_path(SYSTEMD_PASSPHRASE_CREDENTIAL) {
        return read_passphrase_file(&path, "systemd credential secrets-passphrase");
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
            "no passphrase available: set SECRETS_PASSPHRASE, set \
             SECRETS_PASSPHRASE_FILE, provide systemd credential \
             secrets-passphrase, or run attached to a terminal"
        )
    }
}

fn systemd_credential_path(name: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("CREDENTIALS_DIRECTORY")?;
    let path = PathBuf::from(dir).join(name);
    path.exists().then_some(path)
}

fn read_passphrase_file(path: &Path, source: &str) -> Result<SecretString> {
    validate_passphrase_file_permissions(path)?;

    let mut passphrase = fs::read_to_string(path)
        .with_context(|| format!("failed to read {source} passphrase file {}", path.display()))?;
    strip_single_trailing_newline(&mut passphrase);

    if passphrase.is_empty() {
        bail!("{source} passphrase file is empty");
    }

    Ok(SecretString::from(passphrase))
}

fn strip_single_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

#[cfg(unix)]
fn validate_passphrase_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect passphrase file {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("passphrase file {} must not be a symlink", path.display());
    }

    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "passphrase file {} must not be readable, writable, or executable by group/others",
            path.display()
        );
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_passphrase_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn passphrase_file_strips_one_trailing_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("passphrase");
        fs::write(&path, "correct horse battery staple\r\n").unwrap();
        set_owner_only_permissions(&path);

        let passphrase = read_passphrase_file(&path, "test").unwrap();
        assert_eq!(passphrase.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn passphrase_file_keeps_internal_newlines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("passphrase");
        fs::write(&path, "line1\nline2").unwrap();
        set_owner_only_permissions(&path);

        let passphrase = read_passphrase_file(&path, "test").unwrap();
        assert_eq!(passphrase.expose_secret(), "line1\nline2");
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_file_rejects_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("passphrase");
        fs::write(&path, "secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = read_passphrase_file(&path, "test").unwrap_err();
        assert!(err.to_string().contains("group/others"));
    }

    #[cfg(unix)]
    fn set_owner_only_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_owner_only_permissions(_path: &Path) {}
}
