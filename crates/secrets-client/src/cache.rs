//! Encrypted offline cache for fetched project secrets.
//!
//! The cache stores only AEAD ciphertext on disk. The per-user cache key is
//! protected by the OS where possible:
//! - macOS: Keychain
//! - Windows: DPAPI, current-user scope
//! - Linux/other Unix: a `0600` key file under the cache directory

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::ExposeSecret;
use secrets_crypto::{decrypt, encrypt, hash_token, MasterKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::config::Config;

const CACHE_VERSION: u8 = 1;
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_AAD_PREFIX: &[u8] = b"secrets-manager-client-cache-v1";
const KEY_ENTROPY: &[u8] = b"secrets-manager-cache-key-v1";

pub struct CacheStore {
    dir: PathBuf,
    key: MasterKey,
    server_url: String,
    token_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u8,
    created_at_unix: u64,
    nonce: String,
    ciphertext: String,
}

impl CacheStore {
    pub fn open(cfg: &Config) -> Result<Self> {
        let dir = cache_dir()?;
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create cache directory at {}", dir.display()))?;
        let key = load_or_create_cache_key(&dir)?;
        Ok(CacheStore {
            dir,
            key,
            server_url: cfg.server_url.clone(),
            token_hash: hash_token(cfg.token.expose_secret()),
        })
    }

    pub fn store(&self, project: &str, secrets: &BTreeMap<String, String>) -> Result<()> {
        let mut plaintext = serde_json::to_vec(secrets).context("failed to encode cache payload")?;
        let (nonce, ciphertext) = encrypt(&self.key, &plaintext, &self.aad(project))
            .map_err(|_| anyhow!("failed to encrypt cache payload"))?;
        plaintext.zeroize();
        let envelope = Envelope {
            version: CACHE_VERSION,
            created_at_unix: now_unix()?,
            nonce: b64_encode(&nonce),
            ciphertext: b64_encode(&ciphertext),
        };
        let data = serde_json::to_vec(&envelope).context("failed to encode cache envelope")?;
        write_private_file(&self.cache_path(project), &data)?;
        Ok(())
    }

    pub fn load(&self, project: &str) -> Result<BTreeMap<String, String>> {
        let data = fs::read(self.cache_path(project)).context("failed to read cache")?;
        let envelope: Envelope =
            serde_json::from_slice(&data).context("failed to parse cache envelope")?;
        if envelope.version != CACHE_VERSION {
            bail!("unsupported cache version");
        }
        let age = now_unix()?.saturating_sub(envelope.created_at_unix);
        if age > CACHE_TTL.as_secs() {
            bail!("cache expired");
        }

        let nonce = b64_decode(&envelope.nonce)?;
        let mut ciphertext = b64_decode(&envelope.ciphertext)?;
        let mut plaintext = decrypt(&self.key, &nonce, &ciphertext, &self.aad(project))
            .map_err(|_| anyhow!("failed to decrypt cache payload"))?;
        ciphertext.zeroize();

        let out = serde_json::from_slice(&plaintext).context("failed to parse cache payload")?;
        plaintext.zeroize();
        Ok(out)
    }

    pub fn remove(&self, project: &str) {
        let _ = fs::remove_file(self.cache_path(project));
    }

    fn aad(&self, project: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CACHE_AAD_PREFIX.len() + self.server_url.len() + self.token_hash.len() + project.len(),
        );
        aad.extend_from_slice(CACHE_AAD_PREFIX);
        aad.extend_from_slice(&(self.server_url.len() as u32).to_le_bytes());
        aad.extend_from_slice(self.server_url.as_bytes());
        aad.extend_from_slice(&self.token_hash);
        aad.extend_from_slice(&(project.len() as u32).to_le_bytes());
        aad.extend_from_slice(project.as_bytes());
        aad
    }

    fn cache_path(&self, project: &str) -> PathBuf {
        let mut h = Sha256::new();
        h.update(self.server_url.as_bytes());
        h.update([0]);
        h.update(self.token_hash);
        h.update([0]);
        h.update(project.as_bytes());
        let name = b64_encode(&h.finalize());
        self.dir.join(format!("{name}.json"))
    }
}

fn cache_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SECRETS_CACHE_DIR") {
        return Ok(PathBuf::from(p));
    }
    let base = dirs::cache_dir().ok_or_else(|| anyhow!("cannot determine cache directory"))?;
    Ok(base.join("secrets"))
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .context("invalid base64 in cache")
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn key_from_slice(bytes: &[u8]) -> Result<MasterKey> {
    let mut raw = [0u8; 32];
    if bytes.len() != raw.len() {
        bail!("invalid cache key length");
    }
    raw.copy_from_slice(bytes);
    Ok(MasterKey::from_bytes(raw))
}

#[cfg(target_os = "windows")]
fn load_or_create_cache_key(dir: &Path) -> Result<MasterKey> {
    use windows_dpapi::{decrypt_data, encrypt_data, Scope};

    let path = dir.join("cache-key.dpapi");
    if path.exists() {
        let protected = fs::read(&path).context("failed to read DPAPI cache key")?;
        let mut raw = decrypt_data(&protected, Scope::User, Some(KEY_ENTROPY))
            .context("DPAPI decrypt failed")?;
        let key = key_from_slice(&raw)?;
        raw.zeroize();
        return Ok(key);
    }

    let mut raw = random_key();
    let protected =
        encrypt_data(&raw, Scope::User, Some(KEY_ENTROPY)).context("DPAPI encrypt failed")?;
    write_private_file(&path, &protected)?;
    let key = MasterKey::from_bytes(raw);
    raw.zeroize();
    Ok(key)
}

#[cfg(target_os = "macos")]
fn load_or_create_cache_key(_dir: &Path) -> Result<MasterKey> {
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const SERVICE: &str = "secrets-manager";
    const ACCOUNT: &str = "offline-cache-key";

    match security_framework::passwords::get_generic_password(SERVICE, ACCOUNT) {
        Ok(encoded) => {
            let mut encoded = String::from_utf8(encoded)
                .context("cache key in macOS Keychain is not valid UTF-8")?;
            let mut raw = b64_decode(&encoded)?;
            encoded.zeroize();
            let key = key_from_slice(&raw)?;
            raw.zeroize();
            Ok(key)
        }
        Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {
            let mut raw = random_key();
            let mut encoded = b64_encode(&raw);
            security_framework::passwords::set_generic_password(
                SERVICE,
                ACCOUNT,
                encoded.as_bytes(),
            )
            .context("failed to store cache key in macOS Keychain")?;
            encoded.zeroize();
            let key = MasterKey::from_bytes(raw);
            raw.zeroize();
            Ok(key)
        }
        Err(e) => Err(anyhow!("failed to read cache key from macOS Keychain: {e}")),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn load_or_create_cache_key(dir: &Path) -> Result<MasterKey> {
    let path = dir.join("cache-key");
    if path.exists() {
        ensure_private_permissions(&path)?;
        let mut raw = fs::read(&path).context("failed to read cache key")?;
        let key = key_from_slice(&raw)?;
        raw.zeroize();
        return Ok(key);
    }

    let mut raw = random_key();
    write_private_file(&path, &raw)?;
    let key = MasterKey::from_bytes(raw);
    raw.zeroize();
    Ok(key)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn load_or_create_cache_key(dir: &Path) -> Result<MasterKey> {
    let path = dir.join("cache-key");
    if path.exists() {
        let mut raw = fs::read(&path).context("failed to read cache key")?;
        let key = key_from_slice(&raw)?;
        raw.zeroize();
        return Ok(key);
    }

    let mut raw = random_key();
    write_private_file(&path, &raw)?;
    let key = MasterKey::from_bytes(raw);
    raw.zeroize();
    Ok(key)
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory at {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = private_open_for_write(&tmp)?;
        file.write_all(data)
            .with_context(|| format!("failed to write {}", tmp.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("failed to replace {}", path.display()))?;
    set_private_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn private_open_for_write(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

#[cfg(not(unix))]
fn private_open_for_write(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn ensure_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} has permissions {:04o}; refusing to use cache key unless it is 0600",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn test_cfg() -> Config {
        Config {
            server_url: "https://example.invalid".to_string(),
            token: SecretString::from("test-token".to_string()),
        }
    }

    #[test]
    fn cache_roundtrip_is_encrypted_and_bound_to_project() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());
        let cache = CacheStore::open(&test_cfg()).unwrap();

        let mut secrets = BTreeMap::new();
        secrets.insert("DATABASE_URL".to_string(), "postgres://secret".to_string());
        cache.store("cdn", &secrets).unwrap();

        let body = fs::read(cache.cache_path("cdn")).unwrap();
        assert!(!body
            .windows(b"postgres://secret".len())
            .any(|w| w == b"postgres://secret"));
        assert_eq!(cache.load("cdn").unwrap(), secrets);
        assert!(cache.load("other-project").is_err());

        std::env::remove_var("SECRETS_CACHE_DIR");
    }
}
