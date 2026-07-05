//! Encrypted offline cache for fetched project secrets.
//!
//! The cache stores only AEAD ciphertext on disk. The per-user cache key is
//! protected by the OS where possible:
//! - macOS: Keychain
//! - Windows: DPAPI, current-user scope
//! - Linux/other Unix: a `0600` key file under the cache directory

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::ExposeSecret;
use secrets_crypto::{decrypt, encrypt, hash_token, MasterKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::api::{secret_map_from_plain, SecretMap};
use crate::config::Config;
use crate::error::{Error, Result};

const CACHE_VERSION: u8 = 2;
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_AAD_PREFIX: &[u8] = b"secrets-manager-client-cache-v2";
const KEY_ENTROPY: &[u8] = b"secrets-manager-cache-key-v1";
/// Tolerated forward clock skew when validating `created_at_unix`.
/// Anything further in the future than this is treated as tampering.
const MAX_FUTURE_SKEW_SECS: u64 = 120;

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
        fs::create_dir_all(&dir).map_err(|e| {
            Error::Cache(format!(
                "failed to create cache directory at {}: {e}",
                dir.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&dir)
                .map_err(|e| Error::Cache(format!("failed to stat {}: {e}", dir.display())))?
                .permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o700);
                fs::set_permissions(&dir, perms).map_err(|e| {
                    Error::Cache(format!("failed to chmod {}: {e}", dir.display()))
                })?;
            }
        }
        let key = load_or_create_cache_key(&dir)?;
        Ok(CacheStore {
            dir,
            key,
            server_url: cfg.server_url.clone(),
            token_hash: hash_token(cfg.token.expose_secret()),
        })
    }

    pub fn store(&self, project: &str, secrets: &SecretMap) -> Result<()> {
        let plain = secrets
            .iter()
            .map(|(key, value)| (key, value.expose_secret()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut plaintext = serde_json::to_vec(&plain)
            .map_err(|e| Error::Cache(format!("failed to encode cache payload: {e}")))?;
        let created_at_unix = now_unix()?;
        // The timestamp is part of the AAD so a cache-file writer cannot
        // refresh `created_at_unix` to replay a stale ciphertext past its TTL.
        let (nonce, ciphertext) = encrypt(&self.key, &plaintext, &self.aad(project, created_at_unix))
            .map_err(|_| Error::Cache("failed to encrypt cache payload".to_string()))?;
        plaintext.zeroize();
        let envelope = Envelope {
            version: CACHE_VERSION,
            created_at_unix,
            nonce: b64_encode(&nonce),
            ciphertext: b64_encode(&ciphertext),
        };
        let data = serde_json::to_vec(&envelope)
            .map_err(|e| Error::Cache(format!("failed to encode cache envelope: {e}")))?;
        write_private_file(&self.cache_path(project), &data)?;
        Ok(())
    }

    pub fn load(&self, project: &str) -> Result<SecretMap> {
        let data = fs::read(self.cache_path(project))
            .map_err(|e| Error::Cache(format!("failed to read cache: {e}")))?;
        let envelope: Envelope = serde_json::from_slice(&data)
            .map_err(|e| Error::Cache(format!("failed to parse cache envelope: {e}")))?;
        if envelope.version != CACHE_VERSION {
            return Err(Error::Cache("unsupported cache version".to_string()));
        }
        let now = now_unix()?;
        if envelope.created_at_unix > now + MAX_FUTURE_SKEW_SECS {
            return Err(Error::Cache(
                "cache timestamp is in the future; refusing to use it".to_string(),
            ));
        }
        let age = now.saturating_sub(envelope.created_at_unix);
        if age > CACHE_TTL.as_secs() {
            return Err(Error::Cache("cache expired".to_string()));
        }

        let nonce = b64_decode(&envelope.nonce)?;
        let mut ciphertext = b64_decode(&envelope.ciphertext)?;
        // Decryption authenticates the timestamp via the AAD.
        let mut plaintext = decrypt(
            &self.key,
            &nonce,
            &ciphertext,
            &self.aad(project, envelope.created_at_unix),
        )
        .map_err(|_| Error::Cache("failed to decrypt cache payload".to_string()))?;
        ciphertext.zeroize();

        let raw: std::collections::BTreeMap<String, String> = serde_json::from_slice(&plaintext)
            .map_err(|e| Error::Cache(format!("failed to parse cache payload: {e}")))?;
        plaintext.zeroize();
        secret_map_from_plain(raw)
    }

    pub fn remove(&self, project: &str) {
        let _ = fs::remove_file(self.cache_path(project));
    }

    fn aad(&self, project: &str, created_at_unix: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            CACHE_AAD_PREFIX.len()
                + self.server_url.len()
                + self.token_hash.len()
                + project.len()
                + 8,
        );
        aad.extend_from_slice(CACHE_AAD_PREFIX);
        aad.extend_from_slice(&(self.server_url.len() as u32).to_le_bytes());
        aad.extend_from_slice(self.server_url.as_bytes());
        aad.extend_from_slice(&self.token_hash);
        aad.extend_from_slice(&(project.len() as u32).to_le_bytes());
        aad.extend_from_slice(project.as_bytes());
        aad.extend_from_slice(&created_at_unix.to_le_bytes());
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
    let base = dirs::cache_dir()
        .ok_or_else(|| Error::Cache("cannot determine cache directory".to_string()))?;
    Ok(base.join("secrets"))
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Cache(format!("system clock is before Unix epoch: {e}")))?
        .as_secs())
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Cache(format!("invalid base64 in cache: {e}")))
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn key_from_slice(bytes: &[u8]) -> Result<MasterKey> {
    let mut raw = [0u8; 32];
    if bytes.len() != raw.len() {
        return Err(Error::Cache("invalid cache key length".to_string()));
    }
    raw.copy_from_slice(bytes);
    Ok(MasterKey::from_bytes(raw))
}

#[cfg(target_os = "windows")]
fn load_or_create_cache_key(dir: &Path) -> Result<MasterKey> {
    use windows_dpapi::{decrypt_data, encrypt_data, Scope};

    let path = dir.join("cache-key.dpapi");
    if path.exists() {
        let protected = fs::read(&path)
            .map_err(|e| Error::Cache(format!("failed to read DPAPI cache key: {e}")))?;
        let mut raw = decrypt_data(&protected, Scope::User, Some(KEY_ENTROPY))
            .map_err(|e| Error::Cache(format!("DPAPI decrypt failed: {e}")))?;
        let key = key_from_slice(&raw)?;
        raw.zeroize();
        return Ok(key);
    }

    let mut raw = random_key();
    let protected = encrypt_data(&raw, Scope::User, Some(KEY_ENTROPY))
        .map_err(|e| Error::Cache(format!("DPAPI encrypt failed: {e}")))?;
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
            let mut encoded = String::from_utf8(encoded).map_err(|e| {
                Error::Cache(format!(
                    "cache key in macOS Keychain is not valid UTF-8: {e}"
                ))
            })?;
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
            .map_err(|e| {
                Error::Cache(format!("failed to store cache key in macOS Keychain: {e}"))
            })?;
            encoded.zeroize();
            let key = MasterKey::from_bytes(raw);
            raw.zeroize();
            Ok(key)
        }
        Err(e) => Err(Error::Cache(format!(
            "failed to read cache key from macOS Keychain: {e}"
        ))),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn load_or_create_cache_key(dir: &Path) -> Result<MasterKey> {
    use std::io::Read as _;

    let path = dir.join("cache-key");
    if path.exists() {
        let mut file = open_private_for_read(&path)?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)
            .map_err(|e| Error::Cache(format!("failed to read cache key: {e}")))?;
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
        let mut raw =
            fs::read(&path).map_err(|e| Error::Cache(format!("failed to read cache key: {e}")))?;
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
        fs::create_dir_all(parent).map_err(|e| {
            Error::Cache(format!(
                "failed to create directory at {}: {e}",
                parent.display()
            ))
        })?;
    }
    // Randomized temp name + `create_new` (O_CREAT|O_EXCL): an attacker who
    // pre-plants a file or symlink at the temp path makes the open fail
    // instead of us writing through it.
    let tmp = random_temp_sibling(path)?;
    let write_result = (|| -> Result<()> {
        let mut file = private_open_for_write(&tmp)?;
        file.write_all(data)
            .map_err(|e| Error::Cache(format!("failed to write {}: {e}", tmp.display())))?;
        file.flush()
            .map_err(|e| Error::Cache(format!("failed to flush {}: {e}", tmp.display())))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::Cache(format!(
            "failed to replace {}: {e}",
            path.display()
        )));
    }
    Ok(())
}

fn random_temp_sibling(path: &Path) -> Result<PathBuf> {
    let mut suffix = [0u8; 16];
    OsRng.fill_bytes(&mut suffix);
    let file_name = path
        .file_name()
        .ok_or_else(|| Error::Cache(format!("invalid cache path {}", path.display())))?;
    let mut name = file_name.to_os_string();
    name.push(format!(".{}.tmp", b64_encode(&suffix)));
    Ok(path.with_file_name(name))
}

#[cfg(unix)]
fn private_open_for_write(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::Cache(format!("failed to open {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn private_open_for_write(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| Error::Cache(format!("failed to open {}: {e}", path.display())))
}

/// Open an existing private file for reading without following symlinks,
/// then validate the opened fd's metadata (regular file, 0600) so the
/// check cannot be raced against the open.
#[cfg(all(unix, not(target_os = "macos")))]
fn open_private_for_read(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::Cache(format!("failed to open {}: {e}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| Error::Cache(format!("failed to stat {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(Error::Cache(format!(
            "{} is not a regular file; refusing to use it",
            path.display()
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Cache(format!(
            "{} has permissions {:04o}; refusing to use cache key unless it is 0600",
            path.display(),
            mode
        )));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    // Tests mutate the process-wide SECRETS_CACHE_DIR env var; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_cfg() -> Config {
        Config {
            server_url: "https://example.invalid".to_string(),
            token: SecretString::from("test-token".to_string()),
        }
    }

    fn cfg_with(server_url: &str, token: &str) -> Config {
        Config {
            server_url: server_url.to_string(),
            token: SecretString::from(token.to_string()),
        }
    }

    fn one_secret() -> SecretMap {
        let mut secrets = SecretMap::new();
        secrets.insert(
            "API_KEY".to_string(),
            SecretString::from("value".to_string()),
        );
        secrets
    }

    #[test]
    fn cache_roundtrip_is_encrypted_and_bound_to_project() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());
        let cache = CacheStore::open(&test_cfg()).unwrap();

        let mut secrets = SecretMap::new();
        secrets.insert(
            "DATABASE_URL".to_string(),
            SecretString::from("postgres://secret".to_string()),
        );
        cache.store("cdn", &secrets).unwrap();

        let body = fs::read(cache.cache_path("cdn")).unwrap();
        assert!(!body
            .windows(b"postgres://secret".len())
            .any(|w| w == b"postgres://secret"));
        assert_eq!(
            cache
                .load("cdn")
                .unwrap()
                .get("DATABASE_URL")
                .unwrap()
                .expose_secret(),
            "postgres://secret"
        );
        assert!(cache.load("other-project").is_err());

        std::env::remove_var("SECRETS_CACHE_DIR");
    }

    #[test]
    fn tampered_timestamp_fails_decryption() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());
        let cache = CacheStore::open(&test_cfg()).unwrap();

        let mut secrets = SecretMap::new();
        secrets.insert(
            "API_KEY".to_string(),
            SecretString::from("value".to_string()),
        );
        cache.store("proj", &secrets).unwrap();

        // Rewind the plaintext timestamp: decryption must fail because the
        // timestamp is bound into the AAD.
        let path = cache.cache_path("proj");
        let mut envelope: Envelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope.created_at_unix -= 3600;
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(cache.load("proj").is_err());

        std::env::remove_var("SECRETS_CACHE_DIR");
    }

    #[test]
    fn future_timestamp_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());
        let cache = CacheStore::open(&test_cfg()).unwrap();

        let mut secrets = SecretMap::new();
        secrets.insert(
            "API_KEY".to_string(),
            SecretString::from("value".to_string()),
        );
        cache.store("proj", &secrets).unwrap();

        let path = cache.cache_path("proj");
        let mut envelope: Envelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope.created_at_unix += MAX_FUTURE_SKEW_SECS + 3600;
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let err = cache.load("proj").unwrap_err().to_string();
        assert!(err.contains("future"), "unexpected error: {err}");

        std::env::remove_var("SECRETS_CACHE_DIR");
    }

    #[test]
    fn expired_cache_past_ttl_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());
        let cache = CacheStore::open(&test_cfg()).unwrap();
        cache.store("proj", &one_secret()).unwrap();

        // Push the timestamp older than the 24h TTL. The AAD still matches
        // (we rewrite it), so this exercises the TTL check specifically.
        let path = cache.cache_path("proj");
        let mut envelope: Envelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope.created_at_unix -= CACHE_TTL.as_secs() + 60;
        // Re-encrypt under the (older) timestamp so decryption itself would
        // succeed; only the age check should reject it.
        let cache2 = CacheStore::open(&test_cfg()).unwrap();
        let (nonce, ct) = encrypt(
            &cache2.key,
            &serde_json::to_vec(&std::collections::BTreeMap::from([("API_KEY", "value")]))
                .unwrap(),
            &cache2.aad("proj", envelope.created_at_unix),
        )
        .unwrap();
        envelope.nonce = b64_encode(&nonce);
        envelope.ciphertext = b64_encode(&ct);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let err = cache.load("proj").unwrap_err().to_string();
        assert!(err.contains("expired"), "unexpected error: {err}");

        std::env::remove_var("SECRETS_CACHE_DIR");
    }

    #[test]
    fn cache_is_bound_to_token_and_server_url() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());

        // Write a cache entry with one identity.
        let writer = CacheStore::open(&cfg_with("https://a.invalid", "token-a")).unwrap();
        writer.store("proj", &one_secret()).unwrap();
        let written_path = writer.cache_path("proj");

        // A different token must not be able to read that entry. Its cache
        // path differs (token_hash is in the path), so a load simply misses.
        let other_token = CacheStore::open(&cfg_with("https://a.invalid", "token-b")).unwrap();
        assert_ne!(other_token.cache_path("proj"), written_path);
        assert!(other_token.load("proj").is_err());

        // Even if an attacker copies the ciphertext file to the other
        // identity's path, the AAD (token_hash + server_url) makes the AEAD
        // reject it.
        fs::copy(&written_path, other_token.cache_path("proj")).unwrap();
        assert!(other_token.load("proj").is_err());

        // Same for a different server URL.
        let other_server = CacheStore::open(&cfg_with("https://b.invalid", "token-a")).unwrap();
        fs::copy(&written_path, other_server.cache_path("proj")).unwrap();
        assert!(other_server.load("proj").is_err());

        std::env::remove_var("SECRETS_CACHE_DIR");
    }

    #[test]
    fn tampered_ciphertext_in_cache_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("SECRETS_CACHE_DIR", tmp.path());
        let cache = CacheStore::open(&test_cfg()).unwrap();
        cache.store("proj", &one_secret()).unwrap();

        let path = cache.cache_path("proj");
        let mut envelope: Envelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut ct = b64_decode(&envelope.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        envelope.ciphertext = b64_encode(&ct);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        assert!(cache.load("proj").is_err());

        std::env::remove_var("SECRETS_CACHE_DIR");
    }
}
