//! Thin HTTP client for the secrets server.
//!
//! TLS is provided by ureq's rustls backend. The bearer token is sent in
//! the `Authorization` header and never placed in the URL or logs.

use std::collections::BTreeMap;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::cache::CacheStore;
use crate::config::Config;
use crate::error::{Error, Result};

pub type SecretMap = BTreeMap<String, SecretString>;

/// Hard cap on response bodies read from the server. A hostile or
/// compromised server must not be able to exhaust client memory.
const MAX_RESPONSE_BYTES: u64 = 1 << 20; // 1 MiB

pub struct Api {
    agent: ureq::Agent,
    base: String,
    token: SecretString,
    cache: Option<CacheStore>,
}

impl Api {
    pub fn new(cfg: &Config) -> Self {
        Self::with_cache(cfg, true)
    }

    pub fn new_no_cache(cfg: &Config) -> Self {
        Self::with_cache(cfg, false)
    }

    fn with_cache(cfg: &Config, cache_enabled: bool) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(20)))
            .build()
            .into();
        let cache = if cache_enabled {
            match CacheStore::open(cfg) {
                Ok(cache) => Some(cache),
                Err(e) => {
                    eprintln!("[warn] offline cache disabled: {e}");
                    None
                }
            }
        } else {
            None
        };
        Api {
            agent,
            base: cfg.server_url.clone(),
            token: cfg.token.clone(),
            cache,
        }
    }

    fn auth_header(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.token.expose_secret()))
    }

    /// Fetch and decrypt all secrets for a project.
    pub fn get_secrets(&self, project: &str) -> Result<SecretMap> {
        match self.fetch_secrets(project) {
            Ok(secrets) => {
                if let Some(cache) = &self.cache {
                    if let Err(e) = cache.store(project, &secrets) {
                        eprintln!("[warn] failed to update offline cache: {e}");
                    }
                }
                Ok(secrets)
            }
            Err(e) if e.is_transport() => {
                if let Some(cache) = &self.cache {
                    match cache.load(project) {
                        Ok(secrets) => {
                            eprintln!(
                                "[warn] server unreachable; using encrypted offline cache for project `{project}`"
                            );
                            Ok(secrets)
                        }
                        Err(cache_err) => Err(Error::OfflineCacheUnavailable {
                            transport: e.to_string(),
                            cache: cache_err.to_string(),
                        }),
                    }
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn fetch_secrets(&self, project: &str) -> Result<SecretMap> {
        let url = format!("{}/v1/projects/{}/secrets", self.base, project);
        let resp = self
            .agent
            .get(&url)
            .header("Authorization", self.auth_header().as_str())
            .call();

        match resp {
            Ok(mut r) => {
                // Bounded read: never trust the server for response size.
                let buf = Zeroizing::new(
                    r.body_mut()
                        .with_config()
                        .limit(MAX_RESPONSE_BYTES)
                        .read_to_vec()
                        .map_err(|_| Error::UnexpectedResponse)?,
                );
                let raw: BTreeMap<String, String> =
                    serde_json::from_slice(&buf).map_err(|_| Error::UnexpectedResponse)?;
                secret_map_from_plain(raw)
            }
            Err(e) => Err(map_error(e)),
        }
    }

    /// Set a single secret value.
    pub fn set_secret(&self, project: &str, key: &str, value: &SecretString) -> Result<()> {
        #[derive(serde::Serialize)]
        struct SetBody<'a> {
            value: &'a str,
        }

        let url = format!("{}/v1/projects/{}/secrets/{}", self.base, project, key);
        let body = Zeroizing::new(
            serde_json::to_vec(&SetBody {
                value: value.expose_secret(),
            })
            .map_err(|_| Error::UnexpectedResponse)?,
        );
        let resp = self
            .agent
            .put(&url)
            .header("Authorization", self.auth_header().as_str())
            .content_type("application/json")
            .send(body.as_slice());

        match resp {
            Ok(_) => {
                if let Some(cache) = &self.cache {
                    cache.remove(project);
                }
                Ok(())
            }
            Err(e) => Err(map_error(e)),
        }
    }
}

/// Map a ureq error to a clean, non-leaking message.
fn map_error(e: ureq::Error) -> Error {
    match e {
        ureq::Error::StatusCode(code) => match code {
            401 => Error::Unauthorized,
            403 => Error::Forbidden,
            404 => Error::NotFound,
            _ => Error::Http(code),
        },
        _ => Error::Transport(e.to_string()),
    }
}

/// Same key rules the server enforces on write. Applied to every key the
/// client receives (from the network or the offline cache) before the key
/// can reach a child-process environment or dotenv output, so a hostile
/// server cannot inject `BAD\nX=Y`-style keys.
fn valid_secret_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub(crate) fn secret_map_from_plain(raw: BTreeMap<String, String>) -> Result<SecretMap> {
    let mut out = SecretMap::new();
    for (key, value) in raw {
        if !valid_secret_key(&key) {
            // Deliberately does not echo the hostile key material.
            return Err(Error::UnexpectedResponse);
        }
        out.insert(key, SecretString::from(value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_server_keys() {
        for bad in ["", "BAD\nX=Y", "a b", "k=v", "🔥", &"k".repeat(129)] {
            let mut raw = BTreeMap::new();
            raw.insert(bad.to_string(), "v".to_string());
            assert!(
                secret_map_from_plain(raw).is_err(),
                "key {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn accepts_valid_keys() {
        let mut raw = BTreeMap::new();
        raw.insert("DATABASE_URL".to_string(), "v".to_string());
        raw.insert("api.key-2".to_string(), "v".to_string());
        let map = secret_map_from_plain(raw).unwrap();
        assert_eq!(map.len(), 2);
    }
}
