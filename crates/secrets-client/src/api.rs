//! Thin HTTP client for the secrets server.
//!
//! TLS is provided by ureq's rustls backend. The bearer token is sent in
//! the `Authorization` header and never placed in the URL or logs.

use std::collections::BTreeMap;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};

use crate::cache::CacheStore;
use crate::config::Config;
use crate::error::{Error, Result};

pub type SecretMap = BTreeMap<String, SecretString>;

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
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build();
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

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.expose_secret())
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
            .set("Authorization", &self.auth_header())
            .call();

        match resp {
            Ok(r) => {
                let raw = r
                    .into_json::<BTreeMap<String, String>>()
                    .map_err(|_| Error::UnexpectedResponse)?;
                Ok(secret_map_from_plain(raw))
            }
            Err(e) => Err(map_error(e)),
        }
    }

    /// Set a single secret value.
    pub fn set_secret(&self, project: &str, key: &str, value: &SecretString) -> Result<()> {
        let url = format!("{}/v1/projects/{}/secrets/{}", self.base, project, key);
        let resp = self
            .agent
            .put(&url)
            .set("Authorization", &self.auth_header())
            .send_json(ureq::json!({ "value": value.expose_secret() }));

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
        ureq::Error::Status(code, _resp) => match code {
            401 => Error::Unauthorized,
            403 => Error::Forbidden,
            404 => Error::NotFound,
            _ => Error::Http(code),
        },
        ureq::Error::Transport(t) => Error::Transport(t.kind().to_string()),
    }
}

pub(crate) fn secret_map_from_plain(raw: BTreeMap<String, String>) -> SecretMap {
    raw.into_iter()
        .map(|(key, value)| (key, SecretString::from(value)))
        .collect()
}
