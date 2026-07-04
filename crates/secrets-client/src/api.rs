//! Thin HTTP client for the secrets server.
//!
//! TLS is provided by ureq's rustls backend. The bearer token is sent in
//! the `Authorization` header and never placed in the URL or logs.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::config::Config;

pub struct Api {
    agent: ureq::Agent,
    base: String,
    token: SecretString,
}

impl Api {
    pub fn new(cfg: &Config) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build();
        Api {
            agent,
            base: cfg.server_url.clone(),
            token: cfg.token.clone(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.expose_secret())
    }

    /// Fetch and decrypt all secrets for a project as a key/value map.
    pub fn get_secrets(&self, project: &str) -> Result<BTreeMap<String, String>> {
        let url = format!("{}/v1/projects/{}/secrets", self.base, project);
        let resp = self
            .agent
            .get(&url)
            .set("Authorization", &self.auth_header())
            .call();

        match resp {
            Ok(r) => r
                .into_json::<BTreeMap<String, String>>()
                .map_err(|_| anyhow!("server returned an unexpected response")),
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
            Ok(_) => Ok(()),
            Err(e) => Err(map_error(e)),
        }
    }
}

/// Map a ureq error to a clean, non-leaking message.
fn map_error(e: ureq::Error) -> anyhow::Error {
    match e {
        ureq::Error::Status(code, _resp) => match code {
            401 => anyhow!("unauthorized (check your token)"),
            403 => anyhow!("forbidden (token not permitted for this project)"),
            404 => anyhow!("not found"),
            _ => anyhow!("server error (HTTP {code})"),
        },
        ureq::Error::Transport(t) => {
            anyhow!("cannot reach server: {}", t.kind())
        }
    }
}
