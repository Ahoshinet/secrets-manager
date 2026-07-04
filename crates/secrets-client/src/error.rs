//! Public error type for the embeddable client API.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("server returned an unexpected response")]
    UnexpectedResponse,
    #[error("unauthorized (check your token)")]
    Unauthorized,
    #[error("forbidden (token not permitted for this project)")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("server error (HTTP {0})")]
    Http(u16),
    #[error("cannot reach server: {0}")]
    Transport(String),
    #[error("{transport}; no usable offline cache ({cache})")]
    OfflineCacheUnavailable { transport: String, cache: String },
    #[error("configuration error: {0}")]
    Config(String),
    #[error("cache error: {0}")]
    Cache(String),
}

impl Error {
    pub(crate) fn is_transport(&self) -> bool {
        matches!(self, Error::Transport(_))
    }
}
