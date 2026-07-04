//! Bearer-token authentication and scope enforcement.

use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use secrets_crypto::hash_token;
use zeroize::Zeroize;

use crate::app::AppState;
use crate::error::AppError;
use crate::repo::{self, AuthedToken};

/// Extract the raw bearer token from an `Authorization` header, if present.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Resolve a request's token *name* for audit logging (no enforcement).
/// Returns `None` for missing/invalid/revoked tokens.
pub fn resolve_token_name(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let mut token = extract_bearer(headers)?;
    let hash = hash_token(&token);
    token.zeroize();

    let conn = state.db.lock().ok()?;
    repo::authenticate(&conn, &hash).ok().flatten().map(|t| t.name)
}

#[async_trait]
impl FromRequestParts<AppState> for AuthedToken {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let mut token = extract_bearer(&parts.headers).ok_or(AppError::Unauthorized)?;
        let hash = hash_token(&token);
        token.zeroize();

        let conn = state
            .db
            .lock()
            .map_err(|_| AppError::Internal("db lock poisoned"))?;

        match repo::authenticate(&conn, &hash).map_err(|_| AppError::Internal("database"))? {
            Some(authed) => Ok(authed),
            None => Err(AppError::Unauthorized),
        }
    }
}

/// Enforce that a scoped token may only touch its own project.
/// A token with `scope = None` may touch any project.
pub fn ensure_scope(token: &AuthedToken, project: &str) -> Result<(), AppError> {
    match &token.scope {
        Some(s) if s != project => Err(AppError::Forbidden),
        _ => Ok(()),
    }
}
