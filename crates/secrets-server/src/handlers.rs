//! HTTP handlers for the `/v1` API.
//!
//! All handlers except `health` require a valid bearer token (enforced by
//! the [`AuthedToken`] extractor). Scoped tokens are further checked with
//! [`auth::ensure_scope`]. No handler ever returns secret material in an
//! error path.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use secrecy::{ExposeSecret, SecretString};
use secrets_crypto::{aad_bytes, decrypt, encrypt};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::app::AppState;
use crate::auth::ensure_scope;
use crate::error::AppError;
use crate::repo::{self, AuthedToken};

fn valid_project(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Unauthenticated liveness probe.
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Deserialize)]
pub struct CreateProjectBody {
    name: String,
}

pub async fn create_project(
    State(state): State<AppState>,
    token: AuthedToken,
    Json(body): Json<CreateProjectBody>,
) -> Result<impl IntoResponse, AppError> {
    if !valid_project(&body.name) {
        return Err(AppError::BadRequest("invalid project name"));
    }
    ensure_scope(&token, &body.name)?;

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    if repo::project_id(&conn, &body.name)?.is_some() {
        return Err(AppError::Conflict("project already exists"));
    }
    repo::create_project(&conn, &body.name)?;

    Ok((StatusCode::CREATED, Json(json!({ "name": body.name }))))
}

pub async fn list_projects(
    State(state): State<AppState>,
    token: AuthedToken,
) -> Result<Json<Value>, AppError> {
    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let projects = repo::list_projects(&conn)?;

    let names: Vec<Value> = projects
        .into_iter()
        // A scoped token only sees its own project.
        .filter(|p| match &token.scope {
            Some(s) => s == &p.name,
            None => true,
        })
        .map(|p| json!({ "name": p.name, "created_at": p.created_at }))
        .collect();

    Ok(Json(json!({ "projects": names })))
}

pub async fn get_secrets(
    State(state): State<AppState>,
    token: AuthedToken,
    Path(name): Path<String>,
) -> Result<Json<BTreeMap<String, String>>, AppError> {
    ensure_scope(&token, &name)?;

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let pid = repo::project_id(&conn, &name)?.ok_or(AppError::NotFound)?;
    let rows = repo::list_secret_rows(&conn, pid)?;

    let mut out = BTreeMap::new();
    for row in rows {
        let aad = aad_bytes(&name, &row.key);
        let plaintext = decrypt(&state.key, &row.nonce, &row.ciphertext, &aad)
            .map_err(|_| AppError::Internal("decrypt"))?;
        let value =
            String::from_utf8(plaintext).map_err(|_| AppError::Internal("non-utf8 secret"))?;
        out.insert(row.key, value);
    }

    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct SetSecretBody {
    value: String,
}

pub async fn put_secret(
    State(state): State<AppState>,
    token: AuthedToken,
    Path((name, key)): Path<(String, String)>,
    Json(mut body): Json<SetSecretBody>,
) -> Result<Json<Value>, AppError> {
    ensure_scope(&token, &name)?;
    if !valid_key(&key) {
        body.value.zeroize();
        return Err(AppError::BadRequest("invalid key name"));
    }

    // Keep the plaintext in a secret wrapper and wipe the raw copy.
    let secret = SecretString::from(std::mem::take(&mut body.value));

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let pid = repo::project_id(&conn, &name)?.ok_or(AppError::NotFound)?;

    let aad = aad_bytes(&name, &key);
    let (nonce, ciphertext) = encrypt(&state.key, secret.expose_secret().as_bytes(), &aad)
        .map_err(|_| AppError::Internal("encrypt"))?;

    let version = repo::upsert_secret(&conn, pid, &key, &nonce, &ciphertext)?;

    Ok(Json(json!({ "key": key, "version": version })))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    token: AuthedToken,
    Path((name, key)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    ensure_scope(&token, &name)?;

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let pid = repo::project_id(&conn, &name)?.ok_or(AppError::NotFound)?;

    if repo::delete_secret(&conn, pid, &key)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}
