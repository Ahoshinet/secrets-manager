//! HTTP handlers for the `/v1` API.
//!
//! All handlers except `health` require a valid bearer token (enforced by
//! the [`AuthedToken`] extractor). Scoped tokens are further checked with
//! [`auth::ensure_scope`]. No handler ever returns secret material in an
//! error path.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use secrecy::{ExposeSecret, SecretString};
use secrets_crypto::{aad_bytes, decrypt, encrypt, generate_token, hash_token};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroize;

use crate::app::AppState;
use crate::auth::{ensure_admin, ensure_scope};
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

/// Map a JSON extraction failure to the documented contract: `413` when
/// the body exceeded the size limit, `400` for everything else
/// (malformed JSON, wrong content type, missing fields).
fn map_json_rejection(rejection: JsonRejection) -> AppError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::PayloadTooLarge
    } else {
        AppError::BadRequest("invalid JSON body")
    }
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
    body: Result<Json<CreateProjectBody>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Json(body) = body.map_err(map_json_rejection)?;
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

/// Note on memory hygiene: the decrypted values necessarily traverse the
/// JSON serializer and HTTP stack as plain heap data; those copies are
/// outside our control and are not zeroized. See docs/SECURITY.md.
pub async fn get_secrets(
    State(state): State<AppState>,
    token: AuthedToken,
    Path(name): Path<String>,
) -> Result<Json<BTreeMap<String, String>>, AppError> {
    if !valid_project(&name) {
        return Err(AppError::BadRequest("invalid project name"));
    }
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
    body: Result<Json<SetSecretBody>, JsonRejection>,
) -> Result<Json<Value>, AppError> {
    let Json(mut body) = body.map_err(map_json_rejection)?;
    if !valid_project(&name) {
        body.value.zeroize();
        return Err(AppError::BadRequest("invalid project name"));
    }
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
    if !valid_project(&name) {
        return Err(AppError::BadRequest("invalid project name"));
    }
    if !valid_key(&key) {
        return Err(AppError::BadRequest("invalid key name"));
    }
    ensure_scope(&token, &name)?;

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let pid = repo::project_id(&conn, &name)?.ok_or(AppError::NotFound)?;

    if repo::delete_secret(&conn, pid, &key)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

#[derive(Deserialize)]
pub struct CreateTokenBody {
    name: String,
    project: Option<String>,
    ttl_days: Option<u32>,
    #[serde(default)]
    no_expiry: bool,
}

pub async fn create_token(
    State(state): State<AppState>,
    token: AuthedToken,
    body: Result<Json<CreateTokenBody>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    ensure_admin(&token)?;

    let Json(body) = body.map_err(map_json_rejection)?;
    if !valid_project(&body.name) {
        return Err(AppError::BadRequest("invalid token name"));
    }
    if let Some(project) = &body.project {
        if !valid_project(project) {
            return Err(AppError::BadRequest("invalid project scope name"));
        }
    }
    if body.no_expiry && body.ttl_days.is_some() {
        return Err(AppError::BadRequest(
            "ttl_days cannot be used with no_expiry",
        ));
    }

    let expires_at = if body.no_expiry {
        None
    } else {
        let days = body.ttl_days.unwrap_or(90);
        if days == 0 {
            return Err(AppError::BadRequest("ttl_days must be at least 1"));
        }
        Some(
            (time::OffsetDateTime::now_utc() + time::Duration::days(i64::from(days)))
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|_| AppError::Internal("format token expiry"))?,
        )
    };

    let new_token = generate_token();
    let token_hash = hash_token(new_token.expose_secret());
    {
        let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
        repo::insert_token(
            &conn,
            &body.name,
            &token_hash,
            body.project.as_deref(),
            expires_at.as_deref(),
        )?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "name": body.name,
            "scope": body.project,
            "expires_at": expires_at,
            "token": new_token.expose_secret(),
        })),
    ))
}

pub async fn list_tokens(
    State(state): State<AppState>,
    token: AuthedToken,
) -> Result<Json<Value>, AppError> {
    ensure_admin(&token)?;

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let tokens: Vec<Value> = repo::list_tokens(&conn)?
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name,
                "scope": t.scope,
                "created_at": t.created_at,
                "expires_at": t.expires_at,
                "revoked": t.revoked,
            })
        })
        .collect();
    Ok(Json(json!({ "tokens": tokens })))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    token: AuthedToken,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_admin(&token)?;
    if !valid_project(&name) {
        return Err(AppError::BadRequest("invalid token name"));
    }

    let conn = state.db.lock().map_err(|_| AppError::Internal("db lock"))?;
    let revoked = repo::revoke_token(&conn, &name)?;
    Ok(Json(json!({ "revoked": revoked })))
}
