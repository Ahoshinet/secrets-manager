//! Application error type.
//!
//! Responses carry only generic, secret-free messages. Internal details
//! are logged to stderr as fixed strings, never with secret material.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest(&'static str),
    Conflict(&'static str),
    /// Something failed server-side. The `&'static str` is a non-secret
    /// context tag logged to stderr; the client only sees a generic msg.
    Internal(&'static str),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg): (StatusCode, &str) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::Internal(tag) => {
                // Fixed tag only — no secret material.
                eprintln!("[error] internal: {tag}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

/// Map a rusqlite error to a generic internal error (never leak details).
impl From<rusqlite::Error> for AppError {
    fn from(_e: rusqlite::Error) -> Self {
        AppError::Internal("database")
    }
}
