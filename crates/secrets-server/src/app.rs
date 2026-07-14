//! Shared application state and router construction.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{delete, get, put};
use rusqlite::Connection;
use secrets_crypto::MasterKey;

use crate::audit::AuditLog;
use crate::{audit, handlers};

/// Cheaply-cloneable handle to shared server state.
#[derive(Clone)]
pub struct AppState {
    /// SQLite is single-writer; guard it with a mutex. Calls are short.
    pub db: Arc<Mutex<Connection>>,
    /// Master key, held only in memory for the process lifetime.
    pub key: Arc<MasterKey>,
    pub audit: Arc<AuditLog>,
}

/// Build the full router with the audit layer applied to every route.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(handlers::health))
        .route(
            "/v1/projects",
            get(handlers::list_projects).post(handlers::create_project),
        )
        .route("/v1/projects/{name}/secrets", get(handlers::get_secrets))
        .route(
            "/v1/projects/{name}/secrets/{key}",
            put(handlers::put_secret).delete(handlers::delete_secret),
        )
        .route(
            "/v1/tokens",
            get(handlers::list_tokens).post(handlers::create_token),
        )
        .route("/v1/tokens/{name}", delete(handlers::revoke_token))
        // Documented API contract: request bodies are capped at 1 MiB
        // (matches the clients' response-read cap). Exceeding it is 413.
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit::audit_middleware,
        ))
        .with_state(state)
}
