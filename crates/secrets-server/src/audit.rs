//! Append-only JSON Lines audit log.
//!
//! Records who did what, never *what the secret was*. Only the token
//! **name** (not the token), method, path, and status are written.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use serde::Serialize;

use crate::app::AppState;
use crate::auth;

pub struct AuditLog {
    file: Mutex<File>,
}

#[derive(Serialize)]
struct Entry<'a> {
    ts: String,
    /// Token *name* only. `None` when the request was unauthenticated.
    token: Option<&'a str>,
    method: &'a str,
    path: &'a str,
    status: u16,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create audit log directory at {}",
                    parent.display()
                )
            })?;
        }
        let file = audit_open_options()
            .open(path)
            .with_context(|| format!("failed to open audit log at {}", path.display()))?;
        set_private_permissions(path)?;
        Ok(AuditLog {
            file: Mutex::new(file),
        })
    }

    /// Append one audit record. Failures are reported to stderr but never
    /// abort request handling.
    pub fn record(&self, method: &Method, path: &str, token: Option<&str>, status: u16) {
        let entry = Entry {
            ts: crate::repo::now_rfc3339(),
            token,
            method: method.as_str(),
            path,
            status,
        };

        let mut line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("[warn] failed to serialize audit entry");
                return;
            }
        };
        line.push('\n');

        if let Ok(mut f) = self.file.lock() {
            if f.write_all(line.as_bytes()).and_then(|_| f.flush()).is_err() {
                eprintln!("[warn] failed to write audit entry");
            }
        }
    }
}

#[cfg(unix)]
fn audit_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = OpenOptions::new();
    opts.create(true).append(true).mode(0o600);
    opts
}

#[cfg(not(unix))]
fn audit_open_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    opts
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Middleware that records every request after it completes.
///
/// The token *name* is resolved independently for logging; this never
/// logs the token itself, nor any request/response body.
pub async fn audit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let token_name = auth::resolve_token_name(&state, request.headers());

    let response = next.run(request).await;

    state
        .audit
        .record(&method, &path, token_name.as_deref(), response.status().as_u16());

    response
}
