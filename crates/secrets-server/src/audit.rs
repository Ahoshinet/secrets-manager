//! Append-only JSON Lines audit log.
//!
//! Records who did what, never *what the secret was*. Only the token
//! **name** (not the token), method, matched route template, project
//! name, and status are written. Raw request paths are never logged:
//! they can contain secret key names or attacker-chosen segments.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use axum::extract::{MatchedPath, Request, State};
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
    /// Matched route template (e.g. `/v1/projects/:name/secrets/:key`),
    /// or `(unmatched)` for requests that hit no route. Never the raw path.
    path: &'a str,
    /// Project name extracted from the path for project-scoped routes.
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<&'a str>,
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
            .with_context(|| {
                format!(
                    "failed to open audit log at {} (must not be a symlink)",
                    path.display()
                )
            })?;
        ensure_private(&file, path)?;
        Ok(AuditLog {
            file: Mutex::new(file),
        })
    }

    /// Append one audit record. Failures are reported to stderr but never
    /// abort request handling.
    pub fn record(
        &self,
        method: &Method,
        path: &str,
        project: Option<&str>,
        token: Option<&str>,
        status: u16,
    ) {
        let entry = Entry {
            ts: crate::repo::now_rfc3339(),
            token,
            method: method.as_str(),
            path,
            project,
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
    opts.create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    opts
}

#[cfg(not(unix))]
fn audit_open_options() -> OpenOptions {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    opts
}

/// Validate and fix up the *opened* file: fd-based, so it cannot be raced
/// against the open (no TOCTOU window).
#[cfg(unix)]
fn ensure_private(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = file
        .metadata()
        .with_context(|| format!("failed to stat audit log at {}", path.display()))?;
    if !meta.is_file() {
        bail!("audit log {} is not a regular file", path.display());
    }
    let mut permissions = meta.permissions();
    if permissions.mode() & 0o077 != 0 {
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .with_context(|| format!("failed to chmod audit log at {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private(file: &File, path: &Path) -> Result<()> {
    let meta = file
        .metadata()
        .with_context(|| format!("failed to stat audit log at {}", path.display()))?;
    if !meta.is_file() {
        bail!("audit log {} is not a regular file", path.display());
    }
    Ok(())
}

/// Middleware that records every request after it completes.
///
/// The token *name* is resolved independently for logging; this never
/// logs the token itself, nor any request/response body. The logged path
/// is the matched route *template* — never the raw URI, which can contain
/// secret key names or attacker-chosen segments. The project name is
/// logged separately for project-scoped routes.
pub async fn audit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());
    let project = match &matched {
        Some(t) if t.starts_with("/v1/projects/:name") => request
            .uri()
            .path()
            .split('/')
            .nth(3)
            .map(truncate_for_log),
        _ => None,
    };
    let token_name = auth::resolve_token_name(&state, request.headers());

    let response = next.run(request).await;

    state.audit.record(
        &method,
        matched.as_deref().unwrap_or("(unmatched)"),
        project.as_deref(),
        token_name.as_deref(),
        response.status().as_u16(),
    );

    response
}

/// Cap a path segment destined for the log. Valid project names are at
/// most 64 bytes; longer (hence invalid) segments are truncated so a
/// hostile request cannot bloat the audit log.
fn truncate_for_log(segment: &str) -> String {
    let mut end = segment.len().min(64);
    while !segment.is_char_boundary(end) {
        end -= 1;
    }
    segment[..end].to_string()
}
