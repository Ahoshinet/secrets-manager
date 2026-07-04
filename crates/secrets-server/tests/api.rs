//! End-to-end API tests driving the real router against a temp SQLite DB.
//!
//! A fixed test key ([`MasterKey::from_bytes`]) is used to avoid the
//! expensive Argon2id derivation; the crypto path itself is covered by
//! `secrets-crypto`'s unit tests.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use secrets_crypto::{hash_token, MasterKey};
use secrets_server::app::{self, AppState};
use secrets_server::audit::AuditLog;
use secrets_server::{db, repo};
use tempfile::TempDir;
use tower::ServiceExt; // for `oneshot`

type Db = Arc<Mutex<rusqlite::Connection>>;

fn setup() -> (Router, Db, TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let conn = db::open(&tmp.path().join("test.db")).unwrap();
    let db: Db = Arc::new(Mutex::new(conn));
    let audit = Arc::new(AuditLog::open(&tmp.path().join("audit.jsonl")).unwrap());

    let state = AppState {
        db: db.clone(),
        key: Arc::new(MasterKey::from_bytes([9u8; 32])),
        audit,
    };
    (app::router(state), db, tmp)
}

fn add_token(db: &Db, name: &str, raw: &str, scope: Option<&str>) {
    let conn = db.lock().unwrap();
    repo::insert_token(&conn, name, &hash_token(raw), scope).unwrap();
}

async fn send(
    router: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn health_needs_no_auth() {
    let (router, _db, _tmp) = setup();
    let (status, body) = send(&router, "GET", "/v1/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ok"));
}

#[tokio::test]
async fn missing_token_is_401() {
    let (router, _db, _tmp) = setup();
    let (status, _) = send(&router, "GET", "/v1/projects", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_is_401() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "real-token", None);
    let (status, _) = send(&router, "GET", "/v1/projects", Some("wrong-token"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_token_is_401() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok-abc", None);
    {
        let conn = db.lock().unwrap();
        let n = repo::revoke_token(&conn, "dev").unwrap();
        assert_eq!(n, 1);
    }
    let (status, _) = send(&router, "GET", "/v1/projects", Some("tok-abc"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scoped_token_forbidden_on_other_project() {
    let (router, db, _tmp) = setup();
    add_token(&db, "cdn-only", "tok-cdn", Some("cdn"));
    // Accessing a different project must be 403 regardless of existence.
    let (status, _) =
        send(&router, "GET", "/v1/projects/mcp/secrets", Some("tok-cdn"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scoped_token_allowed_on_own_project() {
    let (router, db, _tmp) = setup();
    add_token(&db, "cdn-only", "tok-cdn", Some("cdn"));
    // Create the project (scoped token may create its own).
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok-cdn"),
        Some(r#"{"name":"cdn"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) =
        send(&router, "GET", "/v1/projects/cdn/secrets", Some("tok-cdn"), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn put_on_unknown_project_is_404() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);
    let (status, _) = send(
        &router,
        "PUT",
        "/v1/projects/ghost/secrets/KEY",
        Some("tok"),
        Some(r#"{"value":"x"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn full_crud_roundtrip_and_ciphertext_at_rest() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);

    // Create project.
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok"),
        Some(r#"{"name":"cdn"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Duplicate create -> 409.
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok"),
        Some(r#"{"name":"cdn"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Set a secret.
    let secret_value = "postgres://user:p@ss@db.internal/app";
    let (status, body) = send(
        &router,
        "PUT",
        "/v1/projects/cdn/secrets/DATABASE_URL",
        Some("tok"),
        Some(&format!(r#"{{"value":"{secret_value}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"version\":1"));

    // Read it back — value must match.
    let (status, body) =
        send(&router, "GET", "/v1/projects/cdn/secrets", Some("tok"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(secret_value), "value roundtrip failed: {body}");

    // At rest, the ciphertext must NOT contain the plaintext.
    {
        let conn = db.lock().unwrap();
        let ct: Vec<u8> = conn
            .query_row("SELECT ciphertext FROM secrets", [], |r| r.get(0))
            .unwrap();
        let plain = secret_value.as_bytes();
        assert!(
            !ct.windows(plain.len()).any(|w| w == plain),
            "plaintext leaked into ciphertext column"
        );
    }

    // Update bumps version.
    let (status, body) = send(
        &router,
        "PUT",
        "/v1/projects/cdn/secrets/DATABASE_URL",
        Some("tok"),
        Some(r#"{"value":"new"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"version\":2"));

    // Delete it.
    let (status, _) = send(
        &router,
        "DELETE",
        "/v1/projects/cdn/secrets/DATABASE_URL",
        Some("tok"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Now gone.
    let (status, body) =
        send(&router, "GET", "/v1/projects/cdn/secrets", Some("tok"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("DATABASE_URL"));

    // Deleting again -> 404.
    let (status, _) = send(
        &router,
        "DELETE",
        "/v1/projects/cdn/secrets/DATABASE_URL",
        Some("tok"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_names_are_400() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);

    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok"),
        Some(r#"{"name":"bad name!"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn audit_logs_token_name_but_not_token_or_secret_value() {
    let (router, db, tmp) = setup();
    add_token(&db, "dev-token-name", "raw-token-value", None);

    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("raw-token-value"),
        Some(r#"{"name":"cdn"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let secret_value = "postgres://user:pass@host/db";
    let (status, _) = send(
        &router,
        "PUT",
        "/v1/projects/cdn/secrets/DATABASE_URL",
        Some("raw-token-value"),
        Some(&format!(r#"{{"value":"{secret_value}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let audit = std::fs::read_to_string(tmp.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("dev-token-name"));
    assert!(!audit.contains("raw-token-value"));
    assert!(!audit.contains(secret_value));
}
