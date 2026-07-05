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
    repo::insert_token(&conn, name, &hash_token(raw), scope, None).unwrap();
}

fn add_token_with_expiry(db: &Db, name: &str, raw: &str, expires_at: &str) {
    let conn = db.lock().unwrap();
    repo::insert_token(&conn, name, &hash_token(raw), None, Some(expires_at)).unwrap();
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
    send_inner(router, builder, body).await
}

/// Like [`send`] but the caller supplies the raw `Authorization` header
/// verbatim, to exercise header-parsing edge cases.
async fn send_raw_auth(
    router: &Router,
    method: &str,
    uri: &str,
    auth_header: &str,
) -> (StatusCode, String) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", auth_header);
    send_inner(router, builder, None).await
}

async fn send_inner(
    router: &Router,
    builder: axum::http::request::Builder,
    body: Option<&str>,
) -> (StatusCode, String) {
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
async fn expired_token_is_401() {
    let (router, db, _tmp) = setup();
    add_token_with_expiry(&db, "dev", "tok-expired", "2000-01-01T00:00:00Z");
    let (status, _) = send(&router, "GET", "/v1/projects", Some("tok-expired"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unexpired_token_is_accepted() {
    let (router, db, _tmp) = setup();
    add_token_with_expiry(&db, "dev", "tok-live", "2999-01-01T00:00:00Z");
    let (status, _) = send(&router, "GET", "/v1/projects", Some("tok-live"), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn token_with_garbage_expiry_fails_closed() {
    let (router, db, _tmp) = setup();
    add_token_with_expiry(&db, "dev", "tok-garbage", "not-a-timestamp");
    let (status, _) = send(&router, "GET", "/v1/projects", Some("tok-garbage"), None).await;
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
    // The raw path (with the secret key name) must not be logged; only the
    // route template and the project name are.
    assert!(!audit.contains("DATABASE_URL"));
    assert!(audit.contains("/v1/projects/:name/secrets/:key"));
    assert!(audit.contains(r#""project":"cdn""#));
}

#[tokio::test]
async fn invalid_project_name_is_400_not_404() {
    let (router, db, _tmp) = setup();
    add_token(&db, "tok", "raw", None);

    // '!' is outside the allowed project-name alphabet.
    let (status, _) = send(&router, "GET", "/v1/projects/bad%21name/secrets", Some("raw"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &router,
        "DELETE",
        "/v1/projects/bad%21name/secrets/KEY",
        Some("raw"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_json_is_400() {
    let (router, db, _tmp) = setup();
    add_token(&db, "tok", "raw", None);

    let (status, _) = send(&router, "POST", "/v1/projects", Some("raw"), Some("{not json")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_body_is_413() {
    let (router, db, _tmp) = setup();
    add_token(&db, "tok", "raw", None);
    let (status, _) = send(&router, "POST", "/v1/projects", Some("raw"), Some(r#"{"name":"cdn"}"#)).await;
    assert_eq!(status, StatusCode::CREATED);

    let big = format!(r#"{{"value":"{}"}}"#, "x".repeat(2 * 1024 * 1024));
    let (status, _) = send(
        &router,
        "PUT",
        "/v1/projects/cdn/secrets/BIG",
        Some("raw"),
        Some(&big),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

// ---- header-parsing / auth bypass attempts ---------------------------

#[tokio::test]
async fn lowercase_bearer_scheme_is_rejected() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "real-token", None);
    // The scheme is case-sensitive by design; anything but `Bearer ` fails.
    let (status, _) = send_raw_auth(&router, "GET", "/v1/projects", "bearer real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_bearer_token_is_rejected() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "real-token", None);
    let (status, _) = send_raw_auth(&router, "GET", "/v1/projects", "Bearer ").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_without_scheme_prefix_is_rejected() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "real-token", None);
    // Presenting the raw token with no `Bearer ` prefix must not authenticate.
    let (status, _) = send_raw_auth(&router, "GET", "/v1/projects", "real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn leading_space_in_token_is_rejected() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "real-token", None);
    // `Bearer  real-token` -> extracted token is ` real-token` (leading
    // space), which must not match the stored hash.
    let (status, _) = send_raw_auth(&router, "GET", "/v1/projects", "Bearer  real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- scope enforcement -----------------------------------------------

#[tokio::test]
async fn scoped_token_cannot_create_other_project() {
    let (router, db, _tmp) = setup();
    add_token(&db, "cdn-only", "tok-cdn", Some("cdn"));
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok-cdn"),
        Some(r#"{"name":"mcp"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scoped_token_forbidden_on_existing_other_project() {
    let (router, db, _tmp) = setup();
    // Full token provisions a real project the scoped token must not reach.
    add_token(&db, "admin", "tok-admin", None);
    add_token(&db, "cdn-only", "tok-cdn", Some("cdn"));
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok-admin"),
        Some(r#"{"name":"mcp"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 403 must win over any existence check (no project enumeration).
    let (status, _) =
        send(&router, "GET", "/v1/projects/mcp/secrets", Some("tok-cdn"), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        &router,
        "PUT",
        "/v1/projects/mcp/secrets/KEY",
        Some("tok-cdn"),
        Some(r#"{"value":"x"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---- input-validation boundaries -------------------------------------

#[tokio::test]
async fn project_name_length_boundary() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);

    let ok_name = "a".repeat(64);
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok"),
        Some(&format!(r#"{{"name":"{ok_name}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "64-char name should be allowed");

    let too_long = "a".repeat(65);
    let (status, _) = send(
        &router,
        "POST",
        "/v1/projects",
        Some("tok"),
        Some(&format!(r#"{{"name":"{too_long}"}}"#)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "65-char name should be rejected");
}

#[tokio::test]
async fn key_name_length_boundary() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);
    let (status, _) = send(&router, "POST", "/v1/projects", Some("tok"), Some(r#"{"name":"p"}"#)).await;
    assert_eq!(status, StatusCode::CREATED);

    let ok_key = "K".repeat(128);
    let (status, _) = send(
        &router,
        "PUT",
        &format!("/v1/projects/p/secrets/{ok_key}"),
        Some("tok"),
        Some(r#"{"value":"v"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "128-char key should be allowed");

    let too_long = "K".repeat(129);
    let (status, _) = send(
        &router,
        "PUT",
        &format!("/v1/projects/p/secrets/{too_long}"),
        Some("tok"),
        Some(r#"{"value":"v"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "129-char key should be rejected");
}

#[tokio::test]
async fn missing_value_field_is_400() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);
    let (status, _) = send(&router, "POST", "/v1/projects", Some("tok"), Some(r#"{"name":"p"}"#)).await;
    assert_eq!(status, StatusCode::CREATED);

    // Body is valid JSON but missing the required `value` field.
    let (status, _) = send(
        &router,
        "PUT",
        "/v1/projects/p/secrets/KEY",
        Some("tok"),
        Some(r#"{}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_content_type_is_rejected() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);
    // Deliberately omit the JSON content-type header.
    let builder = Request::builder()
        .method("POST")
        .uri("/v1/projects")
        .header("authorization", "Bearer tok");
    let req = builder.body(Body::from(r#"{"name":"p"}"#.to_string())).unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    // axum's Json extractor requires application/json; anything else is a
    // client error (415/400 depending on version), never a 2xx or 5xx.
    assert!(
        res.status().is_client_error(),
        "expected client error, got {}",
        res.status()
    );
}

#[tokio::test]
async fn unknown_method_is_405() {
    let (router, _db, _tmp) = setup();
    let (status, _) = send(&router, "PATCH", "/v1/projects", None, None).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn encoded_slash_in_project_name_is_not_a_bypass() {
    let (router, db, _tmp) = setup();
    add_token(&db, "dev", "tok", None);
    // `cdn%2f..%2fmcp` must never be accepted as a valid project name.
    let (status, _) = send(
        &router,
        "GET",
        "/v1/projects/cdn%2f..%2fmcp/secrets",
        Some("tok"),
        None,
    )
    .await;
    assert!(
        status.is_client_error(),
        "encoded-slash project name should be a client error, got {status}"
    );
    assert_ne!(status, StatusCode::OK);
}
