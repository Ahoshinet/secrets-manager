//! Typed data-access layer over SQLite.
//!
//! No crypto happens here — callers pass already-encrypted `(nonce,
//! ciphertext)` blobs. This keeps plaintext out of the persistence layer.

use rusqlite::{params, Connection, OptionalExtension};
use secrets_crypto::ct_eq;

/// RFC3339 UTC timestamp for `created_at` / `updated_at` columns.
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("Rfc3339 formatting is infallible for now_utc")
}

// ---- meta ------------------------------------------------------------

pub fn get_meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<Vec<u8>>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
        r.get::<_, Vec<u8>>(0)
    })
    .optional()
}

pub fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

// ---- projects --------------------------------------------------------

pub struct Project {
    pub name: String,
    pub created_at: String,
}

pub fn create_project(conn: &Connection, name: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO projects(name, created_at) VALUES(?1, ?2)",
        params![name, now_rfc3339()],
    )?;
    Ok(())
}

pub fn list_projects(conn: &Connection) -> rusqlite::Result<Vec<Project>> {
    let mut stmt =
        conn.prepare("SELECT name, created_at FROM projects ORDER BY name")?;
    let rows = stmt.query_map([], |r| {
        Ok(Project {
            name: r.get(0)?,
            created_at: r.get(1)?,
        })
    })?;
    rows.collect()
}

pub fn project_id(conn: &Connection, name: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM projects WHERE name = ?1",
        params![name],
        |r| r.get::<_, i64>(0),
    )
    .optional()
}

// ---- secrets ---------------------------------------------------------

/// One encrypted secret row (key + ciphertext material).
pub struct SecretRow {
    pub key: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Insert or update a secret, bumping `version` on update.
pub fn upsert_secret(
    conn: &Connection,
    project_id: i64,
    key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO secrets(project_id, key, nonce, ciphertext, version, updated_at)
         VALUES(?1, ?2, ?3, ?4, 1, ?5)
         ON CONFLICT(project_id, key) DO UPDATE SET
             nonce = excluded.nonce,
             ciphertext = excluded.ciphertext,
             version = secrets.version + 1,
             updated_at = excluded.updated_at",
        params![project_id, key, nonce, ciphertext, now_rfc3339()],
    )?;
    conn.query_row(
        "SELECT version FROM secrets WHERE project_id = ?1 AND key = ?2",
        params![project_id, key],
        |r| r.get::<_, i64>(0),
    )
}

pub fn list_secret_rows(
    conn: &Connection,
    project_id: i64,
) -> rusqlite::Result<Vec<SecretRow>> {
    let mut stmt = conn.prepare(
        "SELECT key, nonce, ciphertext FROM secrets WHERE project_id = ?1 ORDER BY key",
    )?;
    let rows = stmt.query_map(params![project_id], |r| {
        Ok(SecretRow {
            key: r.get(0)?,
            nonce: r.get(1)?,
            ciphertext: r.get(2)?,
        })
    })?;
    rows.collect()
}

/// Delete a secret. Returns true if a row was removed.
pub fn delete_secret(
    conn: &Connection,
    project_id: i64,
    key: &str,
) -> rusqlite::Result<bool> {
    let affected = conn.execute(
        "DELETE FROM secrets WHERE project_id = ?1 AND key = ?2",
        params![project_id, key],
    )?;
    Ok(affected > 0)
}

// ---- tokens ----------------------------------------------------------

pub struct TokenInfo {
    pub name: String,
    pub scope: Option<String>,
    pub created_at: String,
    pub revoked: bool,
}

/// The authenticated identity resolved from a bearer token.
#[derive(Clone)]
pub struct AuthedToken {
    pub name: String,
    pub scope: Option<String>,
}

pub fn insert_token(
    conn: &Connection,
    name: &str,
    token_hash: &[u8],
    scope: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO tokens(name, token_hash, project_scope, created_at, revoked)
         VALUES(?1, ?2, ?3, ?4, 0)",
        params![name, token_hash, scope, now_rfc3339()],
    )?;
    Ok(())
}

pub fn list_tokens(conn: &Connection) -> rusqlite::Result<Vec<TokenInfo>> {
    // Note: token_hash is intentionally never selected/exposed.
    let mut stmt = conn.prepare(
        "SELECT name, project_scope, created_at, revoked FROM tokens ORDER BY created_at",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(TokenInfo {
            name: r.get(0)?,
            scope: r.get(1)?,
            created_at: r.get(2)?,
            revoked: r.get::<_, i64>(3)? != 0,
        })
    })?;
    rows.collect()
}

/// Revoke all active tokens with the given name. Returns count revoked.
pub fn revoke_token(conn: &Connection, name: &str) -> rusqlite::Result<usize> {
    let n = conn.execute(
        "UPDATE tokens SET revoked = 1 WHERE name = ?1 AND revoked = 0",
        params![name],
    )?;
    Ok(n)
}

/// Authenticate a presented token by its SHA-256 hash.
///
/// Fetches all active tokens and compares each hash in **constant time**
/// (`subtle`) to avoid leaking timing information. Returns the matching
/// identity, if any.
pub fn authenticate(
    conn: &Connection,
    presented_hash: &[u8],
) -> rusqlite::Result<Option<AuthedToken>> {
    let mut stmt = conn.prepare(
        "SELECT name, token_hash, project_scope FROM tokens WHERE revoked = 0",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Option<String>>(2)?,
        ))
    })?;

    let mut found: Option<AuthedToken> = None;
    for row in rows {
        let (name, hash, scope) = row?;
        // Do not early-return on match: keep the loop shape uniform.
        if ct_eq(&hash, presented_hash) {
            found = Some(AuthedToken { name, scope });
        }
    }
    Ok(found)
}
