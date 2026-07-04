//! SQLite connection setup and schema migration.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Open (creating if needed) the database, apply pragmas and the schema.
pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("failed to open database at {}", path.display()))?;

    // Durability + integrity oriented pragmas.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;",
    )
    .context("failed to set pragmas")?;

    migrate(&conn)?;
    Ok(conn)
}

/// Create tables if they do not already exist.
pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
          key   TEXT PRIMARY KEY,
          value BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
          id         INTEGER PRIMARY KEY,
          name       TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secrets (
          id         INTEGER PRIMARY KEY,
          project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          key        TEXT NOT NULL,
          nonce      BLOB NOT NULL,
          ciphertext BLOB NOT NULL,
          version    INTEGER NOT NULL DEFAULT 1,
          updated_at TEXT NOT NULL,
          UNIQUE(project_id, key)
        );

        CREATE TABLE IF NOT EXISTS tokens (
          id            INTEGER PRIMARY KEY,
          name          TEXT NOT NULL,
          token_hash    BLOB NOT NULL,
          project_scope TEXT,
          created_at    TEXT NOT NULL,
          revoked       INTEGER NOT NULL DEFAULT 0,
          expires_at    TEXT
        );
        "#,
    )
    .context("schema migration failed")?;

    // Additive migration for databases created before token expiry existed.
    // NULL means "never expires" so pre-existing tokens keep working.
    if !column_exists(conn, "tokens", "expires_at")? {
        conn.execute_batch("ALTER TABLE tokens ADD COLUMN expires_at TEXT;")
            .context("failed to add tokens.expires_at column")?;
    }
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2")
        .context("failed to inspect schema")?;
    let exists = stmt
        .exists(rusqlite::params![table, column])
        .context("failed to inspect schema")?;
    Ok(exists)
}
