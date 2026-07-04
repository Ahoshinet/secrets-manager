//! Cross-process exclusive lock guarding the database.
//!
//! The running server holds this lock for its whole lifetime. `rekey`
//! acquires the same lock before touching the database, so a rekey can
//! never run while a server process still holds the old master key in
//! memory (which would let it keep writing old-key ciphertext after the
//! rekey and silently corrupt the database from the operator's view).
//!
//! Implementation: a dedicated SQLite database (`<db>.lock`) held under
//! `BEGIN EXCLUSIVE`. SQLite maps this to OS-level file locks on both
//! Unix and Windows, and the OS releases them when the process exits —
//! even on crash — so a stale lock can never wedge the system.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Held for as long as the owning process needs exclusive access.
/// Dropping it releases the lock.
pub struct DbLock {
    _conn: Connection,
    path: PathBuf,
}

impl std::fmt::Debug for DbLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbLock").field("path", &self.path).finish()
    }
}

fn lock_path(db_path: &Path) -> PathBuf {
    let mut name = db_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("secrets.db"))
        .to_os_string();
    name.push(".lock");
    db_path.with_file_name(name)
}

/// Try to acquire the exclusive database lock without blocking.
///
/// `holder_hint` is included in the error message so the operator knows
/// what to do (e.g. "stop the running secrets-server before rekeying").
pub fn acquire(db_path: &Path, holder_hint: &str) -> Result<DbLock> {
    let path = lock_path(db_path);
    let conn = Connection::open(&path)
        .with_context(|| format!("failed to open lock file {}", path.display()))?;
    conn.busy_timeout(Duration::ZERO)
        .context("failed to configure lock connection")?;
    conn.execute_batch("BEGIN EXCLUSIVE;").map_err(|_| {
        anyhow::anyhow!(
            "database {} is locked by another process — {holder_hint}",
            db_path.display()
        )
    })?;
    Ok(DbLock { _conn: conn, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_while_first_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("secrets.db");

        let first = acquire(&db, "stop the other process").unwrap();
        let second = acquire(&db, "stop the other process");
        assert!(second.is_err(), "second acquire should fail");
        assert!(second
            .unwrap_err()
            .to_string()
            .contains("locked by another process"));

        drop(first);
        acquire(&db, "stop the other process").expect("lock should be free after drop");
    }
}
