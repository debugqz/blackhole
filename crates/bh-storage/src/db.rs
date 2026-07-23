//! SQLCipher-backed local database. Nothing touches disk in plaintext — the
//! encryption key is a raw 32-byte key handed in by the caller (typically
//! derived from the user's PIN/passcode, or held in the platform keystore —
//! see `keystore.rs`) and is never itself persisted alongside the database.
//! See `docs/SPEC.md` §7.

use std::path::Path;

use r2d2::{CustomizeConnection, Pool};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::{schema, StorageError};

#[derive(Debug)]
struct SetSqlCipherKey {
    hex_key: Zeroizing<String>,
}

/// How long a connection blocks waiting for `SQLITE_BUSY` to clear before
/// giving up. Without this, SQLite's default is 0ms — the first writer to
/// grab the lock (e.g. the disappearing-message sweeper's own pooled
/// connection, ticking on a timer) makes every other concurrent connection
/// (a live API request through a different pooled connection to the same
/// file) fail immediately with "database is locked" instead of just
/// waiting the handful of milliseconds a write actually takes.
const BUSY_TIMEOUT_MS: u32 = 5_000;

impl CustomizeConnection<Connection, rusqlite::Error> for SetSqlCipherKey {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // SQLCipher's `key` pragma does not support bound parameters.
        conn.pragma_update(None, "key", format!("\"x'{}'\"", *self.hex_key))?;
        // Force SQLCipher to actually touch the (decrypted) page cache now,
        // so a wrong key fails loudly here instead of on the first real query.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;
        // WAL lets readers proceed concurrently with a writer instead of
        // the rollback-journal default, which takes an exclusive lock for
        // the duration of every write. No-op (stays "memory") on
        // `:memory:` connections, so it's safe to set unconditionally here
        // rather than only in `open_file_pool`.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Ok(())
    }
}

/// Builds a connection pool against a SQLCipher file at `path`, keyed by
/// `key`. Shared by every independently-keyed database this crate opens —
/// the messaging database here and the payments database in
/// `payments_db.rs` — so the SQLCipher key-setup pragma sequence can't
/// drift between them. Sharing this function does not weaken the isolation
/// between those two databases: each caller still opens its own file, its
/// own key, and its own pool — nothing here lets one database see another.
pub(crate) fn open_file_pool(
    path: impl AsRef<Path>,
    key: &[u8; 32],
) -> Result<Pool<SqliteConnectionManager>, StorageError> {
    let manager = SqliteConnectionManager::file(path.as_ref());
    Pool::builder()
        .connection_customizer(Box::new(SetSqlCipherKey {
            hex_key: Zeroizing::new(hex::encode(key)),
        }))
        .build(manager)
        .map_err(StorageError::Pool)
}

/// As [`open_file_pool`], but entirely in memory (used by tests).
pub(crate) fn open_memory_pool(
    key: &[u8; 32],
) -> Result<Pool<SqliteConnectionManager>, StorageError> {
    let manager = SqliteConnectionManager::memory();
    Pool::builder()
        .max_size(1) // an in-memory SQLite DB is per-connection; keep the pool to one
        .connection_customizer(Box::new(SetSqlCipherKey {
            hex_key: Zeroizing::new(hex::encode(key)),
        }))
        .build(manager)
        .map_err(StorageError::Pool)
}

#[derive(Clone)]
pub struct Database {
    pub(crate) pool: Pool<SqliteConnectionManager>,
}

impl Database {
    /// Opens (creating if absent) a SQLCipher-encrypted database at `path`,
    /// keyed by `key`. Runs pending migrations before returning.
    pub fn open(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, StorageError> {
        let pool = open_file_pool(path, key)?;
        let db = Database { pool };
        let conn = db.conn()?;
        schema::migrate(&conn)?;
        drop(conn);
        Ok(db)
    }

    /// Opens a database entirely in memory (used by tests).
    pub fn open_in_memory(key: &[u8; 32]) -> Result<Self, StorageError> {
        let pool = open_memory_pool(key)?;
        let db = Database { pool };
        let conn = db.conn()?;
        schema::migrate(&conn)?;
        drop(conn);
        Ok(db)
    }

    pub(crate) fn conn(
        &self,
    ) -> Result<r2d2::PooledConnection<SqliteConnectionManager>, StorageError> {
        self.pool.get().map_err(StorageError::Pool)
    }
}
