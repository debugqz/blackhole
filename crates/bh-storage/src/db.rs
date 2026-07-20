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

impl CustomizeConnection<Connection, rusqlite::Error> for SetSqlCipherKey {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // SQLCipher's `key` pragma does not support bound parameters.
        conn.pragma_update(None, "key", format!("\"x'{}'\"", &*self.hex_key))?;
        // Force SQLCipher to actually touch the (decrypted) page cache now,
        // so a wrong key fails loudly here instead of on the first real query.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Database {
    pub(crate) pool: Pool<SqliteConnectionManager>,
}

impl Database {
    /// Opens (creating if absent) a SQLCipher-encrypted database at `path`,
    /// keyed by `key`. Runs pending migrations before returning.
    pub fn open(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, StorageError> {
        let manager = SqliteConnectionManager::file(path.as_ref());
        let pool = Pool::builder()
            .connection_customizer(Box::new(SetSqlCipherKey {
                hex_key: Zeroizing::new(hex::encode(key)),
            }))
            .build(manager)
            .map_err(StorageError::Pool)?;

        let db = Database { pool };
        let conn = db.conn()?;
        schema::migrate(&conn)?;
        drop(conn);
        Ok(db)
    }

    /// Opens a database entirely in memory (used by tests).
    pub fn open_in_memory(key: &[u8; 32]) -> Result<Self, StorageError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1) // an in-memory SQLite DB is per-connection; keep the pool to one
            .connection_customizer(Box::new(SetSqlCipherKey {
                hex_key: Zeroizing::new(hex::encode(key)),
            }))
            .build(manager)
            .map_err(StorageError::Pool)?;

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
