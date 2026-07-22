//! Connection handling for the payments/subscriptions database — a
//! SQLCipher file entirely separate from the messaging database (`db.rs`),
//! with its own encryption key and its own schema (`payments_schema.rs`).
//! CLAUDE.md non-negotiable: "Payments and messaging data are strictly
//! isolated — never link the two databases directly." Nothing in this
//! crate ever opens both under one connection or joins across them; the
//! only thing that ever crosses is the opaque entitlement token minted by
//! `payments::PaymentsDatabase::mark_purchase_paid` and handed to
//! `Database::grant_cosmetic` on the messaging side (SPEC.md §12).

use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::db::{open_file_pool, open_memory_pool};
use crate::{payments_schema, StorageError};

#[derive(Clone)]
pub struct PaymentsDatabase {
    pub(crate) pool: Pool<SqliteConnectionManager>,
}

impl PaymentsDatabase {
    /// Opens (creating if absent) the payments SQLCipher database at
    /// `path`, keyed by `key`. Callers must use a different `path` and a
    /// different `key` than the ones passed to `Database::open` — see the
    /// module doc for why that separation matters.
    pub fn open(path: impl AsRef<Path>, key: &[u8; 32]) -> Result<Self, StorageError> {
        let pool = open_file_pool(path, key)?;
        let db = PaymentsDatabase { pool };
        let conn = db.conn()?;
        payments_schema::migrate(&conn)?;
        drop(conn);
        Ok(db)
    }

    /// Opens a payments database entirely in memory (used by tests).
    pub fn open_in_memory(key: &[u8; 32]) -> Result<Self, StorageError> {
        let pool = open_memory_pool(key)?;
        let db = PaymentsDatabase { pool };
        let conn = db.conn()?;
        payments_schema::migrate(&conn)?;
        drop(conn);
        Ok(db)
    }

    pub(crate) fn conn(
        &self,
    ) -> Result<r2d2::PooledConnection<SqliteConnectionManager>, StorageError> {
        self.pool.get().map_err(StorageError::Pool)
    }
}
