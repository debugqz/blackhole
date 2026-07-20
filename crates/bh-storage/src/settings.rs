//! Flat key-value settings store — cover-traffic on/off, self-destruct
//! defaults, and similar local preferences.

use rusqlite::params;

use crate::{Database, StorageError};

impl Database {
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}
