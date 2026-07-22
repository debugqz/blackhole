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

    /// Opt-in "typing…" presence indicator toggle (see `bh-api::presence`).
    /// Absent key == off: this must default to OFF without requiring a
    /// migration or an explicit row, so a fresh/existing database with no
    /// opinion on the setting behaves as "never send typing signals."
    /// Only the on/off *preference* lives here — the ephemeral typing
    /// signal itself never touches this table or any other durable store.
    pub fn typing_indicators_enabled(&self) -> Result<bool, StorageError> {
        Ok(self.get_setting(TYPING_INDICATORS_SETTING_KEY)?.as_deref() == Some("1"))
    }

    pub fn set_typing_indicators_enabled(&self, enabled: bool) -> Result<(), StorageError> {
        self.set_setting(
            TYPING_INDICATORS_SETTING_KEY,
            if enabled { "1" } else { "0" },
        )
    }
}

const TYPING_INDICATORS_SETTING_KEY: &str = "typing_indicators_enabled";
