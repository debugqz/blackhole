//! Persistence for `bh-crypto`'s Double Ratchet session state. This crate
//! never interprets `ratchet_state` — it's an opaque blob owned by
//! `bh-crypto`, protected only by the fact the whole database is
//! SQLCipher-encrypted at rest.

use rusqlite::params;

use crate::{models::Session, Database, StorageError};

impl Database {
    pub fn upsert_session(&self, session: &Session) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO sessions (session_id, contact_id, device_id, ratchet_state, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(session_id) DO UPDATE SET
                ratchet_state = excluded.ratchet_state,
                updated_at = excluded.updated_at",
            params![
                session.session_id,
                session.contact_id,
                session.device_id,
                session.ratchet_state,
                session.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<Session>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT session_id, contact_id, device_id, ratchet_state, updated_at
                 FROM sessions WHERE session_id = ?1",
                params![session_id],
                |row| {
                    Ok(Session {
                        session_id: row.get(0)?,
                        contact_id: row.get(1)?,
                        device_id: row.get(2)?,
                        ratchet_state: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn delete_session(&self, session_id: &str) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(())
    }
}
