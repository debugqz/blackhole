//! Delivery state for messages a linked secondary device asked its
//! primary to send (`schema.rs`'s `SCHEMA_V22`).
//!
//! Only ever written by a secondary. On a primary this table stays empty,
//! which is why the state lives here instead of as a column on `messages`.

use rusqlite::params;

use crate::{Database, StorageError};

/// Where a delegated send currently stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    /// Handed to (or still being retried toward) the primary; no answer
    /// yet. A message sits here while the primary is offline — the request
    /// waits in its mailbox until the TTL, so this is "delayed", not
    /// "lost".
    Pending,
    /// The primary confirmed it sent the message.
    Sent,
    /// The primary refused it — a broadcast channel the account doesn't
    /// own, a group it is no longer in, a blocked contact, a revoked
    /// device. Final: never retried, because retrying would fail
    /// identically.
    Failed,
}

impl DelegationState {
    pub fn as_str(self) -> &'static str {
        match self {
            DelegationState::Pending => "pending",
            DelegationState::Sent => "sent",
            DelegationState::Failed => "failed",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(DelegationState::Pending),
            "sent" => Some(DelegationState::Sent),
            "failed" => Some(DelegationState::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DelegatedSend {
    pub message_id: String,
    pub state: DelegationState,
    pub error: Option<String>,
    pub updated_at: i64,
}

impl Database {
    pub fn upsert_delegated_send(
        &self,
        message_id: &str,
        state: DelegationState,
        error: Option<&str>,
        updated_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO delegated_sends (message_id, state, error, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(message_id) DO UPDATE SET
                state = excluded.state,
                error = excluded.error,
                updated_at = excluded.updated_at",
            params![message_id, state.as_str(), error, updated_at],
        )?;
        Ok(())
    }

    pub fn get_delegated_send(
        &self,
        message_id: &str,
    ) -> Result<Option<DelegatedSend>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT message_id, state, error, updated_at
                 FROM delegated_sends WHERE message_id = ?1",
                params![message_id],
                |row| {
                    let state: String = row.get(1)?;
                    Ok(DelegatedSend {
                        message_id: row.get(0)?,
                        // A row whose CHECK constraint the DB already
                        // enforced can only fail this if the file was
                        // edited outside the app; treating it as Failed
                        // keeps a corrupt value from being retried forever.
                        state: DelegationState::from_str(&state).unwrap_or(DelegationState::Failed),
                        error: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Oldest-first, so a retry sweep preserves the order the user typed
    /// them in rather than delivering a backlog scrambled.
    pub fn list_pending_delegated_sends(
        &self,
        limit: i64,
    ) -> Result<Vec<DelegatedSend>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT message_id, state, error, updated_at
             FROM delegated_sends WHERE state = 'pending'
             ORDER BY updated_at ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let state: String = row.get(1)?;
            Ok(DelegatedSend {
                message_id: row.get(0)?,
                state: DelegationState::from_str(&state).unwrap_or(DelegationState::Failed),
                error: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Contact, Message};

    fn db_with_one_message() -> (Database, String) {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_contact(&Contact {
            contact_id: "c1".into(),
            identity_public_key: vec![1u8; 64],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
        let conversation = db.ensure_direct_conversation("c1", 0).unwrap();
        db.insert_message(&Message {
            message_id: "req-1".into(),
            conversation_id: conversation.conversation_id.clone(),
            sender_contact_id: None,
            body: Some("hi".into()),
            sent_at: 10,
            received_at: None,
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();
        (db, "req-1".to_string())
    }

    #[test]
    fn pending_becomes_sent_and_leaves_the_pending_list() {
        let (db, id) = db_with_one_message();
        db.upsert_delegated_send(&id, DelegationState::Pending, None, 10)
            .unwrap();
        assert_eq!(db.list_pending_delegated_sends(10).unwrap().len(), 1);

        db.upsert_delegated_send(&id, DelegationState::Sent, None, 20)
            .unwrap();
        assert!(db.list_pending_delegated_sends(10).unwrap().is_empty());
        let row = db.get_delegated_send(&id).unwrap().unwrap();
        assert_eq!(row.state, DelegationState::Sent);
    }

    /// A rejection is final and carries its reason — the secondary shows a
    /// failed send rather than retrying something that will fail the same
    /// way every time.
    #[test]
    fn a_failed_delegation_records_why_and_is_not_pending() {
        let (db, id) = db_with_one_message();
        db.upsert_delegated_send(
            &id,
            DelegationState::Failed,
            Some("broadcast channel: only the owner may post"),
            30,
        )
        .unwrap();

        assert!(db.list_pending_delegated_sends(10).unwrap().is_empty());
        let row = db.get_delegated_send(&id).unwrap().unwrap();
        assert_eq!(row.state, DelegationState::Failed);
        assert!(row.error.unwrap().contains("only the owner may post"));
    }

    /// Deleting the message takes its delegation state with it — the
    /// disappearing-message sweeper must not leave orphan rows behind.
    #[test]
    fn delegation_state_is_cascaded_away_with_its_message() {
        let (db, id) = db_with_one_message();
        db.upsert_delegated_send(&id, DelegationState::Pending, None, 10)
            .unwrap();
        db.conn()
            .unwrap()
            .execute("DELETE FROM messages WHERE message_id = ?1", [&id])
            .unwrap();
        assert!(db.get_delegated_send(&id).unwrap().is_none());
    }
}
