use rusqlite::params;

use crate::{
    models::{Conversation, ConversationKind},
    Database, StorageError,
};

fn kind_from_str(s: &str) -> ConversationKind {
    match s {
        "group" => ConversationKind::Group,
        "self" => ConversationKind::SelfNotes,
        _ => ConversationKind::Direct,
    }
}

/// Fixed conversation id for the singleton local-only "Notes to self"
/// conversation. Using a constant id rather than a random uuid means
/// "exactly one per profile" falls out of the `conversation_id` primary key
/// plus `ON CONFLICT DO NOTHING` in [`Database::ensure_self_conversation`]
/// below, with no extra uniqueness bookkeeping — and since every profile
/// has its own physically separate SQLCipher database file, the same fixed
/// id in two different profiles never collides with anything.
pub const SELF_CONVERSATION_ID: &str = "self-notes";

fn row_to_conversation(row: &rusqlite::Row) -> rusqlite::Result<Conversation> {
    let kind: String = row.get(1)?;
    Ok(Conversation {
        conversation_id: row.get(0)?,
        kind: kind_from_str(&kind),
        contact_id: row.get(2)?,
        group_id: row.get(3)?,
        created_at: row.get(4)?,
        disappearing_timer_secs: row.get(5)?,
    })
}

const SELECT_COLUMNS: &str =
    "conversation_id, kind, contact_id, group_id, created_at, disappearing_timer_secs";

impl Database {
    pub fn create_direct_conversation(
        &self,
        conversation_id: &str,
        contact_id: &str,
        created_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO conversations (conversation_id, kind, contact_id, group_id, created_at)
             VALUES (?1, 'direct', ?2, NULL, ?3)
             ON CONFLICT(conversation_id) DO NOTHING",
            params![conversation_id, contact_id, created_at],
        )?;
        Ok(())
    }

    pub fn create_group_conversation(
        &self,
        conversation_id: &str,
        group_id: &str,
        created_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO conversations (conversation_id, kind, contact_id, group_id, created_at)
             VALUES (?1, 'group', NULL, ?2, ?3)
             ON CONFLICT(conversation_id) DO NOTHING",
            params![conversation_id, group_id, created_at],
        )?;
        Ok(())
    }

    pub fn get_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<Conversation>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM conversations WHERE conversation_id = ?1");
        conn.query_row(&sql, params![conversation_id], row_to_conversation)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn list_conversations(&self) -> Result<Vec<Conversation>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM conversations ORDER BY created_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_conversation)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Sets (or clears, with `None`) the disappearing-messages timer for a
    /// conversation. Only affects messages sent *after* this call — existing
    /// messages keep whatever `expires_at` they already had.
    pub fn set_disappearing_timer(
        &self,
        conversation_id: &str,
        timer_secs: Option<i64>,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE conversations SET disappearing_timer_secs = ?1 WHERE conversation_id = ?2",
            params![timer_secs, conversation_id],
        )?;
        Ok(())
    }

    /// What `expires_at` a message sent right now should get, per the
    /// conversation's current disappearing-messages timer (`None` if the
    /// conversation doesn't exist or the timer is off).
    pub fn compute_message_expiry(
        &self,
        conversation_id: &str,
        sent_at: i64,
    ) -> Result<Option<i64>, StorageError> {
        Ok(self
            .get_conversation(conversation_id)?
            .and_then(|c| c.disappearing_timer_secs)
            .map(|timer| sent_at + timer))
    }

    /// Idempotently ensures this profile's singleton "Notes to self"
    /// conversation exists, creating it on first call and returning the
    /// (possibly pre-existing) row on every call after that. Safe to call
    /// on every `GET /conversations` and again at identity bootstrap —
    /// `ON CONFLICT DO NOTHING` against the fixed [`SELF_CONVERSATION_ID`]
    /// makes repeat calls a no-op rather than an error or a duplicate row.
    pub fn ensure_self_conversation(&self, created_at: i64) -> Result<Conversation, StorageError> {
        self.conn()?.execute(
            "INSERT INTO conversations (conversation_id, kind, contact_id, group_id, created_at)
             VALUES (?1, 'self', NULL, NULL, ?2)
             ON CONFLICT(conversation_id) DO NOTHING",
            params![SELF_CONVERSATION_ID, created_at],
        )?;
        self.get_conversation(SELF_CONVERSATION_ID)?
            .ok_or(StorageError::NotFound)
    }
}
