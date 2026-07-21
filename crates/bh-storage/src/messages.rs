use rusqlite::params;

use crate::{models::Message, Database, StorageError};

fn row_to_message(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    Ok(Message {
        message_id: row.get(0)?,
        conversation_id: row.get(1)?,
        sender_contact_id: row.get(2)?,
        body: row.get(3)?,
        sent_at: row.get(4)?,
        received_at: row.get(5)?,
        expires_at: row.get(6)?,
        deleted_at: row.get(7)?,
        reply_to_message_id: row.get(8)?,
    })
}

const SELECT_COLUMNS: &str = "message_id, conversation_id, sender_contact_id, body, sent_at, \
    received_at, expires_at, deleted_at, reply_to_message_id";

impl Database {
    pub fn insert_message(&self, message: &Message) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO messages
                (message_id, conversation_id, sender_contact_id, body, sent_at, received_at, expires_at, deleted_at, reply_to_message_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                message.message_id,
                message.conversation_id,
                message.sender_contact_id,
                message.body,
                message.sent_at,
                message.received_at,
                message.expires_at,
                message.deleted_at,
                message.reply_to_message_id,
            ],
        )?;
        Ok(())
    }

    pub fn get_message(&self, message_id: &str) -> Result<Option<Message>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM messages WHERE message_id = ?1");
        conn.query_row(&sql, params![message_id], row_to_message)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn list_messages(
        &self,
        conversation_id: &str,
        limit: i64,
    ) -> Result<Vec<Message>, StorageError> {
        let conn = self.conn()?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM messages
             WHERE conversation_id = ?1 AND deleted_at IS NULL
             ORDER BY sent_at DESC LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![conversation_id, limit], row_to_message)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Fetches exactly the messages named by `message_ids` — used for
    /// voluntary abuse reports (SPEC.md §8): the reporting user picks
    /// specific messages, never a bulk export of a whole conversation.
    pub fn get_messages_by_ids(
        &self,
        message_ids: &[String],
    ) -> Result<Vec<Message>, StorageError> {
        if message_ids.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn()?;
        let placeholders = message_ids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM messages WHERE message_id IN ({placeholders})");
        let mut stmt = conn.prepare(&sql)?;
        let params = rusqlite::params_from_iter(message_ids.iter());
        let rows = stmt.query_map(params, row_to_message)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn mark_message_deleted(
        &self,
        message_id: &str,
        deleted_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE messages SET deleted_at = ?1, body = NULL WHERE message_id = ?2",
            params![deleted_at, message_id],
        )?;
        Ok(())
    }

    /// Sweeps self-destructing messages whose `expires_at` has passed
    /// (SPEC.md §7). Returns the ids that were purged.
    pub fn purge_expired_messages(&self, now: i64) -> Result<Vec<String>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT message_id FROM messages
             WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND deleted_at IS NULL",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![now], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        for id in &ids {
            conn.execute(
                "UPDATE messages SET deleted_at = ?1, body = NULL WHERE message_id = ?2",
                params![now, id],
            )?;
        }
        Ok(ids)
    }
}
