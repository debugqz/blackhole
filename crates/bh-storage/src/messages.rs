use rusqlite::{params, Connection};

use crate::{
    models::{Message, MessageEdit},
    Database, StorageError,
};

/// `files`/`payment_requests` declare `ON DELETE CASCADE` against
/// `messages`, but messages are soft-deleted (`UPDATE ... deleted_at`) to
/// preserve quote-reply/thread structure, so that cascade never actually
/// fires. Delete the sensitive sibling rows explicitly whenever a message
/// is deleted/expires, so a "self-destructed" message doesn't leave its
/// file key material or payment address/amount/memo behind.
///
/// A file's `content_hash` can be attached to more than one message (see
/// `message_attachments` in schema.rs), so deleting this message's
/// attachment link must not blow away a file another still-live message
/// depends on — the underlying `files` row (and its key material) is only
/// dropped once no `message_attachments` row references it anymore.
///
/// Returns the `content_hash`es actually dropped from `files` (i.e. no
/// longer referenced by any live message's `message_attachments` row) — the
/// caller needs these to also remove the corresponding chunk directory from
/// disk (`data_dir/files/<content_hash>/`), which `bh-storage` itself has no
/// concept of; see `bh-api`'s `restart_expiry_sweeper`/`chunk_dir`.
fn delete_dependent_rows(conn: &Connection, message_id: &str) -> Result<Vec<String>, StorageError> {
    conn.execute(
        "DELETE FROM payment_requests WHERE message_id = ?1",
        params![message_id],
    )?;
    conn.execute(
        "DELETE FROM message_stickers WHERE message_id = ?1",
        params![message_id],
    )?;

    let mut stmt =
        conn.prepare("SELECT content_hash FROM message_attachments WHERE message_id = ?1")?;
    let content_hashes: Vec<String> = stmt
        .query_map(params![message_id], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    conn.execute(
        "DELETE FROM message_attachments WHERE message_id = ?1",
        params![message_id],
    )?;
    let mut orphaned_content_hashes = Vec::new();
    for content_hash in content_hashes {
        let still_referenced: i64 = conn.query_row(
            "SELECT COUNT(*) FROM message_attachments WHERE content_hash = ?1",
            params![content_hash],
            |row| row.get(0),
        )?;
        if still_referenced == 0 {
            conn.execute(
                "DELETE FROM files WHERE content_hash = ?1",
                params![content_hash],
            )?;
            orphaned_content_hashes.push(content_hash);
        }
    }
    Ok(orphaned_content_hashes)
}

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
        edited_at: row.get(9)?,
    })
}

fn row_to_message_edit(row: &rusqlite::Row) -> rusqlite::Result<MessageEdit> {
    Ok(MessageEdit {
        id: row.get(0)?,
        message_id: row.get(1)?,
        body: row.get(2)?,
        edited_at: row.get(3)?,
    })
}

const SELECT_COLUMNS: &str = "message_id, conversation_id, sender_contact_id, body, sent_at, \
    received_at, expires_at, deleted_at, reply_to_message_id, edited_at";

impl Database {
    pub fn insert_message(&self, message: &Message) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO messages
                (message_id, conversation_id, sender_contact_id, body, sent_at, received_at, expires_at, deleted_at, reply_to_message_id, edited_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
                message.edited_at,
            ],
        )?;
        Ok(())
    }

    /// Archives the current body into `message_edits` (tagged with when
    /// that version became current — the *previous* `edited_at`, or
    /// `sent_at` if this is the first edit) before overwriting the live
    /// row, so editing is never a silent overwrite. Returns `Ok(None)` if
    /// the message doesn't exist or was already deleted (there is nothing
    /// sensible to "edit" once `body` has been wiped by a delete/expiry).
    pub fn edit_message(
        &self,
        message_id: &str,
        new_body: &str,
        edited_at: i64,
    ) -> Result<Option<Message>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM messages WHERE message_id = ?1");
        let current: Option<Message> =
            match conn.query_row(&sql, params![message_id], row_to_message) {
                Ok(message) => Some(message),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(other) => return Err(other.into()),
            };
        let Some(current) = current else {
            return Ok(None);
        };
        if current.deleted_at.is_some() {
            return Ok(None);
        }
        conn.execute(
            "INSERT INTO message_edits (message_id, body, edited_at) VALUES (?1, ?2, ?3)",
            params![
                message_id,
                current.body,
                current.edited_at.unwrap_or(current.sent_at)
            ],
        )?;
        conn.execute(
            "UPDATE messages SET body = ?1, edited_at = ?2 WHERE message_id = ?3",
            params![new_body, edited_at, message_id],
        )?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM messages WHERE message_id = ?1");
        conn.query_row(&sql, params![message_id], row_to_message)
            .map(Some)
            .map_err(Into::into)
    }

    /// Every prior version of a message's body, oldest first.
    pub fn list_message_edits(&self, message_id: &str) -> Result<Vec<MessageEdit>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, message_id, body, edited_at FROM message_edits
             WHERE message_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![message_id], row_to_message_edit)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
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

    /// Messages across every conversation sent strictly after
    /// `(after_sent_at, after_message_id)` in `(sent_at, message_id)`
    /// order — the feed `crates/bh-api/src/device_sync.rs` pulls from for
    /// a linked device's delivery cursor. Deliberately *not* filtered by
    /// `deleted_at IS NULL` like `list_messages`: a self-destructed
    /// message (body already wiped to `NULL`) must still advance the
    /// cursor past it, or a device that syncs after a message expires
    /// would stall retrying the same already-gone message forever.
    pub fn list_messages_since(
        &self,
        after_sent_at: i64,
        after_message_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Message>, StorageError> {
        let conn = self.conn()?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM messages
             WHERE sent_at > ?1 OR (sent_at = ?1 AND message_id > ?2)
             ORDER BY sent_at, message_id LIMIT ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![after_sent_at, after_message_id.unwrap_or(""), limit],
            row_to_message,
        )?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Returns the `content_hash`es orphaned (dropped from `files`) by this
    /// deletion — see `delete_dependent_rows`.
    pub fn mark_message_deleted(
        &self,
        message_id: &str,
        deleted_at: i64,
    ) -> Result<Vec<String>, StorageError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE messages SET deleted_at = ?1, body = NULL WHERE message_id = ?2",
            params![deleted_at, message_id],
        )?;
        delete_dependent_rows(&conn, message_id)
    }

    /// Sweeps self-destructing messages whose `expires_at` has passed
    /// (SPEC.md §7). Returns the purged message ids plus the union of
    /// `content_hash`es orphaned across the whole batch, so the caller
    /// (`bh-api`'s `restart_expiry_sweeper`) can also delete the
    /// corresponding chunk directories from disk — `bh-storage` only owns
    /// the database side of this cleanup.
    pub fn purge_expired_messages(&self, now: i64) -> Result<ExpirySweepResult, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT message_id FROM messages
             WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND deleted_at IS NULL",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![now], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        drop(stmt);
        let mut orphaned_content_hashes = Vec::new();
        for id in &ids {
            conn.execute(
                "UPDATE messages SET deleted_at = ?1, body = NULL WHERE message_id = ?2",
                params![now, id],
            )?;
            orphaned_content_hashes.extend(delete_dependent_rows(&conn, id)?);
        }
        Ok(ExpirySweepResult {
            message_ids: ids,
            orphaned_content_hashes,
        })
    }
}

/// Result of a single expiry sweep pass. See `purge_expired_messages`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpirySweepResult {
    pub message_ids: Vec<String>,
    pub orphaned_content_hashes: Vec<String>,
}
