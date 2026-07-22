//! Metadata for content-addressed file attachments. Chunk bytes themselves
//! live in `bh-files`' own store, not here — this table just tracks what's
//! known about a file and how much of it has been downloaded.

use rusqlite::params;

use crate::{
    models::{AttachmentKind, DownloadState, FileMeta},
    Database, StorageError,
};

fn state_from_str(s: &str) -> DownloadState {
    match s {
        "partial" => DownloadState::Partial,
        "complete" => DownloadState::Complete,
        _ => DownloadState::Pending,
    }
}

fn row_to_file(row: &rusqlite::Row) -> rusqlite::Result<FileMeta> {
    let state: String = row.get(7)?;
    let kind: String = row.get(10)?;
    Ok(FileMeta {
        content_hash: row.get(0)?,
        message_id: row.get(1)?,
        file_name: row.get(2)?,
        mime_type: row.get(3)?,
        size_bytes: row.get(4)?,
        chunk_count: row.get(5)?,
        local_path: row.get(6)?,
        download_state: state_from_str(&state),
        file_key: row.get(8)?,
        manifest_json: row.get(9)?,
        attachment_kind: AttachmentKind::from_db_str(&kind),
        duration_secs: row.get(11)?,
    })
}

const SELECT_COLUMNS: &str = "content_hash, message_id, file_name, mime_type, size_bytes, chunk_count, local_path, download_state, file_key, manifest_json, attachment_kind, duration_secs";

impl Database {
    pub fn upsert_file_meta(&self, file: &FileMeta) -> Result<(), StorageError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO files (content_hash, message_id, file_name, mime_type, size_bytes, chunk_count, local_path, download_state, file_key, manifest_json, attachment_kind, duration_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(content_hash) DO UPDATE SET
                local_path = excluded.local_path,
                download_state = excluded.download_state",
            params![
                file.content_hash,
                file.message_id,
                file.file_name,
                file.mime_type,
                file.size_bytes,
                file.chunk_count,
                file.local_path,
                file.download_state.as_str(),
                file.file_key,
                file.manifest_json,
                file.attachment_kind.as_str(),
                file.duration_secs,
            ],
        )?;
        // Record this message<->content association separately from the
        // content-keyed `files` row above — the same content_hash can be
        // attached to more than one message (see `message_attachments`'
        // doc comment in schema.rs), so a second attach must not erase the
        // first message's association.
        if let Some(message_id) = &file.message_id {
            conn.execute(
                "INSERT OR IGNORE INTO message_attachments (message_id, content_hash) VALUES (?1, ?2)",
                params![message_id, file.content_hash],
            )?;
        }
        Ok(())
    }

    pub fn get_file_meta(&self, content_hash: &str) -> Result<Option<FileMeta>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM files WHERE content_hash = ?1");
        conn.query_row(&sql, params![content_hash], row_to_file)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn set_download_state(
        &self,
        content_hash: &str,
        state: DownloadState,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE files SET download_state = ?1 WHERE content_hash = ?2",
            params![state.as_str(), content_hash],
        )?;
        Ok(())
    }

    /// All attachments for a conversation, joined through
    /// `message_attachments` (not `files.message_id` directly — a single
    /// file can be attached to messages in more than one conversation, so
    /// the per-conversation `message_id` must come from the join row, not
    /// from the content-keyed `files` row).
    pub fn list_files_for_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<FileMeta>, StorageError> {
        let conn = self.conn()?;
        let sql = "SELECT f.content_hash, ma.message_id, f.file_name, f.mime_type, f.size_bytes, f.chunk_count, f.local_path, f.download_state, f.file_key, f.manifest_json, f.attachment_kind, f.duration_secs
             FROM files f
             JOIN message_attachments ma ON ma.content_hash = f.content_hash
             JOIN messages m ON ma.message_id = m.message_id
             WHERE m.conversation_id = ?1
             ORDER BY m.sent_at";
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map(params![conversation_id], row_to_file)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn delete_file_meta(&self, content_hash: &str) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM files WHERE content_hash = ?1",
            params![content_hash],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Contact, Message};

    fn seed_message(db: &Database) {
        db.upsert_contact(&Contact {
            contact_id: "c1".into(),
            identity_public_key: vec![1],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
        db.create_direct_conversation("conv1", "c1", 0).unwrap();
        db.insert_message(&Message {
            message_id: "m1".into(),
            conversation_id: "conv1".into(),
            sender_contact_id: None,
            body: Some("attachment".into()),
            sent_at: 0,
            received_at: None,
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();
    }

    fn sample_file() -> FileMeta {
        FileMeta {
            content_hash: "abc123".into(),
            message_id: Some("m1".into()),
            file_name: Some("photo.jpg".into()),
            mime_type: Some("image/jpeg".into()),
            size_bytes: 1234,
            chunk_count: 1,
            local_path: None,
            download_state: DownloadState::Complete,
            file_key: vec![9u8; 32],
            manifest_json: r#"{"total_size":1234,"chunks":[]}"#.into(),
            attachment_kind: AttachmentKind::File,
            duration_secs: None,
        }
    }

    #[test]
    fn upsert_and_get_round_trips_the_new_columns() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);
        db.upsert_file_meta(&sample_file()).unwrap();

        let loaded = db.get_file_meta("abc123").unwrap().unwrap();
        assert_eq!(loaded.file_key, vec![9u8; 32]);
        assert_eq!(loaded.manifest_json, r#"{"total_size":1234,"chunks":[]}"#);
    }

    #[test]
    fn list_files_for_conversation_joins_through_message_id() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);
        db.upsert_file_meta(&sample_file()).unwrap();

        let files = db.list_files_for_conversation("conv1").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].content_hash, "abc123");
        assert!(db
            .list_files_for_conversation("nonexistent")
            .unwrap()
            .is_empty());
    }

    /// Regression test: attaching the same content (same `content_hash`)
    /// to a second message in a second conversation used to silently
    /// reassign `files.message_id`, making the attachment vanish from the
    /// first conversation's list.
    #[test]
    fn the_same_content_hash_attached_to_two_conversations_stays_listed_in_both() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);
        db.upsert_contact(&Contact {
            contact_id: "c2".into(),
            identity_public_key: vec![2],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
        db.create_direct_conversation("conv2", "c2", 0).unwrap();
        db.insert_message(&Message {
            message_id: "m2".into(),
            conversation_id: "conv2".into(),
            sender_contact_id: None,
            body: Some("attachment".into()),
            sent_at: 0,
            received_at: None,
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();

        db.upsert_file_meta(&sample_file()).unwrap();
        let mut second_attach = sample_file();
        second_attach.message_id = Some("m2".into());
        db.upsert_file_meta(&second_attach).unwrap();

        let conv1_files = db.list_files_for_conversation("conv1").unwrap();
        assert_eq!(conv1_files.len(), 1);
        assert_eq!(conv1_files[0].message_id.as_deref(), Some("m1"));

        let conv2_files = db.list_files_for_conversation("conv2").unwrap();
        assert_eq!(conv2_files.len(), 1);
        assert_eq!(conv2_files[0].message_id.as_deref(), Some("m2"));
    }

    #[test]
    fn delete_file_meta_removes_the_row() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);
        db.upsert_file_meta(&sample_file()).unwrap();
        db.delete_file_meta("abc123").unwrap();
        assert!(db.get_file_meta("abc123").unwrap().is_none());
    }
}
