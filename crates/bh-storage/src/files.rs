//! Metadata for content-addressed file attachments. Chunk bytes themselves
//! live in `bh-files`' own store, not here — this table just tracks what's
//! known about a file and how much of it has been downloaded.

use rusqlite::params;

use crate::{
    models::{DownloadState, FileMeta},
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
    Ok(FileMeta {
        content_hash: row.get(0)?,
        message_id: row.get(1)?,
        file_name: row.get(2)?,
        mime_type: row.get(3)?,
        size_bytes: row.get(4)?,
        chunk_count: row.get(5)?,
        local_path: row.get(6)?,
        download_state: state_from_str(&state),
    })
}

const SELECT_COLUMNS: &str =
    "content_hash, message_id, file_name, mime_type, size_bytes, chunk_count, local_path, download_state";

impl Database {
    pub fn upsert_file_meta(&self, file: &FileMeta) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO files (content_hash, message_id, file_name, mime_type, size_bytes, chunk_count, local_path, download_state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
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
            ],
        )?;
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
}
