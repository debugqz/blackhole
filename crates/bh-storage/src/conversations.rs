use rusqlite::params;

use crate::{
    models::{Conversation, ConversationKind},
    Database, StorageError,
};

fn kind_from_str(s: &str) -> ConversationKind {
    match s {
        "group" => ConversationKind::Group,
        _ => ConversationKind::Direct,
    }
}

fn row_to_conversation(row: &rusqlite::Row) -> rusqlite::Result<Conversation> {
    let kind: String = row.get(1)?;
    Ok(Conversation {
        conversation_id: row.get(0)?,
        kind: kind_from_str(&kind),
        contact_id: row.get(2)?,
        group_id: row.get(3)?,
        created_at: row.get(4)?,
    })
}

const SELECT_COLUMNS: &str = "conversation_id, kind, contact_id, group_id, created_at";

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
}
