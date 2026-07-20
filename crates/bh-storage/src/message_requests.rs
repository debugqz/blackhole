//! "Message request" inbox for unsolicited contact — SPEC.md §8: new
//! contacts default to a request, not the main chat list, until accepted.

use rusqlite::params;

use crate::{
    models::{MessageRequest, MessageRequestStatus},
    Database, StorageError,
};

fn status_from_str(s: &str) -> MessageRequestStatus {
    match s {
        "accepted" => MessageRequestStatus::Accepted,
        "declined" => MessageRequestStatus::Declined,
        _ => MessageRequestStatus::Pending,
    }
}

impl Database {
    pub fn create_message_request(
        &self,
        contact_id: &str,
        received_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO message_requests (contact_id, received_at, status)
             VALUES (?1, ?2, 'pending')
             ON CONFLICT(contact_id) DO NOTHING",
            params![contact_id, received_at],
        )?;
        Ok(())
    }

    pub fn list_pending_message_requests(&self) -> Result<Vec<MessageRequest>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT contact_id, received_at, status FROM message_requests
             WHERE status = 'pending' ORDER BY received_at",
        )?;
        let rows = stmt.query_map([], |row| {
            let status: String = row.get(2)?;
            Ok(MessageRequest {
                contact_id: row.get(0)?,
                received_at: row.get(1)?,
                status: status_from_str(&status),
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn set_message_request_status(
        &self,
        contact_id: &str,
        status: MessageRequestStatus,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE message_requests SET status = ?1 WHERE contact_id = ?2",
            params![status.as_str(), contact_id],
        )?;
        Ok(())
    }
}
