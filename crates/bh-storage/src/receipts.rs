//! Per-recipient delivery/read receipts. This table only ever stores
//! status for messages the *local user* sent — it's populated by decrypting
//! an incoming receipt envelope (`bh-crypto::envelope::Envelope::Receipt`)
//! addressed to us, so the data here already passed through the same
//! Double Ratchet/MLS session as the message content itself. Nothing about
//! a receipt is ever visible to the network layer in plaintext (SPEC.md
//! §2.3) — see `docs/THREAT_MODEL.md` for the receipts entry.

use rusqlite::params;

use crate::{
    models::{MessageReceipt, ReceiptStatus},
    Database, StorageError,
};

fn row_to_receipt(row: &rusqlite::Row) -> rusqlite::Result<MessageReceipt> {
    let status: String = row.get(2)?;
    Ok(MessageReceipt {
        message_id: row.get(0)?,
        contact_id: row.get(1)?,
        status: ReceiptStatus::from_db_str(&status),
        updated_at: row.get(3)?,
    })
}

const SELECT_COLUMNS: &str = "message_id, contact_id, status, updated_at";

impl Database {
    /// Records that `contact_id` has delivered/read `message_id`. A later
    /// `Read` overwrites an earlier `Delivered` for the same pair, but not
    /// vice versa — receipts only move forward (delivered -> read), since
    /// out-of-order network delivery shouldn't be able to downgrade one.
    pub fn upsert_receipt(&self, receipt: &MessageReceipt) -> Result<(), StorageError> {
        let conn = self.conn()?;
        if receipt.status == ReceiptStatus::Delivered {
            let existing: Option<String> = conn
                .query_row(
                    "SELECT status FROM message_receipts WHERE message_id = ?1 AND contact_id = ?2",
                    params![receipt.message_id, receipt.contact_id],
                    |row| row.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })?;
            if existing.as_deref() == Some(ReceiptStatus::Read.as_str()) {
                return Ok(());
            }
        }
        conn.execute(
            "INSERT INTO message_receipts (message_id, contact_id, status, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(message_id, contact_id) DO UPDATE SET
                status = excluded.status, updated_at = excluded.updated_at",
            params![
                receipt.message_id,
                receipt.contact_id,
                receipt.status.as_str(),
                receipt.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn list_receipts_for_message(
        &self,
        message_id: &str,
    ) -> Result<Vec<MessageReceipt>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM message_receipts WHERE message_id = ?1");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![message_id], row_to_receipt)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Contact, Message};

    fn seed(db: &Database) {
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
            body: Some("hi".into()),
            sent_at: 0,
            received_at: None,
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();
    }

    #[test]
    fn receipt_roundtrip_and_upgrade() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed(&db);

        db.upsert_receipt(&MessageReceipt {
            message_id: "m1".into(),
            contact_id: "c1".into(),
            status: ReceiptStatus::Delivered,
            updated_at: 1,
        })
        .unwrap();
        let receipts = db.list_receipts_for_message("m1").unwrap();
        assert_eq!(receipts[0].status, ReceiptStatus::Delivered);

        db.upsert_receipt(&MessageReceipt {
            message_id: "m1".into(),
            contact_id: "c1".into(),
            status: ReceiptStatus::Read,
            updated_at: 2,
        })
        .unwrap();
        let receipts = db.list_receipts_for_message("m1").unwrap();
        assert_eq!(receipts[0].status, ReceiptStatus::Read);
    }

    #[test]
    fn a_late_delivered_receipt_cannot_downgrade_a_read_one() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed(&db);

        db.upsert_receipt(&MessageReceipt {
            message_id: "m1".into(),
            contact_id: "c1".into(),
            status: ReceiptStatus::Read,
            updated_at: 5,
        })
        .unwrap();
        db.upsert_receipt(&MessageReceipt {
            message_id: "m1".into(),
            contact_id: "c1".into(),
            status: ReceiptStatus::Delivered,
            updated_at: 6,
        })
        .unwrap();

        let receipts = db.list_receipts_for_message("m1").unwrap();
        assert_eq!(receipts[0].status, ReceiptStatus::Read);
    }
}
