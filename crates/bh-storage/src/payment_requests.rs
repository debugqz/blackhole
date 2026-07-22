//! In-chat crypto payment requests. One row per message, mirroring the
//! `files` table's "sibling table keyed by `message_id`" shape rather than
//! adding a polymorphic `kind` column to `messages` — see `schema.rs`'s v3
//! comment. `paid_at` is only ever written by an explicit local action;
//! nothing here ever consults a blockchain (SPEC.md §12 isolation, kept by
//! this feature simply never touching payment infrastructure).

use rusqlite::params;

use crate::{
    models::{PaymentAsset, PaymentRequest},
    Database, StorageError,
};

fn row_to_payment_request(row: &rusqlite::Row) -> rusqlite::Result<PaymentRequest> {
    let asset: String = row.get(1)?;
    Ok(PaymentRequest {
        message_id: row.get(0)?,
        asset: PaymentAsset::from_db_str(&asset),
        address: row.get(2)?,
        amount: row.get(3)?,
        memo: row.get(4)?,
        paid_at: row.get(5)?,
    })
}

const SELECT_COLUMNS: &str = "message_id, asset, address, amount, memo, paid_at";

impl Database {
    pub fn insert_payment_request(&self, req: &PaymentRequest) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO payment_requests (message_id, asset, address, amount, memo, paid_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                req.message_id,
                req.asset.as_str(),
                req.address,
                req.amount,
                req.memo,
                req.paid_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_payment_request(
        &self,
        message_id: &str,
    ) -> Result<Option<PaymentRequest>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM payment_requests WHERE message_id = ?1");
        conn.query_row(&sql, params![message_id], row_to_payment_request)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// `paid_at = None` clears a mistaken "mark as paid" — there's no
    /// on-chain check backing this either way, so undoing it is just as
    /// legitimate a local action as setting it.
    pub fn set_payment_request_paid(
        &self,
        message_id: &str,
        paid_at: Option<i64>,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE payment_requests SET paid_at = ?1 WHERE message_id = ?2",
            params![paid_at, message_id],
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
            body: None,
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
    fn insert_get_and_mark_paid_roundtrip() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);

        db.insert_payment_request(&PaymentRequest {
            message_id: "m1".into(),
            asset: PaymentAsset::Xmr,
            address: "some-address".into(),
            amount: Some("1.5".into()),
            memo: Some("dinner".into()),
            paid_at: None,
        })
        .unwrap();

        let fetched = db.get_payment_request("m1").unwrap().unwrap();
        assert_eq!(fetched.asset, PaymentAsset::Xmr);
        assert_eq!(fetched.paid_at, None);

        db.set_payment_request_paid("m1", Some(42)).unwrap();
        let fetched = db.get_payment_request("m1").unwrap().unwrap();
        assert_eq!(fetched.paid_at, Some(42));

        db.set_payment_request_paid("m1", None).unwrap();
        let fetched = db.get_payment_request("m1").unwrap().unwrap();
        assert_eq!(fetched.paid_at, None);
    }

    #[test]
    fn missing_payment_request_is_none() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);
        assert!(db.get_payment_request("m1").unwrap().is_none());
    }
}
