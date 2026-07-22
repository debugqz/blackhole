//! Which sticker (from which purchased pack) a message carries, if any
//! (SPEC.md §12/§15). One row per message, mirroring `payment_requests`'
//! "sibling table keyed by `message_id`" shape rather than a polymorphic
//! `kind` column on `messages` — see `schema.rs`'s v3/v7 comments.
//!
//! This module only ever records *what was sent*. It never checks or
//! grants ownership — that happens once, before the message (and this
//! row) is created, in `crates/bh-api/src/stickers.rs` via
//! `Database::is_cosmetic_owned` (see `cosmetics.rs`). Keeping that check
//! out of this module is deliberate: it means nothing here needs to know
//! about the payments database at all, which is what keeps this feature on
//! the correct side of CLAUDE.md's payments/messaging isolation rule.

use rusqlite::params;

use crate::{models::MessageSticker, Database, StorageError};

fn row_to_message_sticker(row: &rusqlite::Row) -> rusqlite::Result<MessageSticker> {
    Ok(MessageSticker {
        message_id: row.get(0)?,
        pack_item_id: row.get(1)?,
        sticker_id: row.get(2)?,
    })
}

const SELECT_COLUMNS: &str = "message_id, pack_item_id, sticker_id";

impl Database {
    pub fn insert_message_sticker(&self, sticker: &MessageSticker) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO message_stickers (message_id, pack_item_id, sticker_id)
             VALUES (?1, ?2, ?3)",
            params![sticker.message_id, sticker.pack_item_id, sticker.sticker_id],
        )?;
        Ok(())
    }

    pub fn get_message_sticker(
        &self,
        message_id: &str,
    ) -> Result<Option<MessageSticker>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM message_stickers WHERE message_id = ?1");
        conn.query_row(&sql, params![message_id], row_to_message_sticker)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
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
    fn insert_and_get_roundtrip() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);

        db.insert_message_sticker(&MessageSticker {
            message_id: "m1".into(),
            pack_item_id: "sticker-pack-nebula".into(),
            sticker_id: "nebula-wave".into(),
        })
        .unwrap();

        let fetched = db.get_message_sticker("m1").unwrap().unwrap();
        assert_eq!(fetched.pack_item_id, "sticker-pack-nebula");
        assert_eq!(fetched.sticker_id, "nebula-wave");
    }

    #[test]
    fn missing_message_sticker_is_none() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);
        assert!(db.get_message_sticker("m1").unwrap().is_none());
    }
}
