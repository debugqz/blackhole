use rusqlite::params;

use crate::{models::Contact, Database, StorageError};

fn row_to_contact(row: &rusqlite::Row) -> rusqlite::Result<Contact> {
    Ok(Contact {
        contact_id: row.get(0)?,
        identity_public_key: row.get(1)?,
        display_name: row.get(2)?,
        verified: row.get::<_, i64>(3)? != 0,
        blocked: row.get::<_, i64>(4)? != 0,
        added_at: row.get(5)?,
    })
}

const SELECT_COLUMNS: &str =
    "contact_id, identity_public_key, display_name, verified, blocked, added_at";

impl Database {
    pub fn upsert_contact(&self, contact: &Contact) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO contacts (contact_id, identity_public_key, display_name, verified, blocked, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(contact_id) DO UPDATE SET
                identity_public_key = excluded.identity_public_key,
                display_name = excluded.display_name",
            params![
                contact.contact_id,
                contact.identity_public_key,
                contact.display_name,
                contact.verified as i64,
                contact.blocked as i64,
                contact.added_at
            ],
        )?;
        Ok(())
    }

    pub fn get_contact(&self, contact_id: &str) -> Result<Option<Contact>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM contacts WHERE contact_id = ?1");
        conn.query_row(&sql, params![contact_id], row_to_contact)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM contacts ORDER BY added_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_contact)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn set_contact_blocked(&self, contact_id: &str, blocked: bool) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE contacts SET blocked = ?1 WHERE contact_id = ?2",
            params![blocked as i64, contact_id],
        )?;
        Ok(())
    }

    pub fn set_contact_verified(
        &self,
        contact_id: &str,
        verified: bool,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE contacts SET verified = ?1 WHERE contact_id = ?2",
            params![verified as i64, contact_id],
        )?;
        Ok(())
    }

    /// How many non-deleted messages this profile has exchanged with each
    /// contact over a `Direct` conversation — one signal feeding
    /// `bh-api::contacts`'s local trust-level heuristic (see that module's
    /// `compute_trust_level`). A single aggregate query rather than one
    /// call per contact.
    pub fn message_counts_by_contact(
        &self,
    ) -> Result<std::collections::HashMap<String, i64>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT c.contact_id, COUNT(m.message_id) FROM conversations c
             LEFT JOIN messages m ON m.conversation_id = c.conversation_id AND m.deleted_at IS NULL
             WHERE c.kind = 'direct' AND c.contact_id IS NOT NULL
             GROUP BY c.contact_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Message;

    fn contact(id: &str) -> Contact {
        Contact {
            contact_id: id.to_string(),
            identity_public_key: vec![1; 64],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        }
    }

    fn message(id: &str, conversation_id: &str, deleted: bool) -> Message {
        Message {
            message_id: id.to_string(),
            conversation_id: conversation_id.to_string(),
            sender_contact_id: None,
            body: Some("hi".into()),
            sent_at: 0,
            received_at: None,
            expires_at: None,
            deleted_at: if deleted { Some(1) } else { None },
            reply_to_message_id: None,
            edited_at: None,
        }
    }

    #[test]
    fn message_counts_are_zero_with_no_messages() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_contact(&contact("c1")).unwrap();
        db.create_direct_conversation("conv1", "c1", 0).unwrap();

        let counts = db.message_counts_by_contact().unwrap();
        assert_eq!(counts.get("c1").copied().unwrap_or(0), 0);
    }

    #[test]
    fn message_counts_exclude_deleted_and_other_conversation_kinds() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_contact(&contact("c1")).unwrap();
        db.create_direct_conversation("conv1", "c1", 0).unwrap();
        db.insert_message(&message("m1", "conv1", false)).unwrap();
        db.insert_message(&message("m2", "conv1", false)).unwrap();
        db.insert_message(&message("m3", "conv1", true)).unwrap(); // deleted, not counted
        db.ensure_self_conversation(0).unwrap();
        db.insert_message(&message("m4", "self-notes", false))
            .unwrap(); // SelfNotes, not a contact's Direct conversation

        let counts = db.message_counts_by_contact().unwrap();
        assert_eq!(counts.get("c1").copied().unwrap(), 2);
        assert!(!counts.contains_key("self-notes"));
    }
}
