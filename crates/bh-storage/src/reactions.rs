//! Emoji reactions on messages. Stored as `(message_id, contact_id, emoji)`
//! rows rather than a single column on `messages` so the same message can
//! carry reactions from multiple group members without a schema change per
//! reactor (SPEC.md §5.4 groups at scale).

use rusqlite::params;

use crate::{models::Reaction, Database, StorageError};

fn row_to_reaction(row: &rusqlite::Row) -> rusqlite::Result<Reaction> {
    Ok(Reaction {
        message_id: row.get(0)?,
        contact_id: row.get(1)?,
        emoji: row.get(2)?,
        reacted_at: row.get(3)?,
    })
}

const SELECT_COLUMNS: &str = "message_id, contact_id, emoji, reacted_at";

impl Database {
    /// Idempotent: reacting with the same emoji twice just refreshes the
    /// timestamp, it doesn't create a duplicate.
    ///
    /// This can't be a plain `INSERT ... ON CONFLICT` on the
    /// `(message_id, contact_id, emoji)` primary key: SQL treats every
    /// `NULL` as distinct from every other `NULL` for uniqueness purposes,
    /// so two "self" reactions (`contact_id = NULL`) would never be seen as
    /// conflicting. `IS` (NULL-safe equality) in a manual check-then-write
    /// sidesteps that.
    pub fn add_reaction(&self, reaction: &Reaction) -> Result<(), StorageError> {
        let conn = self.conn()?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM reactions
                WHERE message_id = ?1 AND contact_id IS ?2 AND emoji = ?3)",
            params![reaction.message_id, reaction.contact_id, reaction.emoji],
            |row| row.get(0),
        )?;
        if exists {
            conn.execute(
                "UPDATE reactions SET reacted_at = ?1
                 WHERE message_id = ?2 AND contact_id IS ?3 AND emoji = ?4",
                params![
                    reaction.reacted_at,
                    reaction.message_id,
                    reaction.contact_id,
                    reaction.emoji,
                ],
            )?;
        } else {
            conn.execute(
                "INSERT INTO reactions (message_id, contact_id, emoji, reacted_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    reaction.message_id,
                    reaction.contact_id,
                    reaction.emoji,
                    reaction.reacted_at,
                ],
            )?;
        }
        Ok(())
    }

    pub fn remove_reaction(
        &self,
        message_id: &str,
        contact_id: Option<&str>,
        emoji: &str,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM reactions WHERE message_id = ?1 AND contact_id IS ?2 AND emoji = ?3",
            params![message_id, contact_id, emoji],
        )?;
        Ok(())
    }

    pub fn list_reactions(&self, message_id: &str) -> Result<Vec<Reaction>, StorageError> {
        let conn = self.conn()?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM reactions WHERE message_id = ?1 ORDER BY reacted_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![message_id], row_to_reaction)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
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
    fn add_list_and_remove_reactions() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);

        db.add_reaction(&Reaction {
            message_id: "m1".into(),
            contact_id: None,
            emoji: "\u{1F44D}".into(),
            reacted_at: 1,
        })
        .unwrap();
        db.add_reaction(&Reaction {
            message_id: "m1".into(),
            contact_id: Some("c1".into()),
            emoji: "\u{2764}\u{FE0F}".into(),
            reacted_at: 2,
        })
        .unwrap();

        let reactions = db.list_reactions("m1").unwrap();
        assert_eq!(reactions.len(), 2);

        db.remove_reaction("m1", None, "\u{1F44D}").unwrap();
        let reactions = db.list_reactions("m1").unwrap();
        assert_eq!(reactions.len(), 1);
        assert_eq!(reactions[0].contact_id, Some("c1".into()));
    }

    #[test]
    fn reacting_twice_with_same_emoji_does_not_duplicate() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        seed_message(&db);

        for t in [1, 2] {
            db.add_reaction(&Reaction {
                message_id: "m1".into(),
                contact_id: None,
                emoji: "\u{1F44D}".into(),
                reacted_at: t,
            })
            .unwrap();
        }

        let reactions = db.list_reactions("m1").unwrap();
        assert_eq!(reactions.len(), 1);
        assert_eq!(reactions[0].reacted_at, 2);
    }
}
