//! Storage for ephemeral identities (see `bh-api::ephemeral_identity`'s
//! module doc for the full design): a throwaway `IdentityKeyPair`,
//! generated on demand and good for a caller-chosen number of days, meant
//! to be handed out via an invite instead of the profile's real identity.
//!
//! "Revoke" and "expire" are the same operation — [`Database::
//! wipe_ephemeral_identity`] — just triggered at different times (an
//! explicit user action vs. [`spawn_ephemeral_identity_sweeper`] finding it
//! past `expires_at`). Both are a real, irreversible wipe: the identity row
//! itself, its `ON DELETE CASCADE`d conversation and (via that
//! conversation's own cascade) every message in it, and its shadow contact
//! row (not reachable through the cascade chain, so deleted explicitly).

use std::time::Duration;

use rusqlite::params;
use tokio::task::JoinHandle;

use crate::{models::EphemeralIdentity, Database, StorageError};

fn row_to_ephemeral_identity(row: &rusqlite::Row) -> rusqlite::Result<EphemeralIdentity> {
    Ok(EphemeralIdentity {
        id: row.get(0)?,
        label: row.get(1)?,
        identity_public_key: row.get(2)?,
        identity_private_key: row.get(3)?,
        shadow_contact_id: row.get(4)?,
        conversation_id: row.get(5)?,
        created_at: row.get(6)?,
        expires_at: row.get(7)?,
    })
}

const SELECT_COLUMNS: &str = "id, label, identity_public_key, identity_private_key, \
     shadow_contact_id, conversation_id, created_at, expires_at";

impl Database {
    pub fn create_ephemeral_identity(&self, row: &EphemeralIdentity) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO ephemeral_identity
                (id, label, identity_public_key, identity_private_key, shadow_contact_id,
                 conversation_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.id,
                row.label,
                row.identity_public_key,
                row.identity_private_key,
                row.shadow_contact_id,
                row.conversation_id,
                row.created_at,
                row.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_ephemeral_identity(
        &self,
        id: &str,
    ) -> Result<Option<EphemeralIdentity>, StorageError> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM ephemeral_identity WHERE id = ?1");
        self.conn()?
            .query_row(&sql, params![id], row_to_ephemeral_identity)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Every row still in the table is by definition live — a wiped
    /// identity is deleted outright, never soft-deleted — so there's no
    /// status filter to apply here.
    pub fn list_ephemeral_identities(&self) -> Result<Vec<EphemeralIdentity>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM ephemeral_identity ORDER BY created_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_ephemeral_identity)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn list_expired_ephemeral_identity_ids(
        &self,
        now: i64,
    ) -> Result<Vec<String>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id FROM ephemeral_identity WHERE expires_at <= ?1")?;
        let rows = stmt.query_map(params![now], |row| row.get(0))?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Deletes an ephemeral identity, its conversation, every message in
    /// it, and its shadow contact. Returns `false` if `id` doesn't exist
    /// (already wiped, or never existed) rather than erroring — both the
    /// manual revoke endpoint and the sweeper treat that as a no-op
    /// success, not a failure.
    pub fn wipe_ephemeral_identity(&self, id: &str) -> Result<bool, StorageError> {
        let Some(identity) = self.get_ephemeral_identity(id)? else {
            return Ok(false);
        };
        let conn = self.conn()?;
        conn.execute("DELETE FROM ephemeral_identity WHERE id = ?1", params![id])?;
        if let Some(shadow_contact_id) = identity.shadow_contact_id {
            conn.execute(
                "DELETE FROM contacts WHERE contact_id = ?1",
                params![shadow_contact_id],
            )?;
        }
        Ok(true)
    }
}

/// Spawns a background task that wipes any ephemeral identity past its
/// `expires_at` every `interval`. `now` is injected (rather than reading
/// the system clock directly) so callers can test this deterministically —
/// same rationale as `expiry::spawn_expiry_sweeper`.
pub fn spawn_ephemeral_identity_sweeper(
    db: Database,
    interval: Duration,
    now: impl Fn() -> i64 + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate first tick, same as expiry.rs
        loop {
            ticker.tick().await;
            let ids = match db.list_expired_ephemeral_identity_ids(now()) {
                Ok(ids) => ids,
                Err(err) => {
                    tracing::warn!(%err, "ephemeral identity sweep failed to list expired rows");
                    continue;
                }
            };
            for id in ids {
                match db.wipe_ephemeral_identity(&id) {
                    Ok(true) => tracing::debug!(%id, "wiped expired ephemeral identity"),
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!(%err, %id, "failed to wipe expired ephemeral identity")
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Contact;

    fn identity(id: &str, expires_at: i64) -> EphemeralIdentity {
        EphemeralIdentity {
            id: id.to_string(),
            label: Some("Craigslist buyer".into()),
            identity_public_key: vec![1; 64],
            identity_private_key: vec![2; 64],
            shadow_contact_id: None,
            conversation_id: format!("conv-{id}"),
            created_at: 0,
            expires_at,
        }
    }

    #[test]
    fn create_get_list_round_trip() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.create_ephemeral_identity(&identity("e1", 1_000))
            .unwrap();

        let fetched = db.get_ephemeral_identity("e1").unwrap().unwrap();
        assert_eq!(fetched.label.as_deref(), Some("Craigslist buyer"));
        assert_eq!(fetched.expires_at, 1_000);

        assert_eq!(db.list_ephemeral_identities().unwrap().len(), 1);
        assert!(db.get_ephemeral_identity("missing").unwrap().is_none());
    }

    #[test]
    fn wipe_deletes_identity_conversation_messages_and_shadow_contact() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_contact(&Contact {
            contact_id: "shadow1".into(),
            identity_public_key: vec![3; 64],
            display_name: Some("Invite: burner".into()),
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
        let mut row = identity("e1", 1_000);
        row.shadow_contact_id = Some("shadow1".into());
        row.conversation_id = "conv1".into();
        db.create_ephemeral_identity(&row).unwrap();
        db.create_ephemeral_identity_conversation("e1", "conv1", "shadow1", 0)
            .unwrap();
        db.insert_message(&crate::models::Message {
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

        assert!(db.wipe_ephemeral_identity("e1").unwrap());

        assert!(db.get_ephemeral_identity("e1").unwrap().is_none());
        assert!(db.get_conversation("conv1").unwrap().is_none());
        assert!(db.list_messages("conv1", 10).unwrap().is_empty());
        assert!(db.get_contact("shadow1").unwrap().is_none());

        // Wiping again (already gone) is a no-op, not an error.
        assert!(!db.wipe_ephemeral_identity("e1").unwrap());
    }

    #[test]
    fn list_expired_crosses_the_boundary() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.create_ephemeral_identity(&identity("e1", 1_000))
            .unwrap();

        assert!(db
            .list_expired_ephemeral_identity_ids(999)
            .unwrap()
            .is_empty());
        assert_eq!(
            db.list_expired_ephemeral_identity_ids(1_000).unwrap(),
            vec!["e1"]
        );
    }

    #[tokio::test]
    async fn sweeper_wipes_expired_identities_and_leaves_live_ones() {
        use std::sync::atomic::{AtomicI64, Ordering};
        use std::sync::Arc;

        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.create_ephemeral_identity(&identity("expires-soon", 10))
            .unwrap();
        db.create_ephemeral_identity(&identity("expires-later", 10_000))
            .unwrap();

        let clock = Arc::new(AtomicI64::new(0));
        let clock_clone = clock.clone();
        let handle =
            spawn_ephemeral_identity_sweeper(db.clone(), Duration::from_millis(15), move || {
                clock_clone.load(Ordering::SeqCst)
            });

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(db.list_ephemeral_identities().unwrap().len(), 2);

        clock.store(20, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let remaining = db.list_ephemeral_identities().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "expires-later");

        handle.abort();
    }
}
