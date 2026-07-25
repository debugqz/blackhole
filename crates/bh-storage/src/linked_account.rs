//! Persistence for the "this daemon is a linked secondary device" role
//! (`schema.rs`'s `SCHEMA_V21`) — the state `bh-api::device_link::
//! finish_link` used to negotiate and then throw away.
//!
//! Same single-row shape as `own_identity.rs`, and deliberately the same
//! trust boundary: the private key material here is protected by
//! SQLCipher and nothing else, exactly like `own_identity.identity_
//! private_key` and `sessions.ratchet_state` already are.

use rusqlite::params;

use crate::{models::LinkedAccount, Database, StorageError};

const COLUMNS: &str = "device_id, device_public_key, device_private_key, \
     account_public_key, linked_at, revoked_at";

fn row_to_linked_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<LinkedAccount> {
    Ok(LinkedAccount {
        device_id: row.get(0)?,
        device_public_key: row.get(1)?,
        device_private_key: row.get(2)?,
        account_public_key: row.get(3)?,
        linked_at: row.get(4)?,
        revoked_at: row.get(5)?,
    })
}

impl Database {
    /// Records this daemon as a secondary of `linked.account_public_key`.
    ///
    /// Rejects the call outright if this profile already has an
    /// `own_identity` row: that profile is a primary, and a daemon that
    /// is both would be genuinely ambiguous about whether
    /// `conversations::send_message` should encrypt locally or delegate —
    /// see [`LinkedAccount`]'s own doc comment. Returning an error here
    /// rather than silently preferring one role means the same-daemon
    /// device-linking demo (which runs both ceremony roles against one
    /// `AppState`, and *does* have an `own_identity`) keeps behaving
    /// exactly as it did instead of quietly converting that profile into
    /// a secondary of itself.
    pub fn set_linked_account(&self, linked: &LinkedAccount) -> Result<(), StorageError> {
        if self.get_own_identity()?.is_some() {
            return Err(StorageError::Forbidden(
                "cannot mark a profile with its own identity as a linked secondary device"
                    .to_string(),
            ));
        }
        self.conn()?.execute(
            "INSERT INTO linked_account (id, device_id, device_public_key, \
                 device_private_key, account_public_key, linked_at, revoked_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                device_id = excluded.device_id,
                device_public_key = excluded.device_public_key,
                device_private_key = excluded.device_private_key,
                account_public_key = excluded.account_public_key,
                linked_at = excluded.linked_at,
                revoked_at = excluded.revoked_at",
            params![
                linked.device_id,
                linked.device_public_key,
                linked.device_private_key,
                linked.account_public_key,
                linked.linked_at,
                linked.revoked_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_linked_account(&self) -> Result<Option<LinkedAccount>, StorageError> {
        self.conn()?
            .query_row(
                &format!("SELECT {COLUMNS} FROM linked_account WHERE id = 1"),
                [],
                row_to_linked_account,
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Marks this device as revoked by its primary. Deliberately keeps the
    /// row (rather than deleting it) so the client can explain *why* the
    /// device stopped syncing instead of silently reverting to a
    /// bootstrap screen that would invite the user to re-link into the
    /// same revoked state.
    pub fn mark_linked_account_revoked(&self, revoked_at: i64) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE linked_account SET revoked_at = ?1 WHERE id = 1",
            params![revoked_at],
        )?;
        Ok(())
    }

    /// Drops the secondary role entirely — used when the user unlinks this
    /// device from its own side, which (unlike revocation by the primary)
    /// really should return the profile to a blank, re-linkable state.
    pub fn clear_linked_account(&self) -> Result<(), StorageError> {
        self.conn()?
            .execute("DELETE FROM linked_account WHERE id = 1", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::OwnIdentity;

    fn sample() -> LinkedAccount {
        LinkedAccount {
            device_id: "device-1".to_string(),
            device_public_key: vec![7u8; 64],
            device_private_key: vec![1u8; 64],
            account_public_key: vec![9u8; 64],
            linked_at: 1_700_000_000,
            revoked_at: None,
        }
    }

    #[test]
    fn round_trips_and_starts_absent() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(db.get_linked_account().unwrap().is_none());

        db.set_linked_account(&sample()).unwrap();
        let loaded = db.get_linked_account().unwrap().unwrap();
        assert_eq!(loaded.device_id, "device-1");
        assert_eq!(loaded.account_public_key, vec![9u8; 64]);
        assert_eq!(loaded.device_private_key, vec![1u8; 64]);
        assert!(loaded.revoked_at.is_none());
    }

    /// The role split from [`LinkedAccount`]'s doc comment, enforced
    /// rather than merely documented: a profile that already holds the
    /// account's real identity must not also be marked as somebody's
    /// secondary. This is what keeps the pre-existing same-daemon linking
    /// demo (both ceremony roles, one `AppState`, a real `own_identity`)
    /// from converting itself into a secondary of itself.
    #[test]
    fn refuses_to_mark_a_primary_profile_as_a_secondary() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_own_identity(&OwnIdentity {
            identity_public_key: vec![3u8; 64],
            identity_private_key: vec![4u8; 64],
            created_at: 1_700_000_000,
        })
        .unwrap();

        assert!(db.set_linked_account(&sample()).is_err());
        assert!(db.get_linked_account().unwrap().is_none());
    }

    #[test]
    fn revocation_keeps_the_row_and_clearing_removes_it() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_linked_account(&sample()).unwrap();

        db.mark_linked_account_revoked(1_700_000_500).unwrap();
        let revoked = db.get_linked_account().unwrap().unwrap();
        assert_eq!(revoked.revoked_at, Some(1_700_000_500));

        db.clear_linked_account().unwrap();
        assert!(db.get_linked_account().unwrap().is_none());
    }
}
