//! Local record of this identity's opt-in "wake push" registration
//! (SPEC.md §5.6, `crates/bh-push-relay`). Stores nothing but an opaque,
//! locally-generated token and whether the feature is currently on —
//! never message content, never a contact or conversation id. The token
//! is not derived from (and cannot be linked back to) the identity key.
//! Single-row, same pattern as `own_identity.rs`: there is exactly one
//! "is push on for this profile" state at a time.

use rusqlite::params;

use crate::{models::PushRegistration, Database, StorageError};

impl Database {
    pub fn set_push_registration(&self, reg: &PushRegistration) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO push_registration (id, token, enabled, updated_at, relay_url)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                token = excluded.token,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at,
                relay_url = excluded.relay_url",
            params![reg.token, reg.enabled as i64, reg.updated_at, reg.relay_url],
        )?;
        Ok(())
    }

    pub fn get_push_registration(&self) -> Result<Option<PushRegistration>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT token, enabled, updated_at, relay_url FROM push_registration WHERE id = 1",
                [],
                |row| {
                    Ok(PushRegistration {
                        token: row.get(0)?,
                        enabled: row.get::<_, i64>(1)? != 0,
                        updated_at: row.get(2)?,
                        relay_url: row.get(3)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Fully removes the registration row (opt-out) rather than just
    /// flipping `enabled` to 0 — once a user opts out, there's no reason
    /// to keep even the opaque token around.
    pub fn clear_push_registration(&self) -> Result<(), StorageError> {
        self.conn()?
            .execute("DELETE FROM push_registration WHERE id = 1", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_registration_by_default() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(db.get_push_registration().unwrap().is_none());
    }

    #[test]
    fn set_then_get_round_trips() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_push_registration(&PushRegistration {
            token: "abc123".into(),
            enabled: true,
            updated_at: 100,
            relay_url: Some("https://relay.example".into()),
        })
        .unwrap();

        let reg = db.get_push_registration().unwrap().unwrap();
        assert_eq!(reg.token, "abc123");
        assert!(reg.enabled);
        assert_eq!(reg.updated_at, 100);
        assert_eq!(reg.relay_url.as_deref(), Some("https://relay.example"));
    }

    #[test]
    fn relay_url_defaults_to_none_when_omitted() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_push_registration(&PushRegistration {
            token: "abc123".into(),
            enabled: true,
            updated_at: 100,
            relay_url: None,
        })
        .unwrap();

        let reg = db.get_push_registration().unwrap().unwrap();
        assert_eq!(reg.relay_url, None);
    }

    #[test]
    fn setting_again_overwrites_rather_than_duplicates() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_push_registration(&PushRegistration {
            token: "first".into(),
            enabled: true,
            updated_at: 1,
            relay_url: None,
        })
        .unwrap();
        db.set_push_registration(&PushRegistration {
            token: "second".into(),
            enabled: true,
            updated_at: 2,
            relay_url: Some("https://relay.example".into()),
        })
        .unwrap();

        let reg = db.get_push_registration().unwrap().unwrap();
        assert_eq!(reg.token, "second");
        assert_eq!(reg.relay_url.as_deref(), Some("https://relay.example"));
    }

    #[test]
    fn clear_removes_the_registration_entirely() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_push_registration(&PushRegistration {
            token: "abc123".into(),
            enabled: true,
            updated_at: 100,
            relay_url: None,
        })
        .unwrap();
        assert!(db.get_push_registration().unwrap().is_some());

        db.clear_push_registration().unwrap();
        assert!(db.get_push_registration().unwrap().is_none());
    }
}
