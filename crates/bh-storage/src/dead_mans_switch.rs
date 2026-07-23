//! Local "dead man's switch" (see `bh-api::dead_mans_switch`'s module doc
//! for the full design): if the user doesn't check in for `cadence_days`,
//! a predefined set of text messages goes out to predefined contacts,
//! once. Two things make this safe to reason about:
//!
//! 1. **The re-arm latch.** `triggered_at` is set the moment the sweeper
//!    fires and is never cleared except by [`Database::
//!    activate_dead_mans_switch`] transitioning disabled -> enabled — so
//!    [`Database::dead_mans_switch_is_due`] can never return `true` twice
//!    for the same "arming" without the user explicitly re-enabling.
//! 2. **Check-in only ever moves `last_check_in_at` forward**, and only
//!    while a switch exists and is enabled — [`Database::
//!    record_dead_mans_switch_check_in`] is a safe no-op otherwise, so
//!    callers (daemon boot, profile switch, "check in now") never need to
//!    special-case "does this profile even have a switch configured."

use rusqlite::params;

use crate::{
    models::{DeadMansSwitchConfig, DeadMansSwitchRelease, DeadMansSwitchReleaseView},
    Database, StorageError,
};

impl Database {
    pub fn get_dead_mans_switch(&self) -> Result<Option<DeadMansSwitchConfig>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT enabled, cadence_days, last_check_in_at, triggered_at, updated_at
                 FROM dead_mans_switch WHERE id = 1",
                [],
                |row| {
                    Ok(DeadMansSwitchConfig {
                        enabled: row.get::<_, i64>(0)? != 0,
                        cadence_days: row.get(1)?,
                        last_check_in_at: row.get(2)?,
                        triggered_at: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Activates the switch (or updates its cadence while already active).
    /// A disabled -> enabled transition (including the very first
    /// activation, and re-enabling after a firing) resets
    /// `last_check_in_at = now` and clears `triggered_at` — the "re-arm"
    /// the module doc promises. Updating the cadence of an
    /// *already-enabled* switch deliberately does **not** reset
    /// `last_check_in_at`: shortening/lengthening the cadence shouldn't
    /// itself count as a check-in, or a user could indefinitely defer
    /// firing just by nudging the number.
    pub fn activate_dead_mans_switch(
        &self,
        cadence_days: i64,
        now: i64,
    ) -> Result<DeadMansSwitchConfig, StorageError> {
        let was_enabled = self
            .get_dead_mans_switch()?
            .map(|c| c.enabled)
            .unwrap_or(false);
        let conn = self.conn()?;
        if was_enabled {
            conn.execute(
                "UPDATE dead_mans_switch SET cadence_days = ?1, updated_at = ?2 WHERE id = 1",
                params![cadence_days, now],
            )?;
        } else {
            conn.execute(
                "INSERT INTO dead_mans_switch
                    (id, enabled, cadence_days, last_check_in_at, triggered_at, updated_at)
                 VALUES (1, 1, ?1, ?2, NULL, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                    enabled = 1,
                    cadence_days = excluded.cadence_days,
                    last_check_in_at = excluded.last_check_in_at,
                    triggered_at = NULL,
                    updated_at = excluded.updated_at",
                params![cadence_days, now],
            )?;
        }
        drop(conn);
        self.get_dead_mans_switch()?.ok_or(StorageError::NotFound)
    }

    /// Disables the switch. Leaves `cadence_days`/`last_check_in_at` alone
    /// (so re-enabling without changing the cadence is a one-step UI
    /// action) but does **not** clear `triggered_at` here — the re-arm
    /// happens on the next [`Database::activate_dead_mans_switch`] call,
    /// not on disable, so a fired-then-disabled switch's history isn't
    /// lost while it's off.
    pub fn deactivate_dead_mans_switch(&self, now: i64) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE dead_mans_switch SET enabled = 0, updated_at = ?1 WHERE id = 1",
            params![now],
        )?;
        Ok(())
    }

    /// Check-in: resets the countdown to `now`. A safe no-op if no switch
    /// row exists yet, or it exists but is disabled — callers (daemon
    /// boot, profile switch, `POST /dead-mans-switch/check-in`) never need
    /// to check "is this configured" first. Does **not** clear
    /// `triggered_at`: a switch that has already fired stays fired
    /// regardless of check-ins until the user explicitly re-enables it.
    pub fn record_dead_mans_switch_check_in(&self, now: i64) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE dead_mans_switch SET last_check_in_at = ?1, updated_at = ?1
             WHERE id = 1 AND enabled = 1",
            params![now],
        )?;
        Ok(())
    }

    /// Whether the switch should fire right now: enabled, never yet
    /// triggered since it was last armed, and the cadence window has
    /// elapsed. [`Database::mark_dead_mans_switch_triggered`] is the only
    /// thing that ever makes this return `false` again for an
    /// otherwise-still-due row (short of the user disabling it).
    pub fn dead_mans_switch_is_due(&self, now: i64) -> Result<bool, StorageError> {
        self.conn()?
            .query_row(
                "SELECT 1 FROM dead_mans_switch
                 WHERE id = 1 AND enabled = 1 AND triggered_at IS NULL
                   AND (?1 - last_check_in_at) > (cadence_days * 86400)
                 LIMIT 1",
                params![now],
                |_| Ok(()),
            )
            .map(|_| true)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(other.into()),
            })
    }

    /// Marks the switch as fired — the re-arm latch (see module doc).
    /// Idempotent: calling this twice just overwrites `triggered_at` with
    /// the latest `now`, which is harmless since `dead_mans_switch_is_due`
    /// already excludes any row with `triggered_at IS NOT NULL`.
    pub fn mark_dead_mans_switch_triggered(&self, now: i64) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE dead_mans_switch SET triggered_at = ?1, updated_at = ?1 WHERE id = 1",
            params![now],
        )?;
        Ok(())
    }

    pub fn add_dead_mans_switch_release(
        &self,
        contact_id: &str,
        body: &str,
        created_at: i64,
    ) -> Result<DeadMansSwitchRelease, StorageError> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO dead_mans_switch_release (contact_id, body, created_at)
             VALUES (?1, ?2, ?3)",
            params![contact_id, body, created_at],
        )?;
        let id = conn.last_insert_rowid();
        drop(conn);
        Ok(DeadMansSwitchRelease {
            id,
            contact_id: contact_id.to_string(),
            body: body.to_string(),
            created_at,
        })
    }

    /// Listing joined with contact display info, for the UI.
    pub fn list_dead_mans_switch_releases(
        &self,
    ) -> Result<Vec<DeadMansSwitchReleaseView>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT r.id, r.contact_id, c.display_name, r.body, r.created_at
             FROM dead_mans_switch_release r
             JOIN contacts c ON c.contact_id = r.contact_id
             ORDER BY r.created_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DeadMansSwitchReleaseView {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                contact_display_name: row.get(2)?,
                body: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Raw (un-joined) release rows — used internally by the sweeper,
    /// which only needs `contact_id`/`body`, not display info.
    pub fn list_dead_mans_switch_releases_raw(
        &self,
    ) -> Result<Vec<DeadMansSwitchRelease>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, contact_id, body, created_at FROM dead_mans_switch_release ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DeadMansSwitchRelease {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                body: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn remove_dead_mans_switch_release(&self, id: i64) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM dead_mans_switch_release WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Contact;

    fn contact(id: &str) -> Contact {
        Contact {
            contact_id: id.to_string(),
            identity_public_key: vec![1; 32],
            display_name: Some(format!("Contact {id}")),
            verified: false,
            blocked: false,
            added_at: 0,
        }
    }

    #[test]
    fn no_switch_by_default() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(db.get_dead_mans_switch().unwrap().is_none());
        assert!(!db.dead_mans_switch_is_due(1_000_000).unwrap());
    }

    #[test]
    fn activate_round_trips() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        let config = db.activate_dead_mans_switch(7, 100).unwrap();
        assert!(config.enabled);
        assert_eq!(config.cadence_days, 7);
        assert_eq!(config.last_check_in_at, 100);
        assert!(config.triggered_at.is_none());
    }

    #[test]
    fn updating_cadence_while_enabled_does_not_reset_check_in() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.activate_dead_mans_switch(7, 100).unwrap();
        let config = db.activate_dead_mans_switch(3, 999).unwrap();
        assert_eq!(config.cadence_days, 3);
        // Cadence update, not a check-in: the clock must not move.
        assert_eq!(config.last_check_in_at, 100);
    }

    #[test]
    fn deactivate_then_reactivate_resets_check_in_and_clears_trigger() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.activate_dead_mans_switch(1, 0).unwrap();
        db.mark_dead_mans_switch_triggered(500).unwrap();
        db.deactivate_dead_mans_switch(500).unwrap();
        assert!(!db.get_dead_mans_switch().unwrap().unwrap().enabled);
        // Still latched while disabled.
        assert!(db
            .get_dead_mans_switch()
            .unwrap()
            .unwrap()
            .triggered_at
            .is_some());

        let config = db.activate_dead_mans_switch(1, 1_000).unwrap();
        assert!(config.enabled);
        assert_eq!(config.last_check_in_at, 1_000);
        assert!(config.triggered_at.is_none());
    }

    #[test]
    fn due_ness_crosses_the_cadence_boundary() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.activate_dead_mans_switch(1, 0).unwrap(); // 1-day cadence, armed at t=0
        assert!(!db.dead_mans_switch_is_due(0).unwrap());
        assert!(!db.dead_mans_switch_is_due(86_400).unwrap());
        assert!(db.dead_mans_switch_is_due(86_401).unwrap());
    }

    #[test]
    fn marking_triggered_stops_due_ness() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.activate_dead_mans_switch(1, 0).unwrap();
        assert!(db.dead_mans_switch_is_due(86_401).unwrap());
        db.mark_dead_mans_switch_triggered(86_401).unwrap();
        assert!(!db.dead_mans_switch_is_due(200_000).unwrap());
    }

    #[test]
    fn record_check_in_is_a_safe_no_op_when_unconfigured_or_disabled() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.record_dead_mans_switch_check_in(500).unwrap(); // no row yet — no-op
        assert!(db.get_dead_mans_switch().unwrap().is_none());

        db.activate_dead_mans_switch(1, 0).unwrap();
        db.deactivate_dead_mans_switch(0).unwrap();
        db.record_dead_mans_switch_check_in(999).unwrap(); // disabled — no-op
        assert_eq!(
            db.get_dead_mans_switch().unwrap().unwrap().last_check_in_at,
            0
        );
    }

    #[test]
    fn release_entries_add_list_remove_round_trip() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_contact(&contact("c1")).unwrap();
        let release = db
            .add_dead_mans_switch_release("c1", "hello from the future", 42)
            .unwrap();
        assert_eq!(release.contact_id, "c1");

        let views = db.list_dead_mans_switch_releases().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].contact_display_name.as_deref(), Some("Contact c1"));
        assert_eq!(views[0].body, "hello from the future");

        let raw = db.list_dead_mans_switch_releases_raw().unwrap();
        assert_eq!(raw.len(), 1);

        db.remove_dead_mans_switch_release(release.id).unwrap();
        assert!(db.list_dead_mans_switch_releases().unwrap().is_empty());
    }
}
