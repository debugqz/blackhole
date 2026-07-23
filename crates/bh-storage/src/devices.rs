use rusqlite::params;

use crate::{
    models::{Device, DeviceOwner},
    Database, StorageError,
};

fn row_to_device(row: &rusqlite::Row) -> rusqlite::Result<Device> {
    let owner: String = row.get(1)?;
    Ok(Device {
        device_id: row.get(0)?,
        owner: DeviceOwner::from_db_str(&owner),
        contact_id: row.get(2)?,
        name: row.get(3)?,
        public_key: row.get(4)?,
        linked_at: row.get(5)?,
        last_seen_at: row.get(6)?,
        revoked_at: row.get(7)?,
        identity_agreement_key: row.get(8)?,
    })
}

const SELECT_COLUMNS: &str = "device_id, owner, contact_id, name, public_key, linked_at, \
     last_seen_at, revoked_at, identity_agreement_key";

impl Database {
    pub fn upsert_device(&self, device: &Device) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO devices (device_id, owner, contact_id, name, public_key, linked_at, last_seen_at, revoked_at, identity_agreement_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(device_id) DO UPDATE SET
                name = excluded.name,
                last_seen_at = excluded.last_seen_at,
                revoked_at = excluded.revoked_at,
                identity_agreement_key = excluded.identity_agreement_key",
            params![
                device.device_id,
                device.owner.as_str(),
                device.contact_id,
                device.name,
                device.public_key,
                device.linked_at,
                device.last_seen_at,
                device.revoked_at,
                device.identity_agreement_key,
            ],
        )?;
        Ok(())
    }

    /// Records `device_id`'s own X25519 agreement key after the fact —
    /// used when the device's real transport identity is established
    /// separately from the initial `upsert_device` call (e.g. the linked
    /// device publishing it once it comes online for the first time,
    /// rather than the primary already knowing it at link time).
    pub fn set_device_agreement_key(
        &self,
        device_id: &str,
        agreement_key: &[u8],
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE devices SET identity_agreement_key = ?1 WHERE device_id = ?2",
            params![agreement_key, device_id],
        )?;
        Ok(())
    }

    /// Devices linked to the local account — the "active devices" panel
    /// (SPEC.md §4).
    pub fn list_own_devices(&self) -> Result<Vec<Device>, StorageError> {
        let conn = self.conn()?;
        let sql =
            format!("SELECT {SELECT_COLUMNS} FROM devices WHERE owner = 'self' ORDER BY linked_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_device)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn list_contact_devices(&self, contact_id: &str) -> Result<Vec<Device>, StorageError> {
        let conn = self.conn()?;
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM devices WHERE owner = 'contact' AND contact_id = ?1 ORDER BY linked_at"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![contact_id], row_to_device)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    /// Instant revocation — the device stays visible in history but is
    /// marked revoked (SPEC.md §4).
    pub fn revoke_device(&self, device_id: &str, revoked_at: i64) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE devices SET revoked_at = ?1 WHERE device_id = ?2",
            params![revoked_at, device_id],
        )?;
        Ok(())
    }

    /// A single device by id, regardless of owner — used by
    /// `crates/bh-api/src/device_sync.rs` to confirm a sync target is a
    /// real, non-revoked, own-account device before pulling anything for
    /// it.
    pub fn get_device(&self, device_id: &str) -> Result<Option<Device>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM devices WHERE device_id = ?1");
        conn.query_row(&sql, params![device_id], row_to_device)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// The current delivery cursor for a linked device — how far (by
    /// `sent_at`, tie-broken by `message_id`) it has pulled via
    /// `GET /devices/:id/sync`. `None` if the device has never synced.
    pub fn get_device_sync_cursor(
        &self,
        device_id: &str,
    ) -> Result<Option<(i64, Option<String>)>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT cursor_sent_at, cursor_message_id FROM device_sync_cursor WHERE device_id = ?1",
                params![device_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Advances (or initializes) a device's sync cursor after a
    /// successful `GET /devices/:id/sync` pull.
    pub fn advance_device_sync_cursor(
        &self,
        device_id: &str,
        cursor_sent_at: i64,
        cursor_message_id: &str,
        updated_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO device_sync_cursor (device_id, cursor_sent_at, cursor_message_id, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(device_id) DO UPDATE SET
                cursor_sent_at = excluded.cursor_sent_at,
                cursor_message_id = excluded.cursor_message_id,
                updated_at = excluded.updated_at",
            params![device_id, cursor_sent_at, cursor_message_id, updated_at],
        )?;
        Ok(())
    }
}
