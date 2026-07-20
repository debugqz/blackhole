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
    })
}

const SELECT_COLUMNS: &str =
    "device_id, owner, contact_id, name, public_key, linked_at, last_seen_at, revoked_at";

impl Database {
    pub fn upsert_device(&self, device: &Device) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO devices (device_id, owner, contact_id, name, public_key, linked_at, last_seen_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(device_id) DO UPDATE SET
                name = excluded.name,
                last_seen_at = excluded.last_seen_at,
                revoked_at = excluded.revoked_at",
            params![
                device.device_id,
                device.owner.as_str(),
                device.contact_id,
                device.name,
                device.public_key,
                device.linked_at,
                device.last_seen_at,
                device.revoked_at,
            ],
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
}
