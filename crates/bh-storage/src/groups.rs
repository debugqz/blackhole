//! Persistence for `bh-crypto`'s MLS group state — same opaque-blob
//! contract as `sessions.rs`.

use rusqlite::params;

use crate::{
    models::{Group, GroupMember},
    Database, StorageError,
};

impl Database {
    pub fn create_group(&self, group: &Group) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO groups (group_id, name, mls_state, epoch, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                group.group_id,
                group.name,
                group.mls_state,
                group.epoch,
                group.created_at
            ],
        )?;
        Ok(())
    }

    pub fn get_group(&self, group_id: &str) -> Result<Option<Group>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT group_id, name, mls_state, epoch, created_at FROM groups WHERE group_id = ?1",
                params![group_id],
                |row| {
                    Ok(Group {
                        group_id: row.get(0)?,
                        name: row.get(1)?,
                        mls_state: row.get(2)?,
                        epoch: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// Called after every MLS Commit — advances the persisted epoch.
    pub fn update_group_state(
        &self,
        group_id: &str,
        mls_state: &[u8],
        epoch: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE groups SET mls_state = ?1, epoch = ?2 WHERE group_id = ?3",
            params![mls_state, epoch, group_id],
        )?;
        Ok(())
    }

    pub fn add_group_member(
        &self,
        group_id: &str,
        contact_id: &str,
        joined_at: i64,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO group_members (group_id, contact_id, joined_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, contact_id) DO NOTHING",
            params![group_id, contact_id, joined_at],
        )?;
        Ok(())
    }

    pub fn remove_group_member(
        &self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND contact_id = ?2",
            params![group_id, contact_id],
        )?;
        Ok(())
    }

    pub fn list_group_members(&self, group_id: &str) -> Result<Vec<GroupMember>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT group_id, contact_id, joined_at FROM group_members WHERE group_id = ?1",
        )?;
        let rows = stmt.query_map(params![group_id], |row| {
            Ok(GroupMember {
                group_id: row.get(0)?,
                contact_id: row.get(1)?,
                joined_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }
}
