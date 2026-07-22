//! Persistence for `bh-crypto`'s MLS group state — same opaque-blob
//! contract as `sessions.rs`.

use rusqlite::params;

use crate::{
    models::{Group, GroupMember},
    Database, StorageError,
};

fn row_to_group(row: &rusqlite::Row) -> rusqlite::Result<Group> {
    let broadcast_only: i64 = row.get(5)?;
    Ok(Group {
        group_id: row.get(0)?,
        name: row.get(1)?,
        mls_state: row.get(2)?,
        epoch: row.get(3)?,
        created_at: row.get(4)?,
        broadcast_only: broadcast_only != 0,
    })
}

const SELECT_COLUMNS: &str = "group_id, name, mls_state, epoch, created_at, broadcast_only";

impl Database {
    pub fn create_group(&self, group: &Group) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO groups (group_id, name, mls_state, epoch, created_at, broadcast_only)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                group.group_id,
                group.name,
                group.mls_state,
                group.epoch,
                group.created_at,
                group.broadcast_only as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_groups(&self) -> Result<Vec<Group>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM groups ORDER BY created_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_group)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn get_group(&self, group_id: &str) -> Result<Option<Group>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM groups WHERE group_id = ?1");
        conn.query_row(&sql, params![group_id], row_to_group)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    /// The group backing a `kind = 'group'` conversation, if any — used by
    /// `send_message` to decide whether a broadcast-only posting
    /// restriction applies without the caller having to fetch the
    /// conversation and group separately.
    pub fn get_group_for_conversation(
        &self,
        conversation_id: &str,
    ) -> Result<Option<Group>, StorageError> {
        let conn = self.conn()?;
        let sql = "SELECT g.group_id, g.name, g.mls_state, g.epoch, g.created_at, g.broadcast_only
             FROM groups g
             JOIN conversations c ON c.group_id = g.group_id
             WHERE c.conversation_id = ?1";
        conn.query_row(sql, params![conversation_id], row_to_group)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    #[test]
    fn list_groups_returns_every_created_group_in_order() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(db.list_groups().unwrap().is_empty());

        db.create_group(&Group {
            group_id: "g1".into(),
            name: Some("Friends".into()),
            mls_state: b"placeholder".to_vec(),
            epoch: 0,
            created_at: 100,
            broadcast_only: false,
        })
        .unwrap();
        db.create_group(&Group {
            group_id: "g2".into(),
            name: None,
            mls_state: b"placeholder".to_vec(),
            epoch: 0,
            created_at: 200,
            broadcast_only: false,
        })
        .unwrap();

        let groups = db.list_groups().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].group_id, "g1");
        assert_eq!(groups[1].group_id, "g2");
    }
}
