use rusqlite::params;

use crate::{models::OwnIdentity, Database, StorageError};

impl Database {
    pub fn set_own_identity(&self, identity: &OwnIdentity) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO own_identity (id, identity_public_key, identity_private_key, created_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                identity_public_key = excluded.identity_public_key,
                identity_private_key = excluded.identity_private_key",
            params![
                identity.identity_public_key,
                identity.identity_private_key,
                identity.created_at
            ],
        )?;
        Ok(())
    }

    pub fn get_own_identity(&self) -> Result<Option<OwnIdentity>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT identity_public_key, identity_private_key, created_at
                 FROM own_identity WHERE id = 1",
                [],
                |row| {
                    Ok(OwnIdentity {
                        identity_public_key: row.get(0)?,
                        identity_private_key: row.get(1)?,
                        created_at: row.get(2)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }
}
