use rusqlite::params;

use crate::{models::OwnMlsKeyPackage, Database, StorageError};

impl Database {
    /// Replaces whatever key package's signer was previously recorded —
    /// callers must call this every time a fresh key package is generated
    /// and published, including immediately after a successful join (see
    /// `models::OwnMlsKeyPackage`'s doc comment on why that's not optional
    /// the way `own_prekey`'s reuse is).
    pub fn set_own_mls_key_package(
        &self,
        key_package: &OwnMlsKeyPackage,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO own_mls_key_package (id, signer_public_key, key_package_bytes, created_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                signer_public_key = excluded.signer_public_key,
                key_package_bytes = excluded.key_package_bytes,
                created_at = excluded.created_at",
            params![
                key_package.signer_public_key,
                key_package.key_package_bytes,
                key_package.created_at
            ],
        )?;
        Ok(())
    }

    pub fn get_own_mls_key_package(&self) -> Result<Option<OwnMlsKeyPackage>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT signer_public_key, key_package_bytes, created_at
                 FROM own_mls_key_package WHERE id = 1",
                [],
                |row| {
                    Ok(OwnMlsKeyPackage {
                        signer_public_key: row.get(0)?,
                        key_package_bytes: row.get(1)?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    #[test]
    fn get_own_mls_key_package_is_none_until_set() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(db.get_own_mls_key_package().unwrap().is_none());
    }

    #[test]
    fn set_then_get_roundtrips_and_upserts() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.set_own_mls_key_package(&OwnMlsKeyPackage {
            signer_public_key: vec![1u8; 32],
            key_package_bytes: vec![9u8; 8],
            created_at: 1000,
        })
        .unwrap();
        let loaded = db.get_own_mls_key_package().unwrap().unwrap();
        assert_eq!(loaded.signer_public_key, vec![1u8; 32]);
        assert_eq!(loaded.key_package_bytes, vec![9u8; 8]);

        db.set_own_mls_key_package(&OwnMlsKeyPackage {
            signer_public_key: vec![2u8; 32],
            key_package_bytes: vec![8u8; 8],
            created_at: 2000,
        })
        .unwrap();
        let loaded = db.get_own_mls_key_package().unwrap().unwrap();
        assert_eq!(loaded.signer_public_key, vec![2u8; 32]);
        assert_eq!(loaded.key_package_bytes, vec![8u8; 8]);
    }
}
