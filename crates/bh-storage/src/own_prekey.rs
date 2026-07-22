use rusqlite::params;

use crate::{models::OwnPrekey, Database, StorageError};

impl Database {
    /// Only ever called once per identity (see `schema.rs`'s `SCHEMA_V15`
    /// doc comment: a single, non-rotating signed prekey for v1) — but
    /// `ON CONFLICT` upserts anyway, matching `own_identity`'s pattern,
    /// rather than assuming the caller never calls this twice.
    pub fn set_own_prekey(&self, prekey: &OwnPrekey) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO own_prekey
                (id, signed_prekey_id, signed_prekey_secret, signed_prekey_signature,
                 pq_prekey_seed, pq_prekey_signature, created_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                signed_prekey_id = excluded.signed_prekey_id,
                signed_prekey_secret = excluded.signed_prekey_secret,
                signed_prekey_signature = excluded.signed_prekey_signature,
                pq_prekey_seed = excluded.pq_prekey_seed,
                pq_prekey_signature = excluded.pq_prekey_signature",
            params![
                prekey.signed_prekey_id,
                prekey.signed_prekey_secret,
                prekey.signed_prekey_signature,
                prekey.pq_prekey_seed,
                prekey.pq_prekey_signature,
                prekey.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_own_prekey(&self) -> Result<Option<OwnPrekey>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT signed_prekey_id, signed_prekey_secret, signed_prekey_signature,
                        pq_prekey_seed, pq_prekey_signature, created_at
                 FROM own_prekey WHERE id = 1",
                [],
                |row| {
                    Ok(OwnPrekey {
                        signed_prekey_id: row.get(0)?,
                        signed_prekey_secret: row.get(1)?,
                        signed_prekey_signature: row.get(2)?,
                        pq_prekey_seed: row.get(3)?,
                        pq_prekey_signature: row.get(4)?,
                        created_at: row.get(5)?,
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
    fn get_own_prekey_is_none_until_set() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert!(db.get_own_prekey().unwrap().is_none());
    }

    #[test]
    fn set_then_get_roundtrips_and_upserts() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        let prekey = OwnPrekey {
            signed_prekey_id: 1,
            signed_prekey_secret: vec![1u8; 32],
            signed_prekey_signature: vec![2u8; 64],
            pq_prekey_seed: vec![3u8; 96],
            pq_prekey_signature: vec![4u8; 64],
            created_at: 1000,
        };
        db.set_own_prekey(&prekey).unwrap();
        let loaded = db.get_own_prekey().unwrap().unwrap();
        assert_eq!(loaded.signed_prekey_id, 1);
        assert_eq!(loaded.signed_prekey_secret, vec![1u8; 32]);

        let updated = OwnPrekey {
            signed_prekey_id: 2,
            ..prekey
        };
        db.set_own_prekey(&updated).unwrap();
        assert_eq!(db.get_own_prekey().unwrap().unwrap().signed_prekey_id, 2);
    }
}
