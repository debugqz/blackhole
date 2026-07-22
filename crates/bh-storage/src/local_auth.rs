//! Persistence for the Tauri client's local-unlock gate (passkey/TOTP —
//! see `bh-crypto::auth`). Client-side UX only: does **not** gate SQLCipher
//! DB decryption, which happens before any of this is ever read
//! (THREAT_MODEL.md §3.7).

use rusqlite::params;

use crate::{
    models::{PasskeyCredential, TotpSecretRow},
    Database, StorageError,
};

impl Database {
    pub fn get_totp_secret(&self) -> Result<Option<TotpSecretRow>, StorageError> {
        self.conn()?
            .query_row(
                "SELECT base32_secret, enrolled_at FROM totp_secrets WHERE id = 1",
                [],
                |row| {
                    Ok(TotpSecretRow {
                        base32_secret: row.get(0)?,
                        enrolled_at: row.get(1)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn set_totp_secret(&self, secret: &TotpSecretRow) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO totp_secrets (id, base32_secret, enrolled_at)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
                base32_secret = excluded.base32_secret,
                enrolled_at = excluded.enrolled_at",
            params![secret.base32_secret, secret.enrolled_at],
        )?;
        Ok(())
    }

    pub fn delete_totp_secret(&self) -> Result<(), StorageError> {
        self.conn()?
            .execute("DELETE FROM totp_secrets WHERE id = 1", [])?;
        Ok(())
    }

    pub fn list_passkey_credentials(&self) -> Result<Vec<PasskeyCredential>, StorageError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT credential_id, passkey_blob, label, enrolled_at FROM passkey_credentials ORDER BY enrolled_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PasskeyCredential {
                credential_id: row.get(0)?,
                passkey_blob: row.get(1)?,
                label: row.get(2)?,
                enrolled_at: row.get(3)?,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn upsert_passkey_credential(
        &self,
        credential: &PasskeyCredential,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO passkey_credentials (credential_id, passkey_blob, label, enrolled_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(credential_id) DO UPDATE SET
                passkey_blob = excluded.passkey_blob,
                label = excluded.label",
            params![
                credential.credential_id,
                credential.passkey_blob,
                credential.label,
                credential.enrolled_at,
            ],
        )?;
        Ok(())
    }

    pub fn delete_passkey_credential(&self, credential_id: &str) -> Result<(), StorageError> {
        self.conn()?.execute(
            "DELETE FROM passkey_credentials WHERE credential_id = ?1",
            params![credential_id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open_in_memory(&[1u8; 32]).unwrap()
    }

    #[test]
    fn totp_secret_round_trips() {
        let db = test_db();
        assert!(db.get_totp_secret().unwrap().is_none());

        db.set_totp_secret(&TotpSecretRow {
            base32_secret: "JBSWY3DPEHPK3PXP".to_string(),
            enrolled_at: 100,
        })
        .unwrap();
        let loaded = db.get_totp_secret().unwrap().unwrap();
        assert_eq!(loaded.base32_secret, "JBSWY3DPEHPK3PXP");

        db.delete_totp_secret().unwrap();
        assert!(db.get_totp_secret().unwrap().is_none());
    }

    #[test]
    fn passkey_credentials_round_trip() {
        let db = test_db();
        assert!(db.list_passkey_credentials().unwrap().is_empty());

        db.upsert_passkey_credential(&PasskeyCredential {
            credential_id: "cred-1".to_string(),
            passkey_blob: vec![1, 2, 3],
            label: Some("MacBook Touch ID".to_string()),
            enrolled_at: 100,
        })
        .unwrap();
        let creds = db.list_passkey_credentials().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].credential_id, "cred-1");

        db.delete_passkey_credential("cred-1").unwrap();
        assert!(db.list_passkey_credentials().unwrap().is_empty());
    }
}
