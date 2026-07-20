use rusqlite::params;

use crate::{models::Contact, Database, StorageError};

fn row_to_contact(row: &rusqlite::Row) -> rusqlite::Result<Contact> {
    Ok(Contact {
        contact_id: row.get(0)?,
        identity_public_key: row.get(1)?,
        display_name: row.get(2)?,
        verified: row.get::<_, i64>(3)? != 0,
        blocked: row.get::<_, i64>(4)? != 0,
        added_at: row.get(5)?,
    })
}

const SELECT_COLUMNS: &str =
    "contact_id, identity_public_key, display_name, verified, blocked, added_at";

impl Database {
    pub fn upsert_contact(&self, contact: &Contact) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO contacts (contact_id, identity_public_key, display_name, verified, blocked, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(contact_id) DO UPDATE SET
                identity_public_key = excluded.identity_public_key,
                display_name = excluded.display_name",
            params![
                contact.contact_id,
                contact.identity_public_key,
                contact.display_name,
                contact.verified as i64,
                contact.blocked as i64,
                contact.added_at
            ],
        )?;
        Ok(())
    }

    pub fn get_contact(&self, contact_id: &str) -> Result<Option<Contact>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM contacts WHERE contact_id = ?1");
        conn.query_row(&sql, params![contact_id], row_to_contact)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn list_contacts(&self) -> Result<Vec<Contact>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM contacts ORDER BY added_at");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_contact)?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    pub fn set_contact_blocked(&self, contact_id: &str, blocked: bool) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE contacts SET blocked = ?1 WHERE contact_id = ?2",
            params![blocked as i64, contact_id],
        )?;
        Ok(())
    }

    pub fn set_contact_verified(
        &self,
        contact_id: &str,
        verified: bool,
    ) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE contacts SET verified = ?1 WHERE contact_id = ?2",
            params![verified as i64, contact_id],
        )?;
        Ok(())
    }
}
