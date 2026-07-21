//! Local ledger of invite links/QRs this identity has issued. There's no
//! server to ask "has this link been used yet" (SPEC.md §3), so expiry and
//! use-count limits are enforced entirely by the issuer: when someone tries
//! to complete a handshake using a token we issued, we check this table
//! before accepting. See `bh-crypto::invite` for the link/QR payload format
//! itself, which carries the same token.

use rusqlite::params;

use crate::{models::IssuedInvite, Database, StorageError};

fn row_to_invite(row: &rusqlite::Row) -> rusqlite::Result<IssuedInvite> {
    Ok(IssuedInvite {
        token: row.get(0)?,
        created_at: row.get(1)?,
        expires_at: row.get(2)?,
        max_uses: row.get(3)?,
        use_count: row.get(4)?,
        revoked: row.get::<_, i64>(5)? != 0,
    })
}

const SELECT_COLUMNS: &str = "token, created_at, expires_at, max_uses, use_count, revoked";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteValidity {
    Valid,
    Unknown,
    Expired,
    Revoked,
    UseLimitReached,
}

impl Database {
    pub fn record_issued_invite(&self, invite: &IssuedInvite) -> Result<(), StorageError> {
        self.conn()?.execute(
            "INSERT INTO issued_invites (token, created_at, expires_at, max_uses, use_count, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                invite.token,
                invite.created_at,
                invite.expires_at,
                invite.max_uses,
                invite.use_count,
                invite.revoked as i64,
            ],
        )?;
        Ok(())
    }

    pub fn get_issued_invite(&self, token: &[u8]) -> Result<Option<IssuedInvite>, StorageError> {
        let conn = self.conn()?;
        let sql = format!("SELECT {SELECT_COLUMNS} FROM issued_invites WHERE token = ?1");
        conn.query_row(&sql, params![token], row_to_invite)
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other.into()),
            })
    }

    pub fn revoke_invite(&self, token: &[u8]) -> Result<(), StorageError> {
        self.conn()?.execute(
            "UPDATE issued_invites SET revoked = 1 WHERE token = ?1",
            params![token],
        )?;
        Ok(())
    }

    /// Checks whether `token` may still be redeemed at time `now`, *without*
    /// consuming a use — callers that are actually completing a handshake
    /// should call [`Database::consume_invite`] instead, which checks and
    /// increments atomically.
    pub fn check_invite_validity(
        &self,
        token: &[u8],
        now: i64,
    ) -> Result<InviteValidity, StorageError> {
        let Some(invite) = self.get_issued_invite(token)? else {
            return Ok(InviteValidity::Unknown);
        };
        Ok(Self::validity_of(&invite, now))
    }

    fn validity_of(invite: &IssuedInvite, now: i64) -> InviteValidity {
        if invite.revoked {
            return InviteValidity::Revoked;
        }
        if let Some(expires_at) = invite.expires_at {
            if now >= expires_at {
                return InviteValidity::Expired;
            }
        }
        if let Some(max_uses) = invite.max_uses {
            if invite.use_count >= max_uses {
                return InviteValidity::UseLimitReached;
            }
        }
        InviteValidity::Valid
    }

    /// Atomically checks validity and records one use. Returns the validity
    /// the token had *before* this call — a caller only proceeds with the
    /// handshake when this returns `Valid`.
    pub fn consume_invite(&self, token: &[u8], now: i64) -> Result<InviteValidity, StorageError> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let invite: Option<IssuedInvite> = {
            let sql = format!("SELECT {SELECT_COLUMNS} FROM issued_invites WHERE token = ?1");
            tx.query_row(&sql, params![token], row_to_invite)
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })?
        };
        let Some(invite) = invite else {
            return Ok(InviteValidity::Unknown);
        };
        let validity = Self::validity_of(&invite, now);
        if validity == InviteValidity::Valid {
            tx.execute(
                "UPDATE issued_invites SET use_count = use_count + 1 WHERE token = ?1",
                params![token],
            )?;
        }
        tx.commit()?;
        Ok(validity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite(token: Vec<u8>, expires_at: Option<i64>, max_uses: Option<i64>) -> IssuedInvite {
        IssuedInvite {
            token,
            created_at: 0,
            expires_at,
            max_uses,
            use_count: 0,
            revoked: false,
        }
    }

    #[test]
    fn unknown_token_is_unknown() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        assert_eq!(
            db.check_invite_validity(b"nope", 0).unwrap(),
            InviteValidity::Unknown
        );
    }

    #[test]
    fn expiry_is_enforced() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.record_issued_invite(&invite(b"t1".to_vec(), Some(100), None))
            .unwrap();
        assert_eq!(
            db.check_invite_validity(b"t1", 50).unwrap(),
            InviteValidity::Valid
        );
        assert_eq!(
            db.check_invite_validity(b"t1", 100).unwrap(),
            InviteValidity::Expired
        );
    }

    #[test]
    fn single_use_invite_cannot_be_consumed_twice() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.record_issued_invite(&invite(b"t1".to_vec(), None, Some(1)))
            .unwrap();

        assert_eq!(db.consume_invite(b"t1", 0).unwrap(), InviteValidity::Valid);
        assert_eq!(
            db.consume_invite(b"t1", 0).unwrap(),
            InviteValidity::UseLimitReached
        );
    }

    #[test]
    fn revoked_invite_is_rejected() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.record_issued_invite(&invite(b"t1".to_vec(), None, None))
            .unwrap();
        db.revoke_invite(b"t1").unwrap();
        assert_eq!(
            db.consume_invite(b"t1", 0).unwrap(),
            InviteValidity::Revoked
        );
    }
}
