//! SQLCipher-backed local database. Nothing touches disk in plaintext —
//! the encryption key is derived from the user's PIN/passcode and never
//! stored alongside the database. See `docs/SPEC.md` §7.

use crate::StorageError;

pub struct Database;

impl Database {
    pub fn open(_path: &str, _key: &[u8]) -> Result<Self, StorageError> {
        todo!("wire up SQLCipher-backed connection — see docs/SPEC.md §7")
    }
}
