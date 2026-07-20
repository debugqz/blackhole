//! Hardware-backed key custody: Secure Enclave on iOS, Keystore/StrongBox on
//! Android, with a desktop-appropriate fallback elsewhere. Also owns
//! multi-device linking state (the "active devices" panel and instant
//! revocation) and panic wipe. See `docs/SPEC.md` §4, §7.

use crate::StorageError;

pub struct Keystore;

impl Keystore {
    /// Stores a key in the platform's secure hardware element, never in
    /// plaintext on disk.
    pub fn store_key(&self, _label: &str, _key: &[u8]) -> Result<(), StorageError> {
        todo!("wire up platform secure key storage — see docs/SPEC.md §7")
    }

    /// Immediately and irreversibly wipes local key material and the
    /// encrypted database (SPEC.md §7 "panic wipe").
    pub fn panic_wipe(&self) -> Result<(), StorageError> {
        todo!("wire up panic wipe — see docs/SPEC.md §7")
    }
}
