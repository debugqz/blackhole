//! Hardware/OS-backed key custody. On desktop this wraps the platform
//! credential store (Keychain on macOS, Credential Manager on Windows,
//! Secret Service on Linux) via the `keyring` crate. Secure Enclave
//! (iOS) and Keystore/StrongBox (Android) bindings are mobile-specific and
//! out of scope until a mobile client exists (SPEC.md §7).
//!
//! What actually lives here is small: the SQLCipher database encryption key
//! and the device's own signing key. Everything else (sessions, groups,
//! messages) lives inside the SQLCipher-encrypted database itself, which is
//! why keeping those two keys out of reach of disk is enough to protect the
//! rest.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::StorageError;

/// Label under which the SQLCipher database key is stored.
pub const DB_KEY_LABEL: &str = "db-encryption-key";
/// Label under which the device's own long-term signing key is stored.
pub const DEVICE_SIGNING_KEY_LABEL: &str = "device-signing-key";
/// Label under which the *payments* database's SQLCipher key is stored —
/// deliberately a different label (and so a different key) than
/// `DB_KEY_LABEL`, even though both live in the same per-profile keystore
/// service. See `crates/bh-storage/src/payments_db.rs` for why the
/// payments and messaging databases must never share a key.
pub const PAYMENTS_DB_KEY_LABEL: &str = "payments-db-encryption-key";
/// Label under which the HMAC-SHA256 secret gating
/// `bh-api::cosmetics::mark_purchase_paid` is stored (see
/// `bh_crypto::webhook`). Generated on first use — unlike `DB_KEY_LABEL`,
/// this has no PIN-protection concept since it never gates database
/// decryption, only proves a caller knows the shared webhook secret.
pub const COSMETICS_WEBHOOK_SECRET_LABEL: &str = "cosmetics-webhook-secret";
/// Label under which the *MLS group storage* database's SQLCipher key is
/// stored — again a distinct label/key from `DB_KEY_LABEL` and
/// `PAYMENTS_DB_KEY_LABEL`, for the same reason: `bh_crypto::mls_storage
/// ::PersistentMlsProvider` keeps group crypto state in its own SQLCipher
/// file, isolated from both the messaging and payments databases
/// (`docs/THREAT_MODEL.md` §3.2).
pub const MLS_DB_KEY_LABEL: &str = "mls-db-encryption-key";

pub struct Keystore {
    service: String,
    /// Directory containing the encrypted database and any other local
    /// state — what `panic_wipe` deletes from disk.
    data_dir: PathBuf,
    // `keyring::Entry` handles are cached per label rather than recreated
    // on every call: real backends do a round-trip to the OS credential
    // store per `Entry::new`, and the point of this cache is to avoid
    // paying that on every read.
    entries: Mutex<HashMap<String, keyring::Entry>>,
}

impl Keystore {
    pub fn new(service: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            service: service.into(),
            data_dir: data_dir.into(),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn with_entry<T>(
        &self,
        label: &str,
        f: impl FnOnce(&keyring::Entry) -> keyring::Result<T>,
    ) -> Result<T, StorageError> {
        let mut entries = self
            .entries
            .lock()
            .expect("keystore entry cache mutex poisoned");
        if !entries.contains_key(label) {
            entries.insert(
                label.to_string(),
                keyring::Entry::new(&self.service, label)?,
            );
        }
        let entry = entries.get(label).expect("just inserted");
        f(entry).map_err(Into::into)
    }

    /// Stores a key in the platform's secure credential store, never in
    /// plaintext on disk.
    pub fn store_key(&self, label: &str, key: &[u8]) -> Result<(), StorageError> {
        self.with_entry(label, |e| e.set_password(&hex::encode(key)))
    }

    pub fn load_key(&self, label: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let result = self.with_entry(label, |e| match e.get_password() {
            Ok(hex_key) => Ok(Some(hex_key)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e),
        })?;
        match result {
            Some(hex_key) => Ok(Some(
                hex::decode(hex_key).map_err(|_| StorageError::NotFound)?,
            )),
            None => Ok(None),
        }
    }

    pub fn delete_key(&self, label: &str) -> Result<(), StorageError> {
        self.with_entry(label, |e| match e.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e),
        })
    }

    /// Immediately and irreversibly wipes local key material and the
    /// encrypted database directory (SPEC.md §7 "panic wipe"). There is no
    /// undo — this is meant to be triggered from an emergency gesture/PIN,
    /// not casually.
    pub fn panic_wipe(&self) -> Result<(), StorageError> {
        self.delete_key(DB_KEY_LABEL)?;
        self.delete_key(DEVICE_SIGNING_KEY_LABEL)?;
        self.delete_key(PAYMENTS_DB_KEY_LABEL)?;
        self.delete_key(MLS_DB_KEY_LABEL)?;
        if self.data_dir.exists() {
            std::fs::remove_dir_all(&self.data_dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `set_default_credential_builder` replaces a process-global static, so
    // calling it from every test would let concurrently-running tests wipe
    // each other's stored entries out from under them. Install it exactly
    // once for the whole test binary instead.
    fn use_mock_keychain() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    #[test]
    fn store_and_load_roundtrip() {
        use_mock_keychain();
        let dir = std::env::temp_dir().join(format!("bh-keystore-test-{}", std::process::id()));
        let ks = Keystore::new("blackhole-test-roundtrip", dir);
        let key = [7u8; 32];
        ks.store_key(DB_KEY_LABEL, &key).unwrap();
        assert_eq!(ks.load_key(DB_KEY_LABEL).unwrap(), Some(key.to_vec()));
        ks.delete_key(DB_KEY_LABEL).unwrap();
        assert_eq!(ks.load_key(DB_KEY_LABEL).unwrap(), None);
    }

    #[test]
    fn panic_wipe_removes_keys_and_data_dir() {
        use_mock_keychain();
        let dir =
            std::env::temp_dir().join(format!("bh-keystore-wipe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blackhole.db"), b"not real data").unwrap();

        let ks = Keystore::new("blackhole-test-wipe", &dir);
        ks.store_key(DB_KEY_LABEL, &[1u8; 32]).unwrap();
        ks.store_key(DEVICE_SIGNING_KEY_LABEL, &[2u8; 32]).unwrap();
        ks.store_key(PAYMENTS_DB_KEY_LABEL, &[3u8; 32]).unwrap();
        ks.store_key(MLS_DB_KEY_LABEL, &[4u8; 32]).unwrap();
        assert_eq!(ks.load_key(DB_KEY_LABEL).unwrap(), Some(vec![1u8; 32]));

        ks.panic_wipe().unwrap();

        assert_eq!(ks.load_key(DB_KEY_LABEL).unwrap(), None);
        assert_eq!(ks.load_key(DEVICE_SIGNING_KEY_LABEL).unwrap(), None);
        assert_eq!(ks.load_key(PAYMENTS_DB_KEY_LABEL).unwrap(), None);
        assert_eq!(ks.load_key(MLS_DB_KEY_LABEL).unwrap(), None);
        assert!(!dir.exists());
    }
}
