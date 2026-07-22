//! Optional PIN/passphrase layer in front of the SQLCipher database key
//! (`docs/THREAT_MODEL.md` §3.7, ranked gap #7). Today the raw key sits in
//! the OS keystore under `keystore::DB_KEY_LABEL`, so OS-keystore
//! compromise alone is sufficient to decrypt the database — there is no
//! second factor. This module lets that same keystore entry instead hold
//! the key sealed under a user-chosen PIN via `bh_crypto::backup::seal`
//! (Argon2id key derivation, deliberately slow, + ChaCha20Poly1305): once
//! a PIN is set, keystore access alone is no longer enough, the PIN is
//! required too.
//!
//! This wraps the *keystore entry*, not the database file itself — no
//! SQLCipher re-encryption happens when a PIN is set or cleared, only the
//! blob protecting the key changes shape. Telling the two shapes apart
//! needs no separate "is a PIN set" flag: a raw key is always exactly 32
//! bytes, and `backup::seal`'s output (`1` version byte + `16`-byte salt +
//! `12`-byte nonce + a ChaCha20Poly1305 ciphertext with its own 16-byte
//! tag) is always at least 45 bytes — strictly longer for any plaintext,
//! empty or not.

use bh_crypto::backup;

use crate::keystore::Keystore;
use crate::StorageError;

const RAW_KEY_LEN: usize = 32;

/// What's currently stored in the keystore under a given label.
pub enum DbKeyState {
    /// No PIN set — this is the key, ready to use.
    Unprotected([u8; RAW_KEY_LEN]),
    /// A PIN is set — this is the sealed blob; call [`unlock_with_pin`].
    PinProtected(Vec<u8>),
}

/// Reads whichever state `label` is currently in. `None` means no key has
/// ever been stored under this label (first run).
pub fn load_db_key_state(
    keystore: &Keystore,
    label: &str,
) -> Result<Option<DbKeyState>, StorageError> {
    let Some(bytes) = keystore.load_key(label)? else {
        return Ok(None);
    };
    if bytes.len() == RAW_KEY_LEN {
        Ok(Some(DbKeyState::Unprotected(
            bytes.try_into().expect("length checked above"),
        )))
    } else {
        Ok(Some(DbKeyState::PinProtected(bytes)))
    }
}

/// Recovers the raw database key from a [`DbKeyState::PinProtected`] blob.
/// A wrong PIN and a corrupted/tampered blob are indistinguishable to the
/// caller — both come back as [`StorageError::InvalidPin`], same as a
/// wrong SQLCipher key gives no more detail than "won't open."
pub fn unlock_with_pin(pin: &str, sealed: &[u8]) -> Result<[u8; RAW_KEY_LEN], StorageError> {
    let opened = backup::open(pin, sealed).map_err(|_| StorageError::InvalidPin)?;
    opened.try_into().map_err(|_| StorageError::InvalidPin)
}

/// Enables PIN protection: seals `raw_key` under `pin` and overwrites the
/// keystore entry with the sealed blob in place of the plain key. The
/// caller is responsible for having verified `raw_key` is in fact what's
/// currently stored (unprotected) under `label` — see
/// `bh-api::security::set_db_pin` for the intended call site.
pub fn set_pin(
    keystore: &Keystore,
    label: &str,
    pin: &str,
    raw_key: &[u8; RAW_KEY_LEN],
) -> Result<(), StorageError> {
    let sealed = backup::seal(pin, raw_key).map_err(|_| StorageError::InvalidPin)?;
    keystore.store_key(label, &sealed)
}

/// Disables PIN protection: requires the correct current `pin` to unseal
/// `sealed`, then restores the plain key in the keystore. Returns the
/// recovered key so the caller can keep using it without a second
/// keystore round-trip.
pub fn clear_pin(
    keystore: &Keystore,
    label: &str,
    pin: &str,
    sealed: &[u8],
) -> Result<[u8; RAW_KEY_LEN], StorageError> {
    let raw_key = unlock_with_pin(pin, sealed)?;
    keystore.store_key(label, &raw_key)?;
    Ok(raw_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn use_mock_keychain() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    fn fresh_keystore(name: &str) -> Keystore {
        use_mock_keychain();
        let dir =
            std::env::temp_dir().join(format!("bh-db-key-lock-test-{name}-{}", std::process::id()));
        Keystore::new(format!("blackhole-test-{name}"), dir)
    }

    #[test]
    fn unprotected_key_round_trips_through_state_detection() {
        let ks = fresh_keystore("unprotected");
        let key = [3u8; 32];
        ks.store_key("db-key", &key).unwrap();

        match load_db_key_state(&ks, "db-key").unwrap() {
            Some(DbKeyState::Unprotected(loaded)) => assert_eq!(loaded, key),
            _ => panic!("expected Unprotected"),
        }
    }

    #[test]
    fn no_stored_key_is_none() {
        let ks = fresh_keystore("absent");
        assert!(load_db_key_state(&ks, "db-key").unwrap().is_none());
    }

    #[test]
    fn setting_a_pin_replaces_the_raw_key_with_a_sealed_blob_that_unlocks_correctly() {
        let ks = fresh_keystore("set-pin");
        let key = [9u8; 32];
        ks.store_key("db-key", &key).unwrap();

        set_pin(&ks, "db-key", "1234", &key).unwrap();

        let sealed = match load_db_key_state(&ks, "db-key").unwrap() {
            Some(DbKeyState::PinProtected(blob)) => blob,
            _ => panic!("expected PinProtected after set_pin"),
        };
        assert_ne!(
            sealed.len(),
            32,
            "a sealed blob must not look like a raw key"
        );

        let recovered = unlock_with_pin("1234", &sealed).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn wrong_pin_does_not_unlock() {
        let ks = fresh_keystore("wrong-pin");
        let key = [1u8; 32];
        set_pin(&ks, "db-key", "correct-pin", &key).unwrap();
        let sealed = match load_db_key_state(&ks, "db-key").unwrap() {
            Some(DbKeyState::PinProtected(blob)) => blob,
            _ => panic!("expected PinProtected"),
        };
        assert!(matches!(
            unlock_with_pin("wrong-pin", &sealed),
            Err(StorageError::InvalidPin)
        ));
    }

    #[test]
    fn clear_pin_restores_the_plain_key_and_requires_the_right_pin() {
        let ks = fresh_keystore("clear-pin");
        let key = [5u8; 32];
        set_pin(&ks, "db-key", "my-pin", &key).unwrap();
        let sealed = match load_db_key_state(&ks, "db-key").unwrap() {
            Some(DbKeyState::PinProtected(blob)) => blob,
            _ => panic!("expected PinProtected"),
        };

        assert!(matches!(
            clear_pin(&ks, "db-key", "wrong", &sealed),
            Err(StorageError::InvalidPin)
        ));
        // A failed clear must not have touched the stored entry.
        assert!(matches!(
            load_db_key_state(&ks, "db-key").unwrap(),
            Some(DbKeyState::PinProtected(_))
        ));

        let recovered = clear_pin(&ks, "db-key", "my-pin", &sealed).unwrap();
        assert_eq!(recovered, key);
        match load_db_key_state(&ks, "db-key").unwrap() {
            Some(DbKeyState::Unprotected(loaded)) => assert_eq!(loaded, key),
            _ => panic!("expected Unprotected after clear_pin"),
        }
    }

    #[test]
    fn same_key_and_pin_produce_unlinkable_sealed_blobs() {
        let ks_a = fresh_keystore("unlink-a");
        let ks_b = fresh_keystore("unlink-b");
        let key = [8u8; 32];
        set_pin(&ks_a, "db-key", "same-pin", &key).unwrap();
        set_pin(&ks_b, "db-key", "same-pin", &key).unwrap();

        let a = match load_db_key_state(&ks_a, "db-key").unwrap() {
            Some(DbKeyState::PinProtected(blob)) => blob,
            _ => panic!("expected PinProtected"),
        };
        let b = match load_db_key_state(&ks_b, "db-key").unwrap() {
            Some(DbKeyState::PinProtected(blob)) => blob,
            _ => panic!("expected PinProtected"),
        };
        assert_ne!(
            a, b,
            "salt/nonce must be fresh per seal, even for identical inputs"
        );
    }
}
