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
//!
//! **Headless/server exception**: the Linux `keyring` backend is a pure
//! D-Bus Secret Service client (confirmed against `keyring` 3.x's actual
//! `CredentialBuilderApi::build()` path — the `linux-native-sync-persistent`
//! feature's in-kernel `keyutils` half is unreachable through
//! `Entry::new`), so it needs gnome-keyring/kwallet reachable over the
//! session bus. A bootstrap-node `daemon` running in a minimal container has
//! neither, and every `get_password`/`set_password` call would fail —
//! previously an unconditional `panic!` at startup, with no escape hatch
//! short of bundling a D-Bus + keyring-daemon sidecar in the image. Setting
//! `BLACKHOLE_KEYSTORE_BACKEND=file` switches this `Keystore` to
//! [`Backend::File`] instead: keys are hex-encoded into individual files
//! under `<data_dir>/keystore-file-backend/`, `chmod 600` on Unix. This is
//! **weaker than the OS keychain** — the key material sits on the same disk
//! as the SQLCipher ciphertext it protects, so anyone who can read that
//! directory (a misconfigured volume mount, a host-level compromise, an
//! unencrypted backup of the data dir) gets both. It exists purely so a
//! bootstrap node — which holds no real contacts/messages, only its own P2P
//! routing identity — can start unattended; it is deliberately not the
//! default and must be opted into explicitly. See `infra/README.md` for the
//! operational mitigations (dedicated volume, host disk encryption,
//! restrictive permissions) expected around this when it's used.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::StorageError;

/// Directory (relative to a profile's `data_dir`) holding one file per
/// label when [`Backend::File`] is active. Kept visually distinct from
/// ordinary config so it doesn't get mistaken for something safe to commit
/// or back up casually.
const FILE_BACKEND_SUBDIR: &str = "keystore-file-backend";

enum Backend {
    Os {
        service: String,
        // `keyring::Entry` handles are cached per label rather than
        // recreated on every call: real backends do a round-trip to the OS
        // credential store per `Entry::new`, and the point of this cache is
        // to avoid paying that on every read.
        entries: Mutex<HashMap<String, keyring::Entry>>,
    },
    File {
        dir: PathBuf,
    },
}

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
/// Label under which a *persisted* libp2p network identity keypair is
/// stored, when a caller opts into one (see
/// `bh_network::supervised::SupervisedNetwork::spawn_with_bootstrap_and_keypair`
/// and `daemon/src/main.rs`'s `BLACKHOLE_PERSISTENT_NETWORK_IDENTITY`).
/// Unused by default — an ordinary daemon generates a fresh random libp2p
/// identity every run, same as before this label existed; this is only
/// written when a deployment explicitly needs a stable `PeerId` across
/// restarts, e.g. a DHT bootstrap node.
pub const NETWORK_IDENTITY_KEY_LABEL: &str = "network-identity-key";
/// Label under which the *MLS group storage* database's SQLCipher key is
/// stored — again a distinct label/key from `DB_KEY_LABEL` and
/// `PAYMENTS_DB_KEY_LABEL`, for the same reason: `bh_crypto::mls_storage
/// ::PersistentMlsProvider` keeps group crypto state in its own SQLCipher
/// file, isolated from both the messaging and payments databases
/// (`docs/THREAT_MODEL.md` §3.2).
pub const MLS_DB_KEY_LABEL: &str = "mls-db-encryption-key";

pub struct Keystore {
    /// Directory containing the encrypted database and any other local
    /// state — what `panic_wipe` deletes from disk.
    data_dir: PathBuf,
    backend: Backend,
}

/// Reads the opt-in headless-backend switch. Anything other than exactly
/// `"file"` (case-insensitive) keeps the default OS-keychain backend —
/// unset, empty, or a typo all fail safe toward the stronger option rather
/// than silently downgrading key custody.
fn file_backend_requested() -> bool {
    std::env::var("BLACKHOLE_KEYSTORE_BACKEND").is_ok_and(|v| v.eq_ignore_ascii_case("file"))
}

impl Keystore {
    pub fn new(service: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let backend = if file_backend_requested() {
            tracing::warn!(
                dir = %data_dir.join(FILE_BACKEND_SUBDIR).display(),
                "BLACKHOLE_KEYSTORE_BACKEND=file: storing key material on disk \
                 next to the encrypted database instead of the OS keychain — \
                 weaker than the default, see keystore.rs module doc"
            );
            Backend::File {
                dir: data_dir.join(FILE_BACKEND_SUBDIR),
            }
        } else {
            Backend::Os {
                service: service.into(),
                entries: Mutex::new(HashMap::new()),
            }
        };
        Self { data_dir, backend }
    }

    fn with_entry<T>(
        &self,
        service: &str,
        entries: &Mutex<HashMap<String, keyring::Entry>>,
        label: &str,
        f: impl FnOnce(&keyring::Entry) -> keyring::Result<T>,
    ) -> Result<T, StorageError> {
        let mut entries = entries.lock().expect("keystore entry cache mutex poisoned");
        if !entries.contains_key(label) {
            entries.insert(label.to_string(), keyring::Entry::new(service, label)?);
        }
        let entry = entries.get(label).expect("just inserted");
        f(entry).map_err(Into::into)
    }

    fn file_backend_path(dir: &std::path::Path, label: &str) -> PathBuf {
        // Every label passed into this module is one of this file's own
        // `*_LABEL` constants — plain ASCII identifiers, never
        // user-controlled — so using one directly as a file name is safe.
        dir.join(label)
    }

    #[cfg(unix)]
    fn restrict_permissions(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    #[cfg(not(unix))]
    fn restrict_permissions(_path: &std::path::Path, _mode: u32) -> std::io::Result<()> {
        Ok(())
    }

    /// Stores a key in the platform's secure credential store, never in
    /// plaintext on disk — unless [`Backend::File`] is active, see the
    /// module doc for why that exists and what it trades away.
    pub fn store_key(&self, label: &str, key: &[u8]) -> Result<(), StorageError> {
        match &self.backend {
            Backend::Os { service, entries } => self.with_entry(service, entries, label, |e| {
                e.set_password(&hex::encode(key))
            }),
            Backend::File { dir } => {
                std::fs::create_dir_all(dir)?;
                Self::restrict_permissions(dir, 0o700)?;
                let path = Self::file_backend_path(dir, label);
                std::fs::write(&path, hex::encode(key))?;
                Self::restrict_permissions(&path, 0o600)?;
                Ok(())
            }
        }
    }

    pub fn load_key(&self, label: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let hex_key = match &self.backend {
            Backend::Os { service, entries } => {
                self.with_entry(service, entries, label, |e| match e.get_password() {
                    Ok(hex_key) => Ok(Some(hex_key)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(e) => Err(e),
                })?
            }
            Backend::File { dir } => {
                match std::fs::read_to_string(Self::file_backend_path(dir, label)) {
                    Ok(hex_key) => Some(hex_key),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        match hex_key {
            Some(hex_key) => Ok(Some(
                hex::decode(hex_key).map_err(|_| StorageError::NotFound)?,
            )),
            None => Ok(None),
        }
    }

    pub fn delete_key(&self, label: &str) -> Result<(), StorageError> {
        match &self.backend {
            Backend::Os { service, entries } => {
                self.with_entry(service, entries, label, |e| match e.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                    Err(e) => Err(e),
                })
            }
            Backend::File { dir } => {
                match std::fs::remove_file(Self::file_backend_path(dir, label)) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
        }
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

    // `BLACKHOLE_KEYSTORE_BACKEND` is process-wide state, same reasoning as
    // `bh-calls::transport`'s own `ENV_LOCK` for `BLACKHOLE_STUN_SERVERS`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard {
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set_file_backend() -> Self {
            let previous = std::env::var("BLACKHOLE_KEYSTORE_BACKEND").ok();
            // SAFETY: caller holds `ENV_LOCK` for the guard's whole lifetime.
            unsafe { std::env::set_var("BLACKHOLE_KEYSTORE_BACKEND", "file") };
            Self { previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => unsafe { std::env::set_var("BLACKHOLE_KEYSTORE_BACKEND", v) },
                None => unsafe { std::env::remove_var("BLACKHOLE_KEYSTORE_BACKEND") },
            }
        }
    }

    #[test]
    fn file_backend_store_and_load_roundtrip() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::set_file_backend();
        let dir = std::env::temp_dir().join(format!(
            "bh-keystore-file-backend-test-{}",
            std::process::id()
        ));
        let ks = Keystore::new("blackhole-test-file-backend", &dir);
        let key = [9u8; 32];
        ks.store_key(DB_KEY_LABEL, &key).unwrap();
        assert_eq!(ks.load_key(DB_KEY_LABEL).unwrap(), Some(key.to_vec()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.join(FILE_BACKEND_SUBDIR).join(DB_KEY_LABEL);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        ks.delete_key(DB_KEY_LABEL).unwrap();
        assert_eq!(ks.load_key(DB_KEY_LABEL).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_backend_panic_wipe_removes_keys_and_data_dir() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::set_file_backend();
        let dir = std::env::temp_dir().join(format!(
            "bh-keystore-file-backend-wipe-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blackhole.db"), b"not real data").unwrap();

        let ks = Keystore::new("blackhole-test-file-backend-wipe", &dir);
        ks.store_key(DB_KEY_LABEL, &[1u8; 32]).unwrap();
        ks.store_key(DEVICE_SIGNING_KEY_LABEL, &[2u8; 32]).unwrap();
        ks.panic_wipe().unwrap();
        assert!(!dir.exists());
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
