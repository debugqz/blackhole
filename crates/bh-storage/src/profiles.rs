//! Multi-account: each identity/profile gets a fully separate SQLCipher
//! database file *and* a separate platform-keystore service name — the
//! same isolation model the project already uses to keep payments and
//! messaging data apart (SPEC.md §12, CLAUDE.md non-negotiables). There is
//! no shared key material and no shared database between profiles, so a
//! compromise of one profile's key never exposes another's, by
//! construction rather than by access-control policy.
//!
//! The profile *list* itself (id, display name, creation time) is not
//! sensitive — knowing "this device has 2 blackhole profiles named X and
//! Y" is comparable to seeing app icons on a home screen — so it's kept as
//! a small plaintext manifest file, deliberately never merged into any
//! profile's own encrypted database (that would defeat the whole point of
//! keeping them separate). See `docs/THREAT_MODEL.md` for the residual
//! metadata this implies.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::keystore::Keystore;
use crate::StorageError;

const MANIFEST_FILE: &str = "profiles.json";
const DB_FILE_NAME: &str = "blackhole.db";
const PAYMENTS_DB_FILE_NAME: &str = "payments.db";
const MLS_DB_FILE_NAME: &str = "mls.db";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub id: String,
    pub display_name: String,
    pub created_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    profiles: Vec<ProfileMeta>,
}

/// Manages the on-disk layout of multiple isolated profiles under one
/// `root_dir`. Doesn't itself open any database — callers use
/// [`ProfileManager::profile_db_path`] and [`ProfileManager::keystore_for`]
/// with `bh_storage::Database::open` and the rest of this crate exactly as
/// they would for a single-profile install.
pub struct ProfileManager {
    root_dir: PathBuf,
    keystore_service_prefix: String,
    // Caches one `Keystore` per profile for the manager's lifetime, rather
    // than constructing a fresh one on every call: real backends do a
    // round-trip to the OS credential store per `keyring::Entry::new`
    // (see `keystore.rs`), and — more subtly — a daemon that creates a
    // profile in one HTTP request and activates it in a later one needs
    // both requests to resolve to the *same* keystore object for that
    // profile, not just the same (service, label) identity, since nothing
    // here assumes every credential backend a platform might use persists
    // by identity across independently-constructed handles.
    keystores: Mutex<HashMap<String, Arc<Keystore>>>,
}

impl ProfileManager {
    pub fn new(root_dir: impl Into<PathBuf>, keystore_service_prefix: impl Into<String>) -> Self {
        Self {
            root_dir: root_dir.into(),
            keystore_service_prefix: keystore_service_prefix.into(),
            keystores: Mutex::new(HashMap::new()),
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.root_dir.join(MANIFEST_FILE)
    }

    /// Loads the manifest, pruning any entry whose data directory has
    /// vanished. The only way that can happen is [`delete_profile`]
    /// crashing between `panic_wipe` removing a profile's directory and
    /// the manifest write that removes its entry — without this
    /// self-heal, `Database::open`/`PaymentsDatabase::open` would
    /// silently create a fresh, empty database for what the user was told
    /// was a deleted profile, since both `open` on a missing path just
    /// creates one. Pruning here means a crash mid-delete can't resurrect
    /// the profile; it just finishes disappearing on the next access.
    ///
    /// [`delete_profile`]: ProfileManager::delete_profile
    fn load_manifest(&self) -> Result<Manifest, StorageError> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(Manifest::default());
        }
        let bytes = fs::read(&path)?;
        let mut manifest: Manifest = serde_json::from_slice(&bytes)?;
        let before = manifest.profiles.len();
        manifest
            .profiles
            .retain(|p| self.profile_data_dir(&p.id).exists());
        if manifest.profiles.len() != before {
            self.save_manifest(&manifest)?;
        }
        Ok(manifest)
    }

    fn save_manifest(&self, manifest: &Manifest) -> Result<(), StorageError> {
        fs::create_dir_all(&self.root_dir)?;
        let bytes = serde_json::to_vec_pretty(manifest)?;
        fs::write(self.manifest_path(), bytes)?;
        Ok(())
    }

    pub fn list_profiles(&self) -> Result<Vec<ProfileMeta>, StorageError> {
        Ok(self.load_manifest()?.profiles)
    }

    pub fn get_profile(&self, profile_id: &str) -> Result<Option<ProfileMeta>, StorageError> {
        Ok(self
            .load_manifest()?
            .profiles
            .into_iter()
            .find(|p| p.id == profile_id))
    }

    /// Creates a new, empty profile: allocates a random id, creates its
    /// data directory, and records it in the manifest. Does **not** create
    /// the SQLCipher database or keystore entries — the caller does that
    /// via [`ProfileManager::profile_db_path`]/[`ProfileManager::keystore_for`]
    /// once it has a fresh encryption key to hand `Database::open`.
    pub fn create_profile(
        &self,
        display_name: impl Into<String>,
        created_at: i64,
    ) -> Result<ProfileMeta, StorageError> {
        let mut manifest = self.load_manifest()?;
        let meta = ProfileMeta {
            id: Uuid::new_v4().to_string(),
            display_name: display_name.into(),
            created_at,
        };
        fs::create_dir_all(self.profile_data_dir(&meta.id))?;
        manifest.profiles.push(meta.clone());
        self.save_manifest(&manifest)?;
        Ok(meta)
    }

    pub fn rename_profile(
        &self,
        profile_id: &str,
        display_name: impl Into<String>,
    ) -> Result<(), StorageError> {
        let mut manifest = self.load_manifest()?;
        match manifest.profiles.iter_mut().find(|p| p.id == profile_id) {
            Some(profile) => profile.display_name = display_name.into(),
            None => return Err(StorageError::NotFound),
        }
        self.save_manifest(&manifest)
    }

    pub fn profile_data_dir(&self, profile_id: &str) -> PathBuf {
        self.root_dir.join("profiles").join(profile_id)
    }

    pub fn profile_db_path(&self, profile_id: &str) -> PathBuf {
        self.profile_data_dir(profile_id).join(DB_FILE_NAME)
    }

    /// Path to this profile's *payments* database — a separate SQLCipher
    /// file from [`ProfileManager::profile_db_path`], opened with a
    /// separate key (see `keystore::PAYMENTS_DB_KEY_LABEL`). Same
    /// per-profile isolation this module already gives identities, applied
    /// a second time between a profile's messages and its purchases
    /// (SPEC.md §12, CLAUDE.md non-negotiables).
    pub fn payments_db_path(&self, profile_id: &str) -> PathBuf {
        self.profile_data_dir(profile_id)
            .join(PAYMENTS_DB_FILE_NAME)
    }

    /// Path to this profile's *MLS group storage* database — a separate
    /// SQLCipher file from both [`ProfileManager::profile_db_path`] and
    /// [`ProfileManager::payments_db_path`], opened with its own key (see
    /// `keystore::MLS_DB_KEY_LABEL`) via
    /// `bh_crypto::mls_storage::PersistentMlsProvider::open`. Nested under
    /// [`ProfileManager::profile_data_dir`] like the other two, so
    /// [`ProfileManager::delete_profile`] already cleans it up for free.
    pub fn mls_db_path(&self, profile_id: &str) -> PathBuf {
        self.profile_data_dir(profile_id).join(MLS_DB_FILE_NAME)
    }

    fn keystore_service_name(&self, profile_id: &str) -> String {
        format!("{}-{}", self.keystore_service_prefix, profile_id)
    }

    /// A `Keystore` scoped to this one profile — a distinct OS credential-
    /// store service name per profile, so the platform keychain itself
    /// keeps them apart (SPEC.md §7). Returns the same cached instance on
    /// repeated calls for the same `profile_id`.
    pub fn keystore_for(&self, profile_id: &str) -> Arc<Keystore> {
        let mut keystores = self
            .keystores
            .lock()
            .expect("profile keystore cache mutex poisoned");
        keystores
            .entry(profile_id.to_string())
            .or_insert_with(|| {
                Arc::new(Keystore::new(
                    self.keystore_service_name(profile_id),
                    self.profile_data_dir(profile_id),
                ))
            })
            .clone()
    }

    /// Irreversibly wipes one profile: its keys (via that profile's own
    /// `Keystore::panic_wipe`, which also removes its data directory) and
    /// its manifest entry. Other profiles are untouched. Like
    /// `Keystore::panic_wipe`, this has no undo — the caller must have
    /// already confirmed with the user.
    pub fn delete_profile(&self, profile_id: &str) -> Result<(), StorageError> {
        self.keystore_for(profile_id).panic_wipe()?;
        self.keystores
            .lock()
            .expect("profile keystore cache mutex poisoned")
            .remove(profile_id);
        let mut manifest = self.load_manifest()?;
        manifest.profiles.retain(|p| p.id != profile_id);
        self.save_manifest(&manifest)
    }
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

    fn test_manager(name: &str) -> (ProfileManager, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("bh-profiles-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        (
            ProfileManager::new(&dir, format!("blackhole-test-profiles-{name}")),
            dir,
        )
    }

    #[test]
    fn new_manager_has_no_profiles() {
        let (mgr, _dir) = test_manager("empty");
        assert!(mgr.list_profiles().unwrap().is_empty());
    }

    #[test]
    fn create_list_rename_and_delete_profiles() {
        use_mock_keychain();
        let (mgr, _dir) = test_manager("crud");

        let alice = mgr.create_profile("Alice", 100).unwrap();
        let work = mgr.create_profile("Work", 200).unwrap();
        assert!(mgr.profile_data_dir(&alice.id).exists());

        let listed = mgr.list_profiles().unwrap();
        assert_eq!(listed.len(), 2);

        mgr.rename_profile(&alice.id, "Alice (personal)").unwrap();
        let alice_reloaded = mgr.get_profile(&alice.id).unwrap().unwrap();
        assert_eq!(alice_reloaded.display_name, "Alice (personal)");

        mgr.delete_profile(&work.id).unwrap();
        assert!(mgr.get_profile(&work.id).unwrap().is_none());
        assert!(!mgr.profile_data_dir(&work.id).exists());
        assert_eq!(mgr.list_profiles().unwrap().len(), 1);
    }

    /// Regression test: simulates `delete_profile` crashing after
    /// `panic_wipe` removes the profile's directory but before the
    /// manifest write that removes its entry. `load_manifest` must
    /// self-heal — otherwise the profile would keep showing up in
    /// `list_profiles`/`get_profile` pointing at a directory that no
    /// longer exists, and reopening it would silently create a fresh,
    /// empty database instead of surfacing that it was deleted.
    #[test]
    fn a_manifest_entry_whose_directory_vanished_is_pruned_on_next_load() {
        let (mgr, _dir) = test_manager("crash-mid-delete");
        let a = mgr.create_profile("A", 0).unwrap();
        let b = mgr.create_profile("B", 0).unwrap();

        // Simulate the crash: directory gone, manifest entry still there.
        fs::remove_dir_all(mgr.profile_data_dir(&a.id)).unwrap();

        assert!(mgr.get_profile(&a.id).unwrap().is_none());
        let listed = mgr.list_profiles().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, b.id);
    }

    #[test]
    fn profiles_get_distinct_db_paths_and_keystore_services() {
        let (mgr, _dir) = test_manager("isolation");
        let a = mgr.create_profile("A", 0).unwrap();
        let b = mgr.create_profile("B", 0).unwrap();

        assert_ne!(mgr.profile_db_path(&a.id), mgr.profile_db_path(&b.id));
        assert_ne!(
            mgr.keystore_service_name(&a.id),
            mgr.keystore_service_name(&b.id)
        );
    }

    #[test]
    fn deleting_one_profile_does_not_touch_another() {
        use_mock_keychain();
        let (mgr, _dir) = test_manager("delete-isolation");
        let a = mgr.create_profile("A", 0).unwrap();
        let b = mgr.create_profile("B", 0).unwrap();

        // Keep both `Keystore` handles alive across the delete: the mock
        // credential backend (unlike a real OS keychain) only persists a
        // stored secret for the lifetime of the `Entry`/`Keystore` object
        // that created it, not by (service, label) identity alone — so this
        // is also exercising the realistic case of "a long-lived daemon
        // process holding both profiles' keystores open at once."
        let keystore_a = mgr.keystore_for(&a.id);
        let keystore_b = mgr.keystore_for(&b.id);
        keystore_a
            .store_key("db-encryption-key", &[9u8; 32])
            .unwrap();
        keystore_b
            .store_key("db-encryption-key", &[8u8; 32])
            .unwrap();

        mgr.delete_profile(&a.id).unwrap();

        assert!(!mgr.profile_data_dir(&a.id).exists());
        assert!(mgr.profile_data_dir(&b.id).exists());
        assert_eq!(
            keystore_b.load_key("db-encryption-key").unwrap(),
            Some(vec![8u8; 32])
        );
    }
}
