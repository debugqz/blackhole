use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use bh_storage::{keystore::Keystore, profiles::ProfileManager, Database};

use crate::calls::CallRegistry;

/// The database/keystore/data-dir triple for whichever profile is
/// currently active. Multi-account (SPEC.md §12-style isolation, applied
/// to identities rather than payments) means the daemon can hold several
/// of these on disk at once via `ProfileManager`, but only ever has one
/// *active* at a time — switching profiles swaps this out from under
/// `AppState` rather than the daemon restarting.
#[derive(Clone)]
pub struct ProfileSession {
    pub profile_id: String,
    pub db: Database,
    pub keystore: Arc<Keystore>,
    pub data_dir: PathBuf,
}

/// Shared daemon state handed to every request handler. Cloned per
/// request via `axum::extract::State<Arc<AppState>>` — cheap, since the
/// active profile's `Database` wraps a connection pool internally and the
/// rest is behind an `Arc`/lock.
pub struct AppState {
    /// Manages the on-disk layout of every profile this install knows
    /// about (SPEC.md §12 isolation model, applied to identities).
    pub manager: ProfileManager,
    active: RwLock<ProfileSession>,
    /// In-memory, not-per-profile call state (see `calls.rs` module doc
    /// for why calls live outside the profile/database split).
    pub calls: Arc<CallRegistry>,
}

impl AppState {
    pub fn new(manager: ProfileManager, active: ProfileSession) -> Self {
        Self {
            manager,
            active: RwLock::new(active),
            calls: Arc::new(CallRegistry::default()),
        }
    }

    fn read_active(&self) -> ProfileSession {
        self.active
            .read()
            .expect("active profile lock poisoned")
            .clone()
    }

    pub fn db(&self) -> Database {
        self.read_active().db
    }

    pub fn keystore(&self) -> Arc<Keystore> {
        self.read_active().keystore
    }

    pub fn data_dir(&self) -> PathBuf {
        self.read_active().data_dir
    }

    pub fn active_profile_id(&self) -> String {
        self.read_active().profile_id
    }

    /// Swaps in a different profile's session — e.g. after the user picks
    /// a different profile to use. Every subsequent request sees the new
    /// profile's (and only the new profile's) data; nothing from the
    /// previous profile stays reachable through `AppState` afterwards.
    pub fn switch_active(&self, session: ProfileSession) {
        *self.active.write().expect("active profile lock poisoned") = session;
    }
}
