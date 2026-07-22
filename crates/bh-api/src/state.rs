use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bh_crypto::auth::PasskeyManager;
use bh_crypto::mls_storage::PersistentMlsProvider;
use bh_crypto::CryptoError;
use bh_network::supervised::SupervisedNetwork;
use bh_storage::{keystore::Keystore, profiles::ProfileManager, Database, PaymentsDatabase};
use tokio::task::JoinHandle;
use webauthn_rs::prelude::Url;

use crate::calls::CallRegistry;
use crate::device_link::DeviceLinkRegistry;
use crate::device_sync::DeviceSyncRegistry;
use crate::groups::GroupRegistry;
use crate::local_auth::LocalAuthRegistry;
use crate::presence::PresenceRegistry;

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
    /// The cosmetic-store payments database — a physically separate
    /// SQLCipher file/key from `db` (see `bh_storage::payments_db`).
    /// CLAUDE.md non-negotiable: never join or query this alongside `db`
    /// in the same handler; the only thing that ever crosses is the opaque
    /// entitlement token handled in `crates/bh-api/src/cosmetics.rs`.
    pub payments_db: PaymentsDatabase,
    pub keystore: Arc<Keystore>,
    pub data_dir: PathBuf,
    /// Path + key for this profile's persistent MLS group-storage database
    /// (`bh_crypto::mls_storage::PersistentMlsProvider` — THREAT_MODEL.md
    /// §3.2). Kept as path+key rather than an already-open provider so
    /// `ProfileSession` can stay `Clone`: a `PersistentMlsProvider` wraps a
    /// `rusqlite::Connection`, which isn't `Clone`. [`AppState::
    /// mls_provider`] opens a fresh one from these on demand — cheap
    /// relative to an HTTP request, and it means nothing here holds a
    /// connection open across profile switches.
    pub mls_db_path: PathBuf,
    pub mls_db_key: [u8; 32],
    /// Live MLS group/member handles for this profile
    /// (`crate::groups::GroupRegistry`), for the daemon's process
    /// lifetime. Profile-scoped like `db`/`payments_db` rather than
    /// daemon-lifetime like `calls`/`device_link`: it gets swapped (fresh,
    /// empty) on every `switch_active`, same as every other per-profile
    /// field here, so one profile's in-flight group ceremonies can never
    /// leak into another's.
    pub groups: Arc<GroupRegistry>,
    /// Live (in-memory-only) Double Ratchet session state for linked
    /// devices that have synced this process lifetime (`device_sync.rs`).
    /// Profile-scoped like `groups`, not daemon-lifetime like
    /// `calls`/`device_link`: linked devices belong to a specific
    /// identity, so a profile switch must start with a clean slate rather
    /// than leaking one profile's shadow ratchet sessions into another's.
    pub device_sync: Arc<DeviceSyncRegistry>,
    /// Live (in-memory-only) "typing…" presence state (`presence.rs`).
    /// Profile-scoped like `groups`/`device_sync` — conversation ids are
    /// per-profile, so a profile switch must start with a clean slate.
    pub presence: Arc<PresenceRegistry>,
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
    /// The self-destructing-message sweeper (`bh_storage::expiry`) for
    /// whichever profile is currently active. Previously spawned once in
    /// `daemon/src/main.rs` against the startup profile and never moved —
    /// switching profiles at runtime left it purging the *old* profile's
    /// database while the newly-active one accrued expired messages
    /// unswept until the next daemon restart (THREAT_MODEL.md, "known
    /// limitation" on the sweeper). Owning it here instead means
    /// `switch_active` can restart it against the new profile's `db`.
    expiry_sweeper: Mutex<Option<JoinHandle<()>>>,
    /// How often the sweeper checks — normally [`EXPIRY_SWEEP_INTERVAL`];
    /// overridable via [`AppState::with_expiry_sweep_interval`] so tests
    /// can observe a sweep without waiting a real 60 seconds.
    expiry_sweep_interval: Duration,
    /// In-memory, not-per-profile call state (see `calls.rs` module doc
    /// for why calls live outside the profile/database split).
    pub calls: Arc<CallRegistry>,
    /// In-memory device-linking ceremony state (see `device_link.rs`).
    pub device_link: Arc<DeviceLinkRegistry>,
    /// In-memory passkey/TOTP enrollment ceremony state (see
    /// `local_auth.rs`).
    pub local_auth: Arc<LocalAuthRegistry>,
    /// This daemon's WebAuthn relying party, built once at startup from
    /// `BLACKHOLE_RP_ID`/`BLACKHOLE_RP_ORIGIN` (defaulting to the loopback
    /// dev daemon's own id/origin — see `local_auth.rs` module doc for why
    /// the packaged Tauri webview's real origin needs these set per
    /// platform instead).
    pub passkey: Arc<PasskeyManager>,
    /// `bh-network`'s Node/DHT/Mailbox stack (SPEC.md §5), self-healing
    /// across any swarm event loop panic (`docs/THREAT_MODEL.md` §3.10) —
    /// see `bh_network::supervised`. `None` unless the daemon explicitly
    /// attaches one via [`AppState::with_network`]; every integration
    /// test in this crate constructs `AppState` without a real network
    /// stack (no need to bind a TCP listener per test) and leaves this
    /// `None`. `network.rs`'s `GET /network/status` reports `enabled:
    /// false` rather than erroring in that case.
    pub network: Option<SupervisedNetwork>,
    /// Shared secret every request to this loopback API must present as
    /// `Authorization: Bearer <api_token>` (`server.rs`'s
    /// `require_bearer_token` middleware). Closes the gap the module doc
    /// on `reject_browser_origin` already names: binding to loopback only
    /// defends against a browser tab, not another local process/malware
    /// on the same machine, which could otherwise reach every route here
    /// with nothing but a TCP connection. Generated fresh per process
    /// unless `BLACKHOLE_API_TOKEN` is set (tests fix a known value this
    /// way — see `crates/bh-api/tests/api_smoke.rs`'s `use_mock_keychain`);
    /// `daemon/src/main.rs` reads this back after construction and
    /// persists it to a `0600`-permissioned file the Tauri client reads.
    pub api_token: String,
}

/// How often the expiry sweeper checks for self-destructing messages past
/// their `expires_at` — matches the interval `daemon/src/main.rs` used to
/// pass in directly before this moved into `AppState`.
const EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

impl AppState {
    pub fn new(manager: ProfileManager, active: ProfileSession) -> Self {
        Self::with_expiry_sweep_interval(manager, active, EXPIRY_SWEEP_INTERVAL)
    }

    /// As [`new`](Self::new), but with an overridable expiry-sweep
    /// interval — the real constructor tests should use when they need to
    /// observe a sweep happening without waiting a real 60 seconds for it.
    pub fn with_expiry_sweep_interval(
        manager: ProfileManager,
        active: ProfileSession,
        expiry_sweep_interval: Duration,
    ) -> Self {
        let rp_id = std::env::var("BLACKHOLE_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let rp_origin = std::env::var("BLACKHOLE_RP_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:47853".to_string());
        let rp_origin_url = Url::parse(&rp_origin).expect("invalid BLACKHOLE_RP_ORIGIN");
        let passkey = PasskeyManager::new(&rp_id, &rp_origin_url)
            .expect("invalid BLACKHOLE_RP_ID/BLACKHOLE_RP_ORIGIN for passkey relying party");
        let api_token = std::env::var("BLACKHOLE_API_TOKEN").unwrap_or_else(|_| {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).expect("system RNG unavailable");
            hex::encode(bytes)
        });

        let state = Self {
            manager,
            active: RwLock::new(active),
            expiry_sweeper: Mutex::new(None),
            expiry_sweep_interval,
            calls: Arc::new(CallRegistry::default()),
            device_link: Arc::new(DeviceLinkRegistry::default()),
            local_auth: Arc::new(LocalAuthRegistry::default()),
            passkey: Arc::new(passkey),
            network: None,
            api_token,
        };
        state.restart_expiry_sweeper();
        state
    }

    /// Attaches an already-spawned, self-supervising network stack —
    /// called once from `daemon/src/main.rs` after `SupervisedNetwork::
    /// spawn` (an async, fallible operation `AppState::new` itself can't
    /// do, staying consistent with how `ProfileSession`'s own DB/keystore
    /// I/O happens in the caller, not inside this constructor).
    pub fn with_network(mut self, network: SupervisedNetwork) -> Self {
        self.network = Some(network);
        self
    }

    /// (Re)spawns the expiry sweeper against whichever profile is
    /// currently active, aborting whatever sweeper was previously running
    /// (if any) — exactly one sweeper is ever purging messages at a time,
    /// and it always tracks the active profile, including across
    /// `switch_active`. Requires a Tokio runtime to be current (true of
    /// every real caller: `daemon/src/main.rs`'s `#[tokio::main]`, and
    /// `#[tokio::test]` in the integration tests).
    fn restart_expiry_sweeper(&self) {
        let active = self.read_active();
        let db = active.db;
        let data_dir = active.data_dir;
        let handle = bh_storage::expiry::spawn_expiry_sweeper(
            db,
            self.expiry_sweep_interval,
            now,
            move |orphaned_content_hashes| {
                for content_hash in orphaned_content_hashes {
                    let dir = crate::files::chunk_dir(&data_dir, &content_hash);
                    tracing::debug!(%content_hash, path = %dir.display(), "removing orphaned attachment chunk dir");
                    // Ignoring the error matches `files::delete_attachment`'s
                    // existing `remove_dir_all` call: a missing directory
                    // isn't a bug worth surfacing on an unattended timer.
                    let _ = std::fs::remove_dir_all(&dir);
                }
            },
        );
        let mut guard = self
            .expiry_sweeper
            .lock()
            .expect("expiry sweeper handle lock poisoned");
        if let Some(old) = guard.replace(handle) {
            old.abort();
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

    pub fn payments_db(&self) -> PaymentsDatabase {
        self.read_active().payments_db
    }

    pub fn keystore(&self) -> Arc<Keystore> {
        self.read_active().keystore
    }

    pub fn data_dir(&self) -> PathBuf {
        self.read_active().data_dir
    }

    /// The active profile's live MLS group/member registry (see
    /// `groups.rs`) — profile-scoped, unlike `calls`/`device_link`, so
    /// this reads through the active session rather than being a plain
    /// `AppState` field.
    pub fn groups(&self) -> Arc<GroupRegistry> {
        self.read_active().groups
    }

    /// The active profile's live device-sync ratchet-session registry
    /// (see `device_sync.rs`) — profile-scoped for the same reason as
    /// `groups()`.
    pub fn device_sync(&self) -> Arc<DeviceSyncRegistry> {
        self.read_active().device_sync
    }

    /// The active profile's live presence registry (see `presence.rs`) —
    /// profile-scoped for the same reason as `groups()`/`device_sync()`.
    pub fn presence(&self) -> Arc<PresenceRegistry> {
        self.read_active().presence
    }

    /// Opens a fresh handle to the active profile's persistent MLS
    /// group-storage database (THREAT_MODEL.md §3.2). Cheap enough to call
    /// per-request: it's a local SQLCipher connection, not a network
    /// round-trip, and callers only need it for the handful of group
    /// membership operations, not every request.
    pub fn mls_provider(&self) -> Result<PersistentMlsProvider, CryptoError> {
        let active = self.read_active();
        PersistentMlsProvider::open(&active.mls_db_path, &active.mls_db_key)
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
        self.restart_expiry_sweeper();
    }
}
