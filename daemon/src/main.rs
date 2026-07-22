//! The Blackhole daemon: runs on localhost, owns all cryptographic keys and
//! the connection to the P2P network. UI clients talk only to this daemon's
//! localhost API, never directly to the network. See `docs/SPEC.md` §6.
//!
//! `bh-network` (DHT/onion/mailbox) is spawned below via
//! `bh_network::supervised::SupervisedNetwork`, which self-heals if the
//! swarm event loop dies (e.g. the yamux CVE panic — `docs/THREAT_MODEL.md`
//! §3.10) rather than leaving networking silently dead until a manual
//! restart. It's reachable through `AppState::network` and, today, only
//! exposed read-only via `GET /network/status` — nothing yet rewires
//! `bh-api::conversations`' message send/list handlers to actually go over
//! it instead of the local database directly; that's a separate follow-up.

use std::sync::Arc;
use std::time::Duration;

use bh_api::device_sync::DeviceSyncRegistry;
use bh_api::groups::GroupRegistry;
use bh_api::presence::PresenceRegistry;
use bh_api::state::ProfileSession;
use bh_api::AppState;
use bh_crypto::mls_storage::PersistentMlsProvider;
use bh_network::supervised::SupervisedNetwork;
use bh_storage::db_key_lock::{self, DbKeyState};
use bh_storage::keystore::{Keystore, DB_KEY_LABEL, MLS_DB_KEY_LABEL, PAYMENTS_DB_KEY_LABEL};
use bh_storage::profiles::ProfileManager;
use bh_storage::{Database, PaymentsDatabase};

const DEFAULT_PORT: u16 = 47_853;
const SERVICE_NAME: &str = "blackhole";
const DEFAULT_PROFILE_NAME: &str = "Default";
/// All interfaces, OS-assigned port — a P2P listener needs to actually be
/// reachable by other peers, unlike the HTTP API (`ApiServer`, loopback
/// only by design, SPEC.md §6). Overridable via `BLACKHOLE_NETWORK_
/// LISTEN_ADDR` for environments (like this one) where binding all
/// interfaces isn't appropriate.
const DEFAULT_NETWORK_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
const NETWORK_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

fn data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("BLACKHOLE_DATA_DIR") {
        return dir.into();
    }
    dirs::data_dir()
        .expect("no platform data directory available")
        .join("blackhole")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

/// Loads a SQLCipher database key from the platform keystore under `label`,
/// generating and storing a fresh one on first run. Never logged, never
/// persisted outside the keystore (SPEC.md §7). Shared by the messaging
/// database (`DB_KEY_LABEL`) and the payments database
/// (`PAYMENTS_DB_KEY_LABEL`) — same derivation, two independent keys, so a
/// leak of one never yields the other.
///
/// If a PIN has been set for this label (`POST /security/db-pin` — see
/// `bh_storage::db_key_lock`, THREAT_MODEL.md §3.7), the stored entry is a
/// sealed blob rather than the raw key, and `BLACKHOLE_DB_PIN` must supply
/// the PIN to unseal it. Deliberately fails loudly rather than either
/// silently minting a brand-new key (which would look like "it just
/// works" but actually orphans the real encrypted database) or silently
/// starting unprotected.
fn load_or_create_db_key(keystore: &Keystore, label: &str) -> [u8; 32] {
    match db_key_lock::load_db_key_state(keystore, label).expect("keystore access failed") {
        Some(DbKeyState::Unprotected(key)) => key,
        Some(DbKeyState::PinProtected(sealed)) => {
            let pin = std::env::var("BLACKHOLE_DB_PIN").unwrap_or_else(|_| {
                panic!(
                    "database key '{label}' is PIN-protected but BLACKHOLE_DB_PIN is not set; \
                     the daemon cannot start without it (docs/THREAT_MODEL.md §3.7)"
                )
            });
            db_key_lock::unlock_with_pin(&pin, &sealed)
                .expect("BLACKHOLE_DB_PIN did not unlock the database key")
        }
        None => {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).expect("system RNG unavailable");
            keystore
                .store_key(label, &key)
                .expect("failed to store new db key in platform keystore");
            key
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let port = std::env::var("BLACKHOLE_DAEMON_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir).expect("failed to create data directory");

    // Multi-account (SPEC.md §12-style isolation applied to identities):
    // every profile gets its own SQLCipher file and keystore service name
    // under `data_dir` (see `bh_storage::profiles`). On first run there are
    // no profiles yet, so one "Default" profile is created transparently —
    // existing single-profile installs feel unchanged.
    let manager = ProfileManager::new(data_dir.clone(), SERVICE_NAME);
    let mut profiles = manager
        .list_profiles()
        .expect("failed to read profile manifest");
    if profiles.is_empty() {
        let default = manager
            .create_profile(DEFAULT_PROFILE_NAME, now())
            .expect("failed to create default profile");
        profiles.push(default);
    }
    let active_profile_id = std::env::var("BLACKHOLE_ACTIVE_PROFILE")
        .ok()
        .unwrap_or_else(|| profiles[0].id.clone());

    let keystore = manager.keystore_for(&active_profile_id);
    let db_key = load_or_create_db_key(&keystore, DB_KEY_LABEL);
    let db = Database::open(manager.profile_db_path(&active_profile_id), &db_key)
        .expect("failed to open database");

    // Cosmetic-store payments database (SPEC.md §12): a separate SQLCipher
    // file and key from `db` — see `bh_storage::payments_db` for why.
    let payments_db_key = load_or_create_db_key(&keystore, PAYMENTS_DB_KEY_LABEL);
    let payments_db = PaymentsDatabase::open(
        manager.payments_db_path(&active_profile_id),
        &payments_db_key,
    )
    .expect("failed to open payments database");
    bh_api::cosmetics::seed_default_catalog(&payments_db).expect("failed to seed cosmetic catalog");

    // This profile's MLS group-storage key/database (THREAT_MODEL.md §3.2)
    // — a third independent key from `db_key`/`payments_db_key`. Opened
    // once here to fail loudly on a bad key, the same way `db`/
    // `payments_db` do above, even though `ProfileSession` only keeps the
    // path+key (see that struct's doc comment for why).
    let mls_db_key = load_or_create_db_key(&keystore, MLS_DB_KEY_LABEL);
    let mls_db_path = manager.mls_db_path(&active_profile_id);
    PersistentMlsProvider::open(&mls_db_path, &mls_db_key)
        .expect("failed to open MLS group-storage database");

    // P2P network stack (SPEC.md §5) — self-supervising, see this file's
    // module doc and `bh_network::supervised` for why. `AppState::network`
    // is `Option<SupervisedNetwork>` precisely so this can fail without
    // taking the daemon down with it: everything actually in use today
    // (contacts, messages, panic wipe, ...) goes through the local
    // database, not the network stack, so a bind failure here (port
    // exhaustion, a sandboxed/firewalled environment — exactly what
    // `BLACKHOLE_NETWORK_LISTEN_ADDR` exists to work around) shouldn't be
    // a single point of failure for the whole local HTTP API.
    let network_listen_addr = std::env::var("BLACKHOLE_NETWORK_LISTEN_ADDR")
        .unwrap_or_else(|_| DEFAULT_NETWORK_LISTEN_ADDR.to_string());
    let network =
        match SupervisedNetwork::spawn(network_listen_addr, NETWORK_HEALTH_CHECK_INTERVAL).await {
            Ok(network) => {
                tracing::info!(peer_id = %network.peer_id(), "P2P network stack started");
                Some(network)
            }
            Err(err) => {
                tracing::error!(
                    %err,
                    "failed to start P2P network stack — continuing without it; \
                     local API/database are unaffected"
                );
                None
            }
        };

    // Self-destructing messages (SPEC.md §7) get swept on a timer rather
    // than only purged lazily on read. `AppState::new` spawns this against
    // whichever profile is active, and `AppState::switch_active` (used by
    // `POST /profiles/:id/activate`) restarts it against the newly-active
    // profile — see `bh_api::state` for why this moved out of here.
    let data_dir_for_profile = manager.profile_data_dir(&active_profile_id);
    let mut state = AppState::new(
        manager,
        ProfileSession {
            profile_id: active_profile_id,
            db,
            payments_db,
            keystore,
            data_dir: data_dir_for_profile,
            mls_db_path,
            mls_db_key,
            groups: Arc::new(GroupRegistry::default()),
            device_sync: Arc::new(DeviceSyncRegistry::default()),
            presence: Arc::new(PresenceRegistry::default()),
        },
    );
    if let Some(network) = network {
        state = state.with_network(network);
    }
    let state = Arc::new(state);

    tracing::info!("blackhole daemon starting (see docs/SPEC.md §6)");

    if let Err(err) = bh_api::ApiServer::new(port, state).run().await {
        tracing::error!(%err, "daemon API server exited with an error");
        std::process::exit(1);
    }
}
