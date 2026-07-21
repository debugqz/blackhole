//! The Blackhole daemon: runs on localhost, owns all cryptographic keys and
//! the connection to the P2P network. UI clients talk only to this daemon's
//! localhost API, never directly to the network. See `docs/SPEC.md` §6.
//!
//! `bh-network` (DHT/onion/mailbox) isn't wired in here yet — this pass
//! wires the local-only pieces (`bh-storage` + `bh-crypto` identity) behind
//! `bh-api`, since those don't need a live network to be useful.

use std::sync::Arc;

use bh_api::state::ProfileSession;
use bh_api::AppState;
use bh_storage::keystore::{Keystore, DB_KEY_LABEL};
use bh_storage::profiles::ProfileManager;
use bh_storage::Database;

const DEFAULT_PORT: u16 = 47_853;
const SERVICE_NAME: &str = "blackhole";
const DEFAULT_PROFILE_NAME: &str = "Default";

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

/// Loads the SQLCipher database key from the platform keystore, generating
/// and storing a fresh one on first run. Never logged, never persisted
/// outside the keystore (SPEC.md §7).
fn load_or_create_db_key(keystore: &Keystore) -> [u8; 32] {
    if let Some(key) = keystore
        .load_key(DB_KEY_LABEL)
        .expect("keystore access failed")
    {
        return key.try_into().expect("stored db key is not 32 bytes");
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("system RNG unavailable");
    keystore
        .store_key(DB_KEY_LABEL, &key)
        .expect("failed to store new db key in platform keystore");
    key
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
    let db_key = load_or_create_db_key(&keystore);
    let db = Database::open(manager.profile_db_path(&active_profile_id), &db_key)
        .expect("failed to open database");

    // Self-destructing messages (SPEC.md §7) get swept on a timer rather
    // than only purged lazily on read. Known limitation: this sweeper is
    // pinned to whichever profile is active at startup — switching the
    // active profile at runtime (`POST /profiles/:id/activate`) does not
    // yet move the sweeper to the newly-active profile's database. Not a
    // correctness/security issue (a profile's own sweeper resumes on next
    // daemon restart, and nothing un-expires), just a staleness gap;
    // tracked in `docs/THREAT_MODEL.md`.
    bh_storage::expiry::spawn_expiry_sweeper(db.clone(), std::time::Duration::from_secs(60), now);

    let data_dir_for_profile = manager.profile_data_dir(&active_profile_id);
    let state = Arc::new(AppState::new(
        manager,
        ProfileSession {
            profile_id: active_profile_id,
            db,
            keystore,
            data_dir: data_dir_for_profile,
        },
    ));

    tracing::info!("blackhole daemon starting (see docs/SPEC.md §6)");

    if let Err(err) = bh_api::ApiServer::new(port, state).run().await {
        tracing::error!(%err, "daemon API server exited with an error");
        std::process::exit(1);
    }
}
