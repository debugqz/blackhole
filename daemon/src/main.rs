//! The Blackhole daemon: runs on localhost, owns all cryptographic keys and
//! the connection to the P2P network. UI clients talk only to this daemon's
//! localhost API, never directly to the network. See `docs/SPEC.md` §6.
//!
//! `bh-network` (DHT/onion/mailbox) isn't wired in here yet — this pass
//! wires the local-only pieces (`bh-storage` + `bh-crypto` identity) behind
//! `bh-api`, since those don't need a live network to be useful.

use std::sync::Arc;

use bh_api::AppState;
use bh_storage::keystore::{Keystore, DB_KEY_LABEL};
use bh_storage::Database;

const DEFAULT_PORT: u16 = 47_853;
const SERVICE_NAME: &str = "blackhole";

fn data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("BLACKHOLE_DATA_DIR") {
        return dir.into();
    }
    dirs::data_dir()
        .expect("no platform data directory available")
        .join("blackhole")
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

    let keystore = Keystore::new(SERVICE_NAME, data_dir.clone());
    let db_key = load_or_create_db_key(&keystore);
    let db =
        Database::open(data_dir.join("blackhole.db"), &db_key).expect("failed to open database");

    // Self-destructing messages (SPEC.md §7) get swept on a timer rather
    // than only purged lazily on read.
    bh_storage::expiry::spawn_expiry_sweeper(
        db.clone(),
        std::time::Duration::from_secs(60),
        || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is before 1970")
                .as_secs() as i64
        },
    );

    let state = Arc::new(AppState {
        db,
        keystore,
        data_dir,
    });

    tracing::info!("blackhole daemon starting (see docs/SPEC.md §6)");

    if let Err(err) = bh_api::ApiServer::new(port, state).run().await {
        tracing::error!(%err, "daemon API server exited with an error");
        std::process::exit(1);
    }
}
