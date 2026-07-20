use std::path::PathBuf;

use bh_storage::{keystore::Keystore, Database};

/// Shared daemon state handed to every request handler. Cloned per
/// request via `axum::extract::State<Arc<AppState>>` — cheap, since
/// `Database` wraps a connection pool internally.
pub struct AppState {
    pub db: Database,
    pub keystore: Keystore,
    /// Directory containing the database file and any other local state —
    /// what a panic wipe deletes from disk.
    pub data_dir: PathBuf,
}
