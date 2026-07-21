//! Local encrypted-at-rest storage (SQLCipher) and hardware-backed key
//! custody. See `docs/SPEC.md` §7.

mod schema;

pub mod contacts;
pub mod conversations;
pub mod db;
pub mod devices;
pub mod expiry;
pub mod files;
pub mod groups;
pub mod invites;
pub mod keystore;
pub mod message_requests;
pub mod messages;
pub mod models;
pub mod own_identity;
pub mod profiles;
pub mod reactions;
pub mod receipts;
pub mod sessions;
pub mod settings;

pub use db::Database;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("connection pool error: {0}")]
    Pool(r2d2::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("keystore error: {0}")]
    Keystore(#[from] keyring::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found")]
    NotFound,
}
