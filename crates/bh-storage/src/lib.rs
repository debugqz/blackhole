//! Local encrypted-at-rest storage (SQLCipher) and hardware-backed key
//! custody. See `docs/SPEC.md` §7.

mod payments_schema;
mod schema;

pub mod contacts;
pub mod conversations;
pub mod cosmetics;
pub mod db;
pub mod db_key_lock;
pub mod devices;
pub mod expiry;
pub mod files;
pub mod groups;
pub mod invites;
pub mod keystore;
pub mod local_auth;
pub mod message_requests;
pub mod message_stickers;
pub mod messages;
pub mod models;
pub mod own_identity;
pub mod payment_requests;
pub mod payments;
pub mod payments_db;
pub mod payments_models;
pub mod profiles;
pub mod push;
pub mod reactions;
pub mod receipts;
pub mod search;
pub mod sessions;
pub mod settings;

pub use db::Database;
pub use payments_db::PaymentsDatabase;

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
    #[error("incorrect PIN or corrupted key material")]
    InvalidPin,
}
