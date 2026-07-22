//! Persistent MLS storage (`docs/THREAT_MODEL.md` §3.2): `mls.rs`'s
//! `MlsMember::new` uses `openmls_rust_crypto::OpenMlsRustCrypto`'s
//! in-memory storage, which is fine for tests but loses all group state on
//! daemon restart. This module provides an alternative
//! [`PersistentMlsProvider`] that keeps the same audited RustCrypto crypto
//! backend but persists state to disk via `openmls_sqlite_storage` (a real,
//! openmls-maintained `StorageProvider` implementation over `rusqlite`),
//! pointed at our own SQLCipher-keyed connection instead of a plaintext
//! SQLite file.
//!
//! This is a dedicated database file and key, isolated from `bh-storage`'s
//! messaging database — the same "separate file, separate key" pattern
//! already used for the payments database, and for the same reason: it
//! lets this crate stay independent of `bh-storage` rather than depending
//! downward on the crate that depends on it.

use std::path::Path;

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::CryptoError;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

type Storage = SqliteStorageProvider<JsonCodec, Connection>;

/// An `OpenMlsProvider` combining the same audited RustCrypto backend
/// `MlsMember::new` uses with disk-persisted, SQLCipher-encrypted storage
/// instead of an in-memory store.
pub struct PersistentMlsProvider {
    crypto: RustCrypto,
    storage: Storage,
}

impl OpenMlsProvider for PersistentMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn open_sqlcipher_connection(path: &Path, key: &[u8; 32]) -> Result<Connection, CryptoError> {
    let conn = Connection::open(path)
        .map_err(|_| CryptoError::NotImplemented("mls storage: failed to open database"))?;
    // Matches bh-storage's own SQLCipher key setup exactly (see
    // bh_storage::db::SetSqlCipherKey) — the `key` pragma doesn't support
    // bound parameters.
    conn.pragma_update(None, "key", format!("\"x'{}'\"", hex::encode(key)))
        .map_err(|_| CryptoError::KeyDerivation)?;
    // Force SQLCipher to actually touch the (decrypted) page cache now, so
    // a wrong key fails loudly here instead of on the first real query.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(conn)
}

impl PersistentMlsProvider {
    /// Opens (creating if absent) a SQLCipher-encrypted database at `path`
    /// keyed by `key`, running openmls's storage migrations on first use.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, CryptoError> {
        let conn = open_sqlcipher_connection(path, key)?;
        let mut storage = Storage::new(conn);
        storage
            .run_migrations()
            .map_err(|_| CryptoError::NotImplemented("mls storage: migration failed"))?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }

    /// As [`open`](Self::open), but entirely in memory (used by tests —
    /// exercises the exact same persistence code path as the on-disk
    /// case, just without a real file, so the storage-provider wiring
    /// itself is covered without needing a temp directory per test).
    pub fn open_in_memory(key: &[u8; 32]) -> Result<Self, CryptoError> {
        let conn = Connection::open_in_memory()
            .map_err(|_| CryptoError::NotImplemented("mls storage: failed to open database"))?;
        conn.pragma_update(None, "key", format!("\"x'{}'\"", hex::encode(key)))
            .map_err(|_| CryptoError::KeyDerivation)?;
        let mut storage = Storage::new(conn);
        storage
            .run_migrations()
            .map_err(|_| CryptoError::NotImplemented("mls storage: migration failed"))?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }
}
