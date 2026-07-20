//! Local encrypted-at-rest storage and hardware-backed key custody.
//! See `docs/SPEC.md` §7.

pub mod db;
pub mod keystore;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}
