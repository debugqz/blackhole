//! Content-addressed file storage (SPEC.md §5.5): chunking, E2EE per
//! chunk, and resumable download tracking, independent of the text
//! message mailbox (`bh-network::mailbox`). This crate is transport- and
//! storage-agnostic — it only handles the chunking/crypto/verification
//! math; fetching chunks over the network and persisting them to disk are
//! the daemon's job, wiring this together with `bh-network` and
//! `bh-storage::files`.

pub mod chunking;
pub mod download;

pub use chunking::{chunk_and_encrypt, reassemble, ChunkRef, EncryptedChunk, Manifest};
pub use download::DownloadState;

/// 256 KiB — small enough that a single corrupt/missing chunk only costs a
/// small re-fetch, large enough to keep manifest overhead low for
/// multi-gigabyte files.
pub const CHUNK_SIZE: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("chunk content hash mismatch — data is corrupt or tampered")]
    HashMismatch,
    #[error("chunk decryption failed")]
    Decrypt,
    #[error("chunk plaintext length does not match the manifest")]
    LengthMismatch,
    #[error("manifest references a chunk that hasn't been downloaded yet")]
    MissingChunk,
}
