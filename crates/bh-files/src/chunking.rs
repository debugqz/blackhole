//! Splits a file into fixed-size chunks, encrypts each independently, and
//! content-addresses them by the hash of their *ciphertext* — so storage
//! nodes are addressing what they actually hold, and two people sending
//! the same file with different keys don't collide (or leak that it's the
//! same file) at the storage layer.

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{FileError, CHUNK_SIZE};

fn chunk_key_nonce(file_key: &[u8; 32], index: u32) -> ([u8; 32], [u8; 12]) {
    let hkdf = Hkdf::<Sha256>::new(None, file_key);
    let mut out = [0u8; 44];
    let mut info = b"blackhole-file-chunk-v1:".to_vec();
    info.extend_from_slice(&index.to_be_bytes());
    hkdf.expand(&info, &mut out)
        .expect("44 bytes is a valid HKDF-SHA256 output length");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&out[..32]);
    nonce.copy_from_slice(&out[32..44]);
    (key, nonce)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRef {
    pub content_hash: [u8; 32],
    pub plaintext_len: u32,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub total_size: u64,
    pub chunks: Vec<ChunkRef>,
}

pub struct EncryptedChunk {
    pub content_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Splits `data` into `CHUNK_SIZE` pieces and encrypts each with a key
/// derived from `file_key` and its chunk index (never the same key/nonce
/// pair twice, without needing to track nonces).
pub fn chunk_and_encrypt(data: &[u8], file_key: &[u8; 32]) -> (Manifest, Vec<EncryptedChunk>) {
    let mut refs = Vec::new();
    let mut encrypted = Vec::new();

    for (i, plain_chunk) in data.chunks(CHUNK_SIZE.max(1)).enumerate() {
        let (key, nonce) = chunk_key_nonce(file_key, i as u32);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce), plain_chunk)
            .expect("encryption with a freshly-derived key cannot fail");
        let content_hash: [u8; 32] = blake3::hash(&ciphertext).into();

        refs.push(ChunkRef {
            content_hash,
            plaintext_len: plain_chunk.len() as u32,
        });
        encrypted.push(EncryptedChunk {
            content_hash,
            ciphertext,
        });
    }

    (
        Manifest {
            total_size: data.len() as u64,
            chunks: refs,
        },
        encrypted,
    )
}

/// Reassembles the original file from a manifest plus every referenced
/// chunk's ciphertext (keyed by content hash, e.g. as retrieved from the
/// network). Verifies each chunk's hash and length before trusting it.
pub fn reassemble(
    manifest: &Manifest,
    available: &HashMap<[u8; 32], Vec<u8>>,
    file_key: &[u8; 32],
) -> Result<Vec<u8>, FileError> {
    let mut out = Vec::with_capacity(manifest.total_size as usize);

    for (i, chunk_ref) in manifest.chunks.iter().enumerate() {
        let ciphertext = available
            .get(&chunk_ref.content_hash)
            .ok_or(FileError::MissingChunk)?;

        if blake3::hash(ciphertext).as_bytes() != &chunk_ref.content_hash {
            return Err(FileError::HashMismatch);
        }

        let (key, nonce) = chunk_key_nonce(file_key, i as u32);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(&Nonce::from(nonce), ciphertext.as_slice())
            .map_err(|_| FileError::Decrypt)?;

        if plaintext.len() != chunk_ref.plaintext_len as usize {
            return Err(FileError::LengthMismatch);
        }
        out.extend_from_slice(&plaintext);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available_map(chunks: &[EncryptedChunk]) -> HashMap<[u8; 32], Vec<u8>> {
        chunks
            .iter()
            .map(|c| (c.content_hash, c.ciphertext.clone()))
            .collect()
    }

    #[test]
    fn small_file_roundtrips() {
        let file_key = [7u8; 32];
        let data = b"a small file that fits in one chunk".to_vec();
        let (manifest, chunks) = chunk_and_encrypt(&data, &file_key);
        assert_eq!(manifest.chunks.len(), 1);

        let restored = reassemble(&manifest, &available_map(&chunks), &file_key).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn multi_chunk_file_roundtrips() {
        let file_key = [3u8; 32];
        let data: Vec<u8> = (0..CHUNK_SIZE * 3 + 100).map(|i| (i % 256) as u8).collect();
        let (manifest, chunks) = chunk_and_encrypt(&data, &file_key);
        assert_eq!(manifest.chunks.len(), 4);
        assert_eq!(manifest.total_size, data.len() as u64);

        let restored = reassemble(&manifest, &available_map(&chunks), &file_key).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn wrong_file_key_fails_to_reassemble() {
        let data = b"secret file contents".to_vec();
        let (manifest, chunks) = chunk_and_encrypt(&data, &[1u8; 32]);
        assert!(reassemble(&manifest, &available_map(&chunks), &[2u8; 32]).is_err());
    }

    #[test]
    fn tampered_chunk_bytes_fail_hash_check_even_if_map_key_matches() {
        let file_key = [9u8; 32];
        let data = b"integrity matters".to_vec();
        let (manifest, chunks) = chunk_and_encrypt(&data, &file_key);
        let mut available = available_map(&chunks);
        let hash = manifest.chunks[0].content_hash;
        available.get_mut(&hash).unwrap().push(0xFF);

        assert!(matches!(
            reassemble(&manifest, &available, &file_key),
            Err(FileError::HashMismatch)
        ));
    }

    #[test]
    fn missing_chunk_is_reported_not_panicked_on() {
        let data = b"needs all its chunks".to_vec();
        let (manifest, _chunks) = chunk_and_encrypt(&data, &[5u8; 32]);
        let empty = HashMap::new();
        assert!(matches!(
            reassemble(&manifest, &empty, &[5u8; 32]),
            Err(FileError::MissingChunk)
        ));
    }

    #[test]
    fn identical_content_with_different_keys_yields_different_chunk_hashes() {
        let data = b"same plaintext".to_vec();
        let (manifest_a, _) = chunk_and_encrypt(&data, &[1u8; 32]);
        let (manifest_b, _) = chunk_and_encrypt(&data, &[2u8; 32]);
        assert_ne!(
            manifest_a.chunks[0].content_hash,
            manifest_b.chunks[0].content_hash
        );
    }
}
