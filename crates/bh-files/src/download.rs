//! Resumable download tracking: accumulate verified chunks as they arrive
//! (in any order, over however many sessions it takes), and know exactly
//! which ones are still missing — so an interrupted download picks up
//! where it left off instead of restarting.

use std::collections::HashMap;

use crate::chunking::{reassemble, Manifest};
use crate::FileError;

pub struct DownloadState {
    manifest: Manifest,
    chunks: HashMap<[u8; 32], Vec<u8>>,
}

impl DownloadState {
    pub fn new(manifest: Manifest) -> Self {
        Self {
            manifest,
            chunks: HashMap::new(),
        }
    }

    /// Chunk content hashes not yet retrieved.
    pub fn missing_chunks(&self) -> Vec<[u8; 32]> {
        self.manifest
            .chunks
            .iter()
            .map(|c| c.content_hash)
            .filter(|hash| !self.chunks.contains_key(hash))
            .collect()
    }

    /// Records a chunk's ciphertext once retrieved, verifying it actually
    /// hashes to a content hash this manifest references. Rejects
    /// unsolicited chunks — a malicious peer handing us data we didn't ask
    /// for shouldn't be able to make us store or count it.
    pub fn record_chunk(&mut self, ciphertext: Vec<u8>) -> Result<(), FileError> {
        let content_hash: [u8; 32] = blake3::hash(&ciphertext).into();
        if !self
            .manifest
            .chunks
            .iter()
            .any(|c| c.content_hash == content_hash)
        {
            return Err(FileError::HashMismatch);
        }
        self.chunks.insert(content_hash, ciphertext);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.missing_chunks().is_empty()
    }

    pub fn progress(&self) -> (usize, usize) {
        (self.chunks.len(), self.manifest.chunks.len())
    }

    /// Decrypts and reassembles the file. Errors if any chunk is still
    /// missing — check [`is_complete`](Self::is_complete) first.
    pub fn finish(&self, file_key: &[u8; 32]) -> Result<Vec<u8>, FileError> {
        reassemble(&self.manifest, &self.chunks, file_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::chunk_and_encrypt;

    #[test]
    fn tracks_progress_and_completes_once_every_chunk_arrives() {
        let file_key = [4u8; 32];
        let data: Vec<u8> = (0..crate::CHUNK_SIZE * 2 + 500)
            .map(|i| (i % 251) as u8)
            .collect();
        let (manifest, chunks) = chunk_and_encrypt(&data, &file_key);
        assert_eq!(manifest.chunks.len(), 3);

        let mut state = DownloadState::new(manifest);
        assert!(!state.is_complete());
        assert_eq!(state.progress(), (0, 3));

        // Deliver out of order, simulating chunks arriving from different
        // peers at different times.
        state.record_chunk(chunks[2].ciphertext.clone()).unwrap();
        assert_eq!(state.progress(), (1, 3));
        state.record_chunk(chunks[0].ciphertext.clone()).unwrap();
        assert!(!state.is_complete());
        state.record_chunk(chunks[1].ciphertext.clone()).unwrap();

        assert!(state.is_complete());
        assert!(state.missing_chunks().is_empty());

        let restored = state.finish(&file_key).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn resuming_only_needs_the_still_missing_chunks() {
        let file_key = [8u8; 32];
        let data: Vec<u8> = (0..crate::CHUNK_SIZE * 3)
            .map(|i| (i % 200) as u8)
            .collect();
        let (manifest, chunks) = chunk_and_encrypt(&data, &file_key);

        let mut state = DownloadState::new(manifest);
        state.record_chunk(chunks[0].ciphertext.clone()).unwrap();

        // "Session ends" here in a real client; missing_chunks() is what
        // gets persisted/re-requested on the next run.
        let missing = state.missing_chunks();
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&chunks[1].content_hash));
        assert!(missing.contains(&chunks[2].content_hash));
    }

    #[test]
    fn rejects_a_chunk_that_does_not_belong_to_this_manifest() {
        let (manifest, _) = chunk_and_encrypt(b"file a", &[1u8; 32]);
        let (_, unrelated_chunks) = chunk_and_encrypt(b"totally different file", &[2u8; 32]);

        let mut state = DownloadState::new(manifest);
        assert!(state
            .record_chunk(unrelated_chunks[0].ciphertext.clone())
            .is_err());
    }

    #[test]
    fn finish_fails_while_incomplete() {
        let file_key = [1u8; 32];
        let data: Vec<u8> = (0..crate::CHUNK_SIZE * 2)
            .map(|i| (i % 200) as u8)
            .collect();
        let (manifest, chunks) = chunk_and_encrypt(&data, &file_key);

        let mut state = DownloadState::new(manifest);
        state.record_chunk(chunks[0].ciphertext.clone()).unwrap();

        assert!(state.finish(&file_key).is_err());
    }
}
