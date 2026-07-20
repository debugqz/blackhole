//! Store-and-forward offline messaging. Encrypted mailboxes on network nodes,
//! indexed by a hash of the recipient's public key (the node never learns
//! the real identity), with a TTL (e.g. 30 days) and automatic purge. The
//! local daemon pulls on reconnect, decrypts locally, and requests deletion
//! of the node's copy. Group sends fan out once to the group's responsible
//! nodes rather than pushing individually per member. See `docs/SPEC.md`
//! §5.3-5.4.

use crate::NetworkError;

pub struct Mailbox;

impl Mailbox {
    pub async fn push(_recipient_key_hash: &[u8], _ciphertext: &[u8]) -> Result<(), NetworkError> {
        todo!("wire up mailbox push — see docs/SPEC.md §5.3")
    }

    pub async fn pull(_recipient_key_hash: &[u8]) -> Result<Vec<Vec<u8>>, NetworkError> {
        todo!("wire up mailbox pull + deletion request — see docs/SPEC.md §5.3")
    }

    /// Publishes once to the nodes responsible for a group, for member pull
    /// rather than per-member push (SPEC.md §5.4).
    pub async fn fan_out(_group_id: &[u8], _ciphertext: &[u8]) -> Result<(), NetworkError> {
        todo!("wire up group fan-out — see docs/SPEC.md §5.4")
    }
}
