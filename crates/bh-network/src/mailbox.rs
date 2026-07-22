//! Store-and-forward offline messaging. Encrypted mailboxes on network
//! nodes, indexed by a hash of the recipient's public key (the node never
//! sees the real identity — that's the caller's job to hash, this module
//! just takes bytes). TTL-bounded with automatic expiry. The local daemon
//! pulls on reconnect, decrypts locally, and requests deletion of the
//! node's copy. Group sends fan out once to the group's key rather than
//! pushing individually per member — every member just pulls from the same
//! place. See `docs/SPEC.md` §5.3-5.4.
//!
//! **Anti-spam PoW is enforced here** (SPEC.md §8): [`push`](Mailbox::push)
//! rejects a message whose proof-of-work doesn't verify against
//! `pow::challenge_for_message`, binding the work to this exact recipient,
//! message id, ciphertext, and timestamp so a solved challenge can't be
//! replayed for a different message (including a different message id
//! sharing the same ciphertext/timestamp). Callers compute their solution
//! with [`Mailbox::solve_pow`] first.
//!
//! **Manifest races (mitigated, not eliminated).** This is built on the
//! plain Kademlia get/put-record primitives in `dht.rs`, which are
//! single-writer, last-write-wins per key — there's no compare-and-swap.
//! The message record itself is never at risk (each message has its own
//! key, written once). The per-recipient *manifest* (the list of message
//! IDs to know to fetch) is what two concurrent senders can race on. To
//! guard against silently losing an entry, every manifest mutation here
//! does read-merge-write-**verify**, retrying (`MAX_MANIFEST_MERGE_ATTEMPTS`
//! times) if a concurrent writer clobbered the record in between — see
//! `two_concurrent_pushes_to_the_same_recipient_both_survive` below. This
//! converges correctly under the bursty-but-not-pathological concurrency a
//! real client sees; it is still not a true CRDT/atomic merge, and a
//! dedicated mailbox-node protocol with real compare-and-swap remains the
//! long-term fix (`docs/THREAT_MODEL.md` §3.6).

use serde::{Deserialize, Serialize};

use crate::dht::Dht;
use crate::pow::{self, Solution};
use crate::NetworkError;

/// How many times to retry a manifest read-merge-write-verify cycle before
/// giving up. Each retry only happens when a concurrent writer is detected
/// (the verify step failed), so this bounds worst-case contention, not the
/// common case (which succeeds in one attempt).
const MAX_MANIFEST_MERGE_ATTEMPTS: usize = 8;

/// Deliberately low ("liviano" — SPEC.md §8): a normal client burns single-
/// digit milliseconds solving this; an automated mass sender pays that same
/// cost per message, which adds up at scale.
const POW_DIFFICULTY_BITS: u8 = 16;

/// Hard cap on how far in the future a message's `expires_at` may sit —
/// without this, a caller-supplied `ttl_seconds` has no upper bound, so a
/// sender can make a message effectively permanent (defeating the
/// TTL-bounded-storage design) and `now + ttl_seconds` is otherwise
/// unchecked `i64` addition. 30 days is generous for offline store-and-
/// forward delivery.
const MAX_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    message_ids: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct StoredMessage {
    ciphertext: Vec<u8>,
    expires_at: i64,
}

impl StoredMessage {
    /// Hand-rolled binary framing (8-byte big-endian `expires_at` followed
    /// by the raw ciphertext), not `serde_json` — the same lesson
    /// `sealed_sender.rs`'s own `SealedSenderEnvelope::to_bytes` doc
    /// comment already draws for a `Vec<u8>` this size: `serde_json`
    /// encodes bytes as a JSON array of decimal numbers, roughly
    /// quadrupling the payload before it ever reaches the DHT record size
    /// cap (`MemoryStoreConfig::max_value_bytes`, 64KiB by default). A real
    /// call-signal offer's SDP-heavy ciphertext is easily tens of KB —
    /// comfortably under that cap raw, but not once JSON-inflated.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.ciphertext.len());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, NetworkError> {
        let expires_bytes: [u8; 8] = bytes
            .get(..8)
            .ok_or_else(|| NetworkError::Setup("mailbox: stored message truncated".to_string()))?
            .try_into()
            .expect("slice of length 8 always converts to [u8; 8]");
        Ok(Self {
            expires_at: i64::from_be_bytes(expires_bytes),
            ciphertext: bytes[8..].to_vec(),
        })
    }
}

/// Exposed only for `crates/bh-network/fuzz/fuzz_targets/
/// fuzz_mailbox_manifest.rs` — exercises the exact `serde_json::from_slice`
/// deserialization `fetch_manifest` runs on a DHT record's bytes, which is
/// attacker-influenceable content (any node can publish a record under a
/// guessed/derived key). Must never panic on malformed input; deliberately
/// not part of this crate's real public API otherwise.
#[doc(hidden)]
pub fn fuzz_only_parse_manifest_bytes(bytes: &[u8]) -> Result<(), NetworkError> {
    let _manifest: Manifest = serde_json::from_slice(bytes)?;
    Ok(())
}

/// Sleeps a short, randomized delay before the next manifest
/// read-merge-write-verify retry. Two writers racing on the same
/// recipient who both retry *immediately* (no delay at all) tend to keep
/// colliding in lockstep — each one's write clobbers the other's right
/// before it can verify, attempt after attempt. Growing, jittered backoff
/// (roughly `5ms * attempt`, plus up to that much random jitter) spreads
/// retries out in time so concurrent writers converge faster in the
/// common case, without adding a compare-and-swap primitive this module
/// still doesn't have (`docs/THREAT_MODEL.md` §3.6's long-term fix).
async fn manifest_retry_backoff(attempt: usize) {
    let base_ms = 5u64 * (attempt as u64 + 1);
    let mut jitter_byte = [0u8; 1];
    // A failed `getrandom` here would only make backoff slightly less
    // jittery, never break correctness — falling back to no extra jitter
    // (0) rather than propagating an error keeps this a pure timing nicety.
    let _ = getrandom::fill(&mut jitter_byte);
    let jitter_ms = u64::from(jitter_byte[0]) % (base_ms + 1);
    tokio::time::sleep(std::time::Duration::from_millis(base_ms + jitter_ms)).await;
}

fn manifest_key(recipient_key_hash: &[u8]) -> Vec<u8> {
    let mut k = b"bh-mailbox:manifest:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k
}

fn message_key(recipient_key_hash: &[u8], message_id: &[u8]) -> Vec<u8> {
    let mut k = b"bh-mailbox:msg:".to_vec();
    k.extend_from_slice(recipient_key_hash);
    k.push(b':');
    k.extend_from_slice(message_id);
    k
}

#[derive(Clone)]
pub struct Mailbox {
    dht: Dht,
}

impl Mailbox {
    pub fn new(dht: Dht) -> Self {
        Self { dht }
    }

    /// Solves the anti-spam proof-of-work [`push`](Self::push) will
    /// require for this exact `(recipient_key_hash, message_id, ciphertext,
    /// now)` quadruple. Callers must pass the same values to both calls —
    /// the challenge is bound to them so a solved PoW can't be reused for
    /// a different message (including a different `message_id` for
    /// otherwise-identical content).
    pub fn solve_pow(
        recipient_key_hash: &[u8],
        message_id: &[u8],
        ciphertext: &[u8],
        now: i64,
    ) -> Solution {
        pow::solve(&pow::challenge_for_message(
            recipient_key_hash,
            message_id,
            ciphertext,
            now,
            POW_DIFFICULTY_BITS,
        ))
    }

    async fn fetch_manifest(&self, recipient_key_hash: &[u8]) -> Result<Manifest, NetworkError> {
        match self.dht.lookup(&manifest_key(recipient_key_hash)).await? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(Manifest::default()),
        }
    }

    /// Stores `ciphertext` for `recipient_key_hash`, expiring `ttl_seconds`
    /// after `now` (unix seconds — caller-supplied so this is testable
    /// without waiting in real time). Requires a valid `pow_solution` from
    /// [`solve_pow`](Self::solve_pow) for the same
    /// `(recipient_key_hash, ciphertext, now)` — a mailbox node enforcing
    /// this rejects unsolved or mismatched submissions before ever storing
    /// anything (SPEC.md §8).
    pub async fn push(
        &self,
        recipient_key_hash: &[u8],
        message_id: &[u8],
        ciphertext: Vec<u8>,
        ttl_seconds: i64,
        now: i64,
        pow_solution: &Solution,
    ) -> Result<(), NetworkError> {
        if !(0..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(NetworkError::Setup(format!(
                "mailbox: ttl_seconds must be between 0 and {MAX_TTL_SECONDS}, got {ttl_seconds}"
            )));
        }

        let challenge = pow::challenge_for_message(
            recipient_key_hash,
            message_id,
            &ciphertext,
            now,
            POW_DIFFICULTY_BITS,
        );
        if !pow::verify(&challenge, pow_solution) {
            return Err(NetworkError::Setup(
                "mailbox: invalid or insufficient proof-of-work".to_string(),
            ));
        }

        let stored = StoredMessage {
            ciphertext,
            // Checked, not `now + ttl_seconds` directly: `ttl_seconds` is
            // already bounded above, but `now` is caller-supplied too, so
            // guard the addition itself rather than assume it can't
            // overflow.
            expires_at: now.checked_add(ttl_seconds).ok_or_else(|| {
                NetworkError::Setup("mailbox: now + ttl_seconds overflowed".to_string())
            })?,
        };
        self.dht
            .publish(
                &message_key(recipient_key_hash, message_id),
                stored.to_bytes(),
            )
            .await?;

        for attempt in 0..MAX_MANIFEST_MERGE_ATTEMPTS {
            let mut manifest = self.fetch_manifest(recipient_key_hash).await?;
            if manifest.message_ids.iter().any(|id| id == message_id) {
                return Ok(());
            }
            manifest.message_ids.push(message_id.to_vec());
            self.dht
                .publish(
                    &manifest_key(recipient_key_hash),
                    serde_json::to_vec(&manifest)?,
                )
                .await?;

            // Read-after-write: a concurrent writer may have clobbered the
            // manifest between our write and now. If our id didn't stick,
            // merge again rather than silently losing this entry.
            let confirm = self.fetch_manifest(recipient_key_hash).await?;
            if confirm.message_ids.iter().any(|id| id == message_id) {
                return Ok(());
            }
            if attempt + 1 == MAX_MANIFEST_MERGE_ATTEMPTS {
                return Err(NetworkError::Query(format!(
                    "mailbox: manifest update did not stick after {MAX_MANIFEST_MERGE_ATTEMPTS} \
                     attempts (concurrent writers racing on the same recipient); the message \
                     itself is stored and can be recovered by a future merge, but is not yet \
                     discoverable via the manifest"
                )));
            }
            manifest_retry_backoff(attempt).await;
        }
        unreachable!("loop above always returns before exhausting its bound")
    }

    /// Pulls every non-expired message currently in the mailbox, as
    /// `(message_id, ciphertext)` pairs. Expired entries (and entries whose
    /// underlying message record is already gone) are pruned from the
    /// manifest here via [`delete`](Self::delete) rather than left behind
    /// — otherwise every future `pull` would keep re-fetching every stale
    /// entry ever pushed, growing without bound for the life of the
    /// mailbox key.
    pub async fn pull(
        &self,
        recipient_key_hash: &[u8],
        now: i64,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, NetworkError> {
        let manifest = self.fetch_manifest(recipient_key_hash).await?;
        let mut out = Vec::new();
        let mut stale_ids = Vec::new();
        for id in &manifest.message_ids {
            match self
                .dht
                .lookup(&message_key(recipient_key_hash, id))
                .await?
            {
                Some(bytes) => {
                    let stored = StoredMessage::from_bytes(&bytes)?;
                    if stored.expires_at > now {
                        out.push((id.clone(), stored.ciphertext));
                    } else {
                        stale_ids.push(id.clone());
                    }
                }
                None => stale_ids.push(id.clone()),
            }
        }
        for id in stale_ids {
            // Best-effort housekeeping: the entry is already excluded from
            // `out` above regardless of whether this prune succeeds, so a
            // failure here (e.g. a concurrent writer) shouldn't fail the
            // pull itself.
            let _ = self.delete(recipient_key_hash, &id).await;
        }
        Ok(out)
    }

    /// Requests deletion of one message: removes it from the manifest so
    /// future pulls skip it. Same read-merge-write-verify retry as
    /// [`push`](Self::push), for the same reason. This does not (and with
    /// plain Kademlia records, cannot) force other holders of the message
    /// record to purge their copy; that needs a real mailbox-node delete
    /// RPC.
    pub async fn delete(
        &self,
        recipient_key_hash: &[u8],
        message_id: &[u8],
    ) -> Result<(), NetworkError> {
        for attempt in 0..MAX_MANIFEST_MERGE_ATTEMPTS {
            let mut manifest = self.fetch_manifest(recipient_key_hash).await?;
            if !manifest.message_ids.iter().any(|id| id == message_id) {
                return Ok(());
            }
            manifest.message_ids.retain(|id| id != message_id);
            self.dht
                .publish(
                    &manifest_key(recipient_key_hash),
                    serde_json::to_vec(&manifest)?,
                )
                .await?;

            let confirm = self.fetch_manifest(recipient_key_hash).await?;
            if !confirm.message_ids.iter().any(|id| id == message_id) {
                return Ok(());
            }
            if attempt + 1 == MAX_MANIFEST_MERGE_ATTEMPTS {
                return Err(NetworkError::Query(format!(
                    "mailbox: manifest deletion did not stick after {MAX_MANIFEST_MERGE_ATTEMPTS} attempts"
                )));
            }
            manifest_retry_backoff(attempt).await;
        }
        unreachable!("loop above always returns before exhausting its bound")
    }

    /// Publishes once to `group_id` rather than once per member (SPEC.md
    /// §5.4) — every group member just calls [`pull`](Self::pull) with the
    /// same `group_id` as the recipient key. Same PoW requirement as
    /// [`push`](Self::push).
    pub async fn fan_out(
        &self,
        group_id: &[u8],
        message_id: &[u8],
        ciphertext: Vec<u8>,
        ttl_seconds: i64,
        now: i64,
        pow_solution: &Solution,
    ) -> Result<(), NetworkError> {
        self.push(
            group_id,
            message_id,
            ciphertext,
            ttl_seconds,
            now,
            pow_solution,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Node;
    use std::time::Duration;

    async fn connected_pair() -> (Dht, Dht) {
        let node_a = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let node_b = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let addr_a = node_a
            .listen_addrs()
            .await
            .into_iter()
            .next()
            .unwrap()
            .with_p2p(node_a.peer_id())
            .unwrap();
        node_b.dial(addr_a).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        (Dht::new(node_a), Dht::new(node_b))
    }

    async fn publish_with_retry(
        mailbox: &Mailbox,
        recipient: &[u8],
        id: &[u8],
        ct: Vec<u8>,
        ttl: i64,
        now: i64,
    ) {
        let solution = Mailbox::solve_pow(recipient, id, &ct, now);
        for attempt in 0..20 {
            match mailbox
                .push(recipient, id, ct.clone(), ttl, now, &solution)
                .await
            {
                Ok(()) => return,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("push failed after retries: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn recipient_pulls_a_message_pushed_by_someone_else() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash";

        publish_with_retry(
            &sender_mailbox,
            recipient_key,
            b"msg-1",
            b"encrypted contents".to_vec(),
            86_400,
            1_000,
        )
        .await;

        let messages = recipient_mailbox.pull(recipient_key, 1_000).await.unwrap();
        assert_eq!(
            messages,
            vec![(b"msg-1".to_vec(), b"encrypted contents".to_vec())]
        );
    }

    #[tokio::test]
    async fn expired_messages_are_skipped_on_pull() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash-2";

        // TTL of 10s starting at t=1000 -> expires at 1010.
        publish_with_retry(
            &sender_mailbox,
            recipient_key,
            b"msg-1",
            b"old news".to_vec(),
            10,
            1_000,
        )
        .await;

        let messages = recipient_mailbox.pull(recipient_key, 2_000).await.unwrap();
        assert!(
            messages.is_empty(),
            "message past its TTL must not be returned"
        );

        // Regression test: `pull` must also prune the expired entry from
        // the manifest itself, not just exclude it from the returned
        // list — otherwise every future pull keeps re-fetching every
        // stale entry ever pushed, growing without bound.
        let manifest = recipient_mailbox
            .fetch_manifest(recipient_key)
            .await
            .unwrap();
        assert!(
            manifest.message_ids.is_empty(),
            "an expired entry must be pruned from the manifest by pull, not left behind"
        );
    }

    #[tokio::test]
    async fn delete_removes_a_message_from_future_pulls() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash-3";

        publish_with_retry(
            &sender_mailbox,
            recipient_key,
            b"msg-1",
            b"delete me".to_vec(),
            86_400,
            1_000,
        )
        .await;
        assert_eq!(
            recipient_mailbox
                .pull(recipient_key, 1_000)
                .await
                .unwrap()
                .len(),
            1
        );

        recipient_mailbox
            .delete(recipient_key, b"msg-1")
            .await
            .unwrap();
        assert!(recipient_mailbox
            .pull(recipient_key, 1_000)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn fan_out_lets_every_member_pull_the_same_group_message() {
        let (sender_dht, member_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let member_a_mailbox = Mailbox::new(member_dht.clone());
        let member_b_mailbox = Mailbox::new(member_dht);
        let group_id = b"group-42";
        let ciphertext = b"meeting at noon".to_vec();
        let solution = Mailbox::solve_pow(group_id, b"group-msg-1", &ciphertext, 1_000);

        for attempt in 0..20 {
            match sender_mailbox
                .fan_out(
                    group_id,
                    b"group-msg-1",
                    ciphertext.clone(),
                    86_400,
                    1_000,
                    &solution,
                )
                .await
            {
                Ok(()) => break,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("fan_out failed after retries: {e}"),
            }
        }

        let a_messages = member_a_mailbox.pull(group_id, 1_000).await.unwrap();
        let b_messages = member_b_mailbox.pull(group_id, 1_000).await.unwrap();
        assert_eq!(a_messages, b_messages);
        assert_eq!(a_messages[0].1, b"meeting at noon");
    }

    /// The race this module's manifest-merge retry exists to survive: two
    /// senders push to the *same recipient* at the same time. Without the
    /// read-merge-write-verify loop, a naive read-modify-write would let
    /// the second writer's blind overwrite silently drop the first
    /// writer's entry from the manifest.
    #[tokio::test]
    async fn two_concurrent_pushes_to_the_same_recipient_both_survive() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let mailbox_a = Mailbox::new(sender_dht.clone());
        let mailbox_b = Mailbox::new(sender_dht);
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash-race";
        let ct_a = b"hello from a".to_vec();
        let ct_b = b"hello from b".to_vec();
        let solution_a = Mailbox::solve_pow(recipient_key, b"from-a", &ct_a, 1_000);
        let solution_b = Mailbox::solve_pow(recipient_key, b"from-b", &ct_b, 1_000);

        let (result_a, result_b) = tokio::join!(
            mailbox_a.push(
                recipient_key,
                b"from-a",
                ct_a.clone(),
                86_400,
                1_000,
                &solution_a
            ),
            mailbox_b.push(
                recipient_key,
                b"from-b",
                ct_b.clone(),
                86_400,
                1_000,
                &solution_b
            ),
        );
        result_a.expect("push a should eventually succeed via retry");
        result_b.expect("push b should eventually succeed via retry");

        let mut messages = recipient_mailbox.pull(recipient_key, 1_000).await.unwrap();
        messages.sort();
        let mut expected = vec![(b"from-a".to_vec(), ct_a), (b"from-b".to_vec(), ct_b)];
        expected.sort();
        assert_eq!(
            messages, expected,
            "both concurrent pushes must survive in the manifest, not just the last writer"
        );
    }

    /// Heavier contention than the two-writer test above — five senders
    /// racing on the same recipient's manifest at once, the kind of burst
    /// `manifest_retry_backoff`'s jitter exists to help converge instead of
    /// every writer retrying in lockstep. All five entries must survive,
    /// not just however many the retry budget happens to favor.
    #[tokio::test]
    async fn five_concurrent_pushes_to_the_same_recipient_all_survive() {
        let (sender_dht, recipient_dht) = connected_pair().await;
        let recipient_mailbox = Mailbox::new(recipient_dht);
        let recipient_key = b"recipient-key-hash-heavy-race";

        let pushes = (0..5).map(|i| {
            let mailbox = Mailbox::new(sender_dht.clone());
            let message_id = format!("from-{i}").into_bytes();
            let ciphertext = format!("hello from {i}").into_bytes();
            async move {
                let solution = Mailbox::solve_pow(recipient_key, &message_id, &ciphertext, 1_000);
                mailbox
                    .push(
                        recipient_key,
                        &message_id,
                        ciphertext.clone(),
                        86_400,
                        1_000,
                        &solution,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        panic!("push {i} should eventually succeed via retry: {e}")
                    });
                (message_id, ciphertext)
            }
        });
        let mut expected: Vec<(Vec<u8>, Vec<u8>)> = futures::future::join_all(pushes).await;
        expected.sort();

        let mut messages = recipient_mailbox.pull(recipient_key, 1_000).await.unwrap();
        messages.sort();
        assert_eq!(
            messages, expected,
            "every one of 5 concurrent pushes must survive in the manifest"
        );
    }

    #[tokio::test]
    async fn push_without_valid_pow_is_rejected() {
        let (sender_dht, _recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_key = b"recipient-key-hash-pow";
        let ciphertext = b"spam attempt".to_vec();

        // A solution solved for a *different* message doesn't satisfy this
        // one's challenge.
        let wrong_solution = Mailbox::solve_pow(b"someone-else", b"msg-1", &ciphertext, 1_000);
        let result = sender_mailbox
            .push(
                recipient_key,
                b"msg-1",
                ciphertext,
                86_400,
                1_000,
                &wrong_solution,
            )
            .await;
        assert!(
            result.is_err(),
            "push with an invalid PoW solution must be rejected"
        );
    }

    /// Regression test: a PoW solved for one `message_id` must not satisfy
    /// `push` for a different `message_id`, even with identical recipient,
    /// ciphertext, and timestamp — otherwise one solved PoW could be
    /// replayed to store unlimited duplicate mailbox entries for free.
    #[tokio::test]
    async fn push_rejects_a_pow_solved_for_a_different_message_id() {
        let (sender_dht, _recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_key = b"recipient-key-hash-pow-msgid";
        let ciphertext = b"same content".to_vec();

        let solution_for_msg_1 = Mailbox::solve_pow(recipient_key, b"msg-1", &ciphertext, 1_000);
        let result = sender_mailbox
            .push(
                recipient_key,
                b"msg-2",
                ciphertext,
                86_400,
                1_000,
                &solution_for_msg_1,
            )
            .await;
        assert!(
            result.is_err(),
            "a PoW solved for msg-1 must not be replayable to push msg-2"
        );
    }

    #[tokio::test]
    async fn push_rejects_a_ttl_beyond_the_maximum() {
        let (sender_dht, _recipient_dht) = connected_pair().await;
        let sender_mailbox = Mailbox::new(sender_dht);
        let recipient_key = b"recipient-key-hash-ttl";
        let ciphertext = b"hello".to_vec();
        let solution = Mailbox::solve_pow(recipient_key, b"msg-1", &ciphertext, 1_000);

        let result = sender_mailbox
            .push(
                recipient_key,
                b"msg-1",
                ciphertext,
                MAX_TTL_SECONDS + 1,
                1_000,
                &solution,
            )
            .await;
        assert!(
            result.is_err(),
            "a ttl beyond MAX_TTL_SECONDS must be rejected"
        );
    }
}
