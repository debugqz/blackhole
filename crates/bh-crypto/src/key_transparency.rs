//! Key Transparency client-side log (SPEC.md §2.4): an append-only Merkle
//! tree over (identity, public key) log entries, in the same spirit as
//! Certificate Transparency (RFC 6962) and Signal's own Key Transparency —
//! it lets a client detect the network handing out a *different* public
//! key for a contact than what the rest of the network sees, closing the
//! silent-MITM gap noted in `docs/THREAT_MODEL.md` §3.1.
//!
//! **This implements only the tree math and client-side proof
//! verification** — inclusion proofs (this identity's key really is in
//! the log) and consistency proofs (the log only ever grew, nothing was
//! rewritten or reordered). There is no deployed public log service here:
//! running one — accepting appends, publishing signed tree heads, serving
//! proofs to clients — is infrastructure, out of scope per this project's
//! existing infra/no-infra boundary (same reasoning as the DHT/mailbox
//! network itself). What's here is what a client runs *against* that
//! server's responses to actually catch it lying, not the server.
//!
//! Hashing follows RFC 6962 §2.1 exactly (domain-separated leaf/node
//! hashes via a 0x00/0x01 prefix, preventing second-preimage confusion
//! between a leaf and an internal node) — composed entirely from SHA-256,
//! an audited primitive, per SPEC.md §2.2.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

const LEAF_HASH_PREFIX: u8 = 0x00;
const NODE_HASH_PREFIX: u8 = 0x01;

fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_HASH_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_HASH_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn empty_tree_hash() -> Hash {
    Sha256::digest([]).into()
}

/// RFC 6962's tree-splitting rule: the largest power of two strictly
/// smaller than `n`. Every recursive tree operation below splits a range
/// of `n` leaves at this point, which is what makes the resulting tree
/// shape — and therefore every hash in it — deterministic given only the
/// leaf count.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// RFC 6962 §2.1 MTH: the Merkle Tree Hash of already-leaf-hashed data.
pub fn tree_hash(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_tree_hash(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&tree_hash(&leaves[..k]), &tree_hash(&leaves[k..]))
        }
    }
}

/// One entry in the log: an identity's public key as of some point in
/// time. `identity_id` and `public_key` are hashed together into the leaf
/// — callers decide what identifies "identity" (e.g. a contact_id) and
/// what "public key" means (e.g. the concatenated signing+agreement
/// bytes `bh_crypto::identity::IdentityKeyPair` already uses elsewhere).
pub fn entry_hash(identity_id: &[u8], public_key: &[u8], sequence: u64) -> Hash {
    let mut data = Vec::with_capacity(identity_id.len() + public_key.len() + 8);
    data.extend_from_slice(&(identity_id.len() as u32).to_be_bytes());
    data.extend_from_slice(identity_id);
    data.extend_from_slice(public_key);
    data.extend_from_slice(&sequence.to_be_bytes());
    leaf_hash(&data)
}

/// RFC 6962 §2.1.1 PATH: the audit path proving `leaves[index]` is
/// included in `tree_hash(leaves)`. Ordered leaf-to-root: `proof[0]` is
/// the sibling closest to the leaf, `proof.last()` the one closest to the
/// root.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Vec<Hash> {
    fn go(leaves: &[Hash], m: usize) -> Vec<Hash> {
        let n = leaves.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = split_point(n);
        if m < k {
            let mut path = go(&leaves[..k], m);
            path.push(tree_hash(&leaves[k..]));
            path
        } else {
            let mut path = go(&leaves[k..], m - k);
            path.push(tree_hash(&leaves[..k]));
            path
        }
    }
    go(leaves, index)
}

/// Verifies an inclusion proof without needing the full leaf list — just
/// the leaf itself, its claimed position, the tree size the proof was
/// issued against, and the (independently obtained, trusted) root for
/// that size. Structurally mirrors [`inclusion_proof`]'s recursion so the
/// two stay in lockstep by construction rather than by two independently
/// written implementations agreeing by luck.
pub fn verify_inclusion(
    leaf: &Hash,
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    fn recompute(leaf: &Hash, m: usize, n: usize, proof: &[Hash]) -> Option<Hash> {
        if n <= 1 {
            return if proof.is_empty() { Some(*leaf) } else { None };
        }
        let k = split_point(n);
        let (sibling, rest) = proof.split_last()?;
        if m < k {
            Some(node_hash(&recompute(leaf, m, k, rest)?, sibling))
        } else {
            Some(node_hash(sibling, &recompute(leaf, m - k, n - k, rest)?))
        }
    }
    index < tree_size && recompute(leaf, index, tree_size, proof) == Some(*root)
}

/// RFC 6962 §2.1.2 SUBPROOF: a consistency proof that the tree of size `n`
/// is an append-only extension of the tree of size `m` (`0 < m <= n`).
/// `have_root` is the top-level `PROOF` entry point (`true`); the `false`
/// case is used internally when a subtree's hash is needed as a sibling
/// rather than as (part of) the direct path to the old root.
fn subproof(leaves: &[Hash], m: usize, have_root: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if have_root {
            Vec::new()
        } else {
            vec![tree_hash(leaves)]
        };
    }
    let k = split_point(n);
    if m <= k {
        let mut proof = subproof(&leaves[..k], m, have_root);
        proof.push(tree_hash(&leaves[k..]));
        proof
    } else {
        let mut proof = subproof(&leaves[k..], m - k, false);
        proof.push(tree_hash(&leaves[..k]));
        proof
    }
}

/// Builds a proof that the first `old_size` leaves of `leaves` hash to the
/// same root they did when the log was that size — i.e. nothing before
/// `old_size` was altered, inserted before, or reordered as the log grew
/// to its current size. `old_size` must be at least 1 and at most
/// `leaves.len()`.
pub fn consistency_proof(leaves: &[Hash], old_size: usize) -> Vec<Hash> {
    if old_size == 0 || old_size > leaves.len() {
        return Vec::new();
    }
    subproof(leaves, old_size, true)
}

/// Verifies a consistency proof without needing the full leaf list: given
/// the two claimed roots (independently obtained/trusted) and their tree
/// sizes, checks the proof actually connects them.
///
/// `recompute` mirrors `subproof`'s recursion and returns, for the subtree
/// at each level, `(hash of its leftmost `m`-leaf prefix, hash of the full
/// subtree)`. The key move — and the reason consistency proofs work at
/// all — is the `m == n, have_root` base case: by construction, whenever
/// the recursive left-aligned split brings `m` (the old size) exactly even
/// with the current subtree's size, that subtree *is* the old tree, so its
/// hash is `old_root` by definition. No proof entry is needed there
/// (matching `subproof` emitting none), and that trusted value is what
/// propagates upward, combined with proof-supplied sibling hashes, into
/// the final new-tree root. `computed_new == new_root` only holds if those
/// siblings genuinely are the unchanged parts of the tree — a proof built
/// from a rewritten or reordered history can't make both checks pass
/// without a SHA-256 collision.
pub fn verify_consistency(
    old_size: usize,
    old_root: &Hash,
    new_size: usize,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    fn recompute(
        m: usize,
        n: usize,
        have_root: bool,
        old_root: &Hash,
        proof: &[Hash],
    ) -> Option<(Hash, Hash)> {
        if m == n {
            if have_root {
                return if proof.is_empty() {
                    Some((*old_root, *old_root))
                } else {
                    None
                };
            }
            let (&hash, rest) = proof.split_last()?;
            return if rest.is_empty() {
                Some((hash, hash))
            } else {
                None
            };
        }
        let k = split_point(n);
        let (&sibling, rest) = proof.split_last()?;
        if m <= k {
            let (prefix, new_left) = recompute(m, k, have_root, old_root, rest)?;
            Some((prefix, node_hash(&new_left, &sibling)))
        } else {
            let (prefix, new_right) = recompute(m - k, n - k, false, old_root, rest)?;
            Some((
                node_hash(&sibling, &prefix),
                node_hash(&sibling, &new_right),
            ))
        }
    }

    match recompute(old_size, new_size, true, old_root, proof) {
        Some((computed_old, computed_new)) => {
            &computed_old == old_root && &computed_new == new_root
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n as u64)
            .map(|i| entry_hash(b"alice", b"pubkey-bytes", i))
            .collect()
    }

    #[test]
    fn empty_tree_hash_matches_sha256_of_empty_string() {
        assert_eq!(tree_hash(&[]), Sha256::digest([]).as_slice());
    }

    #[test]
    fn single_leaf_tree_hash_is_the_leaf_itself() {
        let l = leaves(1);
        assert_eq!(tree_hash(&l), l[0]);
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_across_many_tree_sizes() {
        for n in 1..=32usize {
            let l = leaves(n);
            let root = tree_hash(&l);
            for m in 0..n {
                let proof = inclusion_proof(&l, m);
                assert!(
                    verify_inclusion(&l[m], m, n, &proof, &root),
                    "inclusion failed for leaf {m} in a tree of size {n}"
                );
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_the_wrong_leaf() {
        let l = leaves(8);
        let root = tree_hash(&l);
        let proof = inclusion_proof(&l, 3);
        assert!(!verify_inclusion(&l[4], 3, 8, &proof, &root));
    }

    #[test]
    fn inclusion_proof_rejects_a_tampered_proof_entry() {
        let l = leaves(8);
        let root = tree_hash(&l);
        let mut proof = inclusion_proof(&l, 3);
        proof[0][0] ^= 0xFF;
        assert!(!verify_inclusion(&l[3], 3, 8, &proof, &root));
    }

    #[test]
    fn inclusion_proof_rejects_the_wrong_root() {
        let l = leaves(8);
        let other_root = tree_hash(&leaves(9));
        let proof = inclusion_proof(&l, 3);
        assert!(!verify_inclusion(&l[3], 3, 8, &proof, &other_root));
    }

    #[test]
    fn consistency_proofs_verify_across_many_size_pairs() {
        for n in 1..=32usize {
            let new_leaves = leaves(n);
            let new_root = tree_hash(&new_leaves);
            for m in 1..=n {
                let old_leaves = &new_leaves[..m];
                let old_root = tree_hash(old_leaves);
                let proof = consistency_proof(&new_leaves, m);
                assert!(
                    verify_consistency(m, &old_root, n, &new_root, &proof),
                    "consistency failed for old_size={m}, new_size={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_a_log_that_rewrote_history() {
        // Same size, but entry 2 changed after the "old" snapshot was
        // taken — simulates a malicious log silently swapping a key.
        let old_leaves = leaves(8);
        let old_root = tree_hash(&old_leaves);

        let mut tampered = leaves(8);
        tampered.push(entry_hash(b"alice", b"pubkey-bytes", 8));
        tampered[2] = entry_hash(b"mallory-swapped-key", b"evil", 2);
        let new_root = tree_hash(&tampered);

        let proof = consistency_proof(&tampered, 8);
        assert!(!verify_consistency(8, &old_root, 9, &new_root, &proof));
    }

    #[test]
    fn consistency_proof_rejects_reordered_history() {
        let old_leaves = leaves(4);
        let old_root = tree_hash(&old_leaves);

        let mut reordered = old_leaves.clone();
        reordered.swap(0, 1);
        reordered.push(entry_hash(b"alice", b"pubkey-bytes", 4));
        let new_root = tree_hash(&reordered);

        let proof = consistency_proof(&reordered, 4);
        assert!(!verify_consistency(4, &old_root, 5, &new_root, &proof));
    }

    #[test]
    fn consistency_proof_for_equal_sizes_is_trivially_valid_only_for_the_same_root() {
        let l = leaves(5);
        let root = tree_hash(&l);
        assert!(verify_consistency(5, &root, 5, &root, &[]));

        let other_root = tree_hash(&leaves(6));
        assert!(!verify_consistency(5, &root, 5, &other_root, &[]));
    }
}
