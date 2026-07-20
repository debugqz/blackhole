//! Onion circuit node selection resistant to Eclipse/Sybil attacks
//! (SPEC.md §5.2): never pick "closest peers" by DHT XOR-distance — that
//! metric is exactly what an attacker games by mining peer IDs close to a
//! target, which is the classic S/Kademlia Eclipse attack. Instead:
//!
//! 1. **Verifiable, unpredictable ordering** — candidates are ranked by
//!    `HMAC-SHA256(seed, peer_id)`, not by anything derived from the
//!    peer_id alone. Given the same seed, anyone can recompute and audit
//!    the ranking (verifiable); an attacker choosing a peer_id has no way
//!    to predict where it'll rank without already knowing the seed
//!    (unpredictable) — the caller should draw `seed` fresh per circuit
//!    from a source the attacker doesn't control in advance.
//! 2. **Forced subnet/operator diversity** — no two selected hops may
//!    share a `subnet_key` (the caller supplies this; a real deployment
//!    would derive it from IP prefix and/or ASN, not something this crate
//!    has a database for).

use std::collections::HashSet;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::NetworkError;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct NodeCandidate {
    pub peer_id: Vec<u8>,
    pub public_key: X25519PublicKey,
    /// Diversity grouping key — e.g. an IP /24 prefix. Two candidates with
    /// the same key are treated as "could be the same operator" and never
    /// both selected into one circuit.
    pub subnet_key: Vec<u8>,
}

fn rank_score(seed: &[u8], peer_id: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(peer_id);
    mac.finalize().into_bytes().into()
}

/// Selects `hop_count` subnet-diverse candidates, ordered by an
/// HMAC-keyed-on-`seed` score rather than DHT closeness. Errors if there
/// aren't enough diverse candidates to fill every hop.
pub fn select_circuit_nodes(
    candidates: &[NodeCandidate],
    hop_count: usize,
    seed: &[u8],
) -> Result<Vec<NodeCandidate>, NetworkError> {
    if candidates.len() < hop_count {
        return Err(NetworkError::Setup(format!(
            "need {hop_count} candidates, only {} available",
            candidates.len()
        )));
    }

    let mut ranked: Vec<(&NodeCandidate, [u8; 32])> = candidates
        .iter()
        .map(|c| (c, rank_score(seed, &c.peer_id)))
        .collect();
    ranked.sort_by_key(|(_, score)| *score);

    let mut selected = Vec::with_capacity(hop_count);
    let mut used_subnets: HashSet<&[u8]> = HashSet::new();
    for (candidate, _) in &ranked {
        if selected.len() == hop_count {
            break;
        }
        if !used_subnets.insert(candidate.subnet_key.as_slice()) {
            continue;
        }
        selected.push((*candidate).clone());
    }

    if selected.len() < hop_count {
        return Err(NetworkError::Setup(format!(
            "not enough subnet-diverse candidates: needed {hop_count} distinct subnets, found {}",
            selected.len()
        )));
    }

    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret as X25519Secret;

    fn candidate(id: &str, subnet: &str) -> NodeCandidate {
        NodeCandidate {
            peer_id: id.as_bytes().to_vec(),
            public_key: X25519PublicKey::from(&X25519Secret::random()),
            subnet_key: subnet.as_bytes().to_vec(),
        }
    }

    #[test]
    fn selection_is_deterministic_for_a_fixed_seed() {
        let candidates = vec![
            candidate("a", "10.0.0.0/24"),
            candidate("b", "10.0.1.0/24"),
            candidate("c", "10.0.2.0/24"),
            candidate("d", "10.0.3.0/24"),
        ];
        let seed = b"circuit-seed-1";

        let first = select_circuit_nodes(&candidates, 3, seed).unwrap();
        let second = select_circuit_nodes(&candidates, 3, seed).unwrap();

        let first_ids: Vec<_> = first.iter().map(|c| c.peer_id.clone()).collect();
        let second_ids: Vec<_> = second.iter().map(|c| c.peer_id.clone()).collect();
        assert_eq!(first_ids, second_ids);
    }

    #[test]
    fn different_seeds_produce_different_orderings() {
        let candidates = vec![
            candidate("a", "10.0.0.0/24"),
            candidate("b", "10.0.1.0/24"),
            candidate("c", "10.0.2.0/24"),
            candidate("d", "10.0.3.0/24"),
            candidate("e", "10.0.4.0/24"),
        ];

        let a = select_circuit_nodes(&candidates, 3, b"seed-a").unwrap();
        let b = select_circuit_nodes(&candidates, 3, b"seed-b").unwrap();

        let a_ids: Vec<_> = a.iter().map(|c| c.peer_id.clone()).collect();
        let b_ids: Vec<_> = b.iter().map(|c| c.peer_id.clone()).collect();
        assert_ne!(
            a_ids, b_ids,
            "two different seeds picked the identical ordered set"
        );
    }

    #[test]
    fn never_selects_two_hops_from_the_same_subnet() {
        // Three candidates share one subnet — the selector must skip the
        // extras rather than pick two hops an attacker controlling that
        // subnet could correlate.
        let candidates = vec![
            candidate("sybil-1", "10.0.0.0/24"),
            candidate("sybil-2", "10.0.0.0/24"),
            candidate("sybil-3", "10.0.0.0/24"),
            candidate("honest-1", "10.0.1.0/24"),
            candidate("honest-2", "10.0.2.0/24"),
        ];

        let selected = select_circuit_nodes(&candidates, 3, b"any-seed").unwrap();
        let subnets: HashSet<_> = selected.iter().map(|c| c.subnet_key.clone()).collect();
        assert_eq!(
            subnets.len(),
            3,
            "all three selected hops must be in distinct subnets"
        );
    }

    #[test]
    fn errors_when_not_enough_diverse_subnets_exist() {
        let candidates = vec![
            candidate("a", "10.0.0.0/24"),
            candidate("b", "10.0.0.0/24"),
            candidate("c", "10.0.1.0/24"),
        ];
        // Only 2 distinct subnets available, but 3 hops requested.
        assert!(select_circuit_nodes(&candidates, 3, b"seed").is_err());
    }

    #[test]
    fn errors_when_fewer_candidates_than_hops() {
        let candidates = vec![candidate("a", "10.0.0.0/24")];
        assert!(select_circuit_nodes(&candidates, 3, b"seed").is_err());
    }
}
