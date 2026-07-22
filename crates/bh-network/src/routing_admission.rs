//! Kademlia routing-table admission control (SPEC.md §5.2). Complements
//! `eclipse_resistance.rs`, which only bounds *circuit-hop selection* —
//! this bounds the routing table itself, the actual place an attacker's
//! Sybil peers get in at all. `transport.rs`'s `handle_swarm_event` calls
//! `kad.add_address` unconditionally for every peer that connects and
//! responds to Identify; this module gates that call.
//!
//! Same subnet-diversity principle as `eclipse_resistance.rs`, applied
//! network-wide instead of per-circuit: no more than [`DEFAULT_MAX_PEERS_PER_SUBNET`]
//! distinct peer ids from the same IP-prefix "subnet" are ever admitted
//! into the routing table. **Known limitation, same honesty this whole
//! threat model applies elsewhere**: this is not a full S/Kademlia
//! rewrite. There's no proof-of-work cost to admission, and "subnet" is
//! only as meaningful as the peer's *observed* connection address — an
//! attacker with real IP diversity (e.g. a real /24 worth of addresses,
//! or many different cloud providers) isn't slowed down by this at all.
//! It closes the "unlimited Sybil peers from one address block" version
//! of the problem, not Sybil resistance in general (`docs/THREAT_MODEL.md`
//! §3.5).

use std::collections::{HashMap, HashSet};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

/// How many distinct peer ids from the same subnet may be admitted into
/// the routing table. Generous enough not to break legitimate deployments
/// on shared infrastructure (a hosting provider's whole /24, several
/// Blackhole nodes behind one NAT, etc.) while bounding how much of the
/// table one address block can dominate.
pub const DEFAULT_MAX_PEERS_PER_SUBNET: usize = 4;

/// IPv4 groups by /24, IPv6 by /48 — coarse enough to catch "many
/// addresses from the same allocation" without a real IP→ASN database
/// (this crate doesn't have one — same caveat `eclipse_resistance.rs`
/// already states about `subnet_key`).
fn subnet_key_for_addr(addr: &Multiaddr) -> Option<Vec<u8>> {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(v4) => {
                let octets = v4.octets();
                return Some(vec![octets[0], octets[1], octets[2]]);
            }
            Protocol::Ip6(v6) => {
                let segments = v6.segments();
                return Some(segments[..3].iter().flat_map(|s| s.to_be_bytes()).collect());
            }
            _ => continue,
        }
    }
    None
}

/// Tracks which peer ids have been admitted into the routing table from
/// which subnets, and decides whether a new admission should be allowed.
#[derive(Default)]
pub struct RoutingAdmission {
    per_subnet: HashMap<Vec<u8>, HashSet<PeerId>>,
    max_per_subnet: usize,
}

impl RoutingAdmission {
    pub fn new() -> Self {
        Self {
            per_subnet: HashMap::new(),
            max_per_subnet: DEFAULT_MAX_PEERS_PER_SUBNET,
        }
    }

    #[cfg(test)]
    fn with_max_per_subnet(max_per_subnet: usize) -> Self {
        Self {
            per_subnet: HashMap::new(),
            max_per_subnet,
        }
    }

    /// Returns `true` if `peer_id`/`addr` should be admitted into the
    /// routing table (the caller should then call `kad.add_address`),
    /// `false` if the subnet `addr` belongs to has already reached the
    /// cap with *other* peer ids. An address with no IP component (e.g. a
    /// relay-only address) is always admitted — there's nothing to bound
    /// a diversity check against.
    ///
    /// Idempotent for a peer id already recorded under this subnet: a
    /// peer re-announcing (or announcing a second address in the same
    /// subnet) doesn't consume a fresh slot.
    pub fn try_admit(&mut self, peer_id: PeerId, addr: &Multiaddr) -> bool {
        let Some(subnet_key) = subnet_key_for_addr(addr) else {
            return true;
        };
        let peers = self.per_subnet.entry(subnet_key).or_default();
        if peers.contains(&peer_id) {
            return true;
        }
        if peers.len() >= self.max_per_subnet {
            return false;
        }
        peers.insert(peer_id);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr_v4(a: u8, b: u8, c: u8, d: u8) -> Multiaddr {
        format!("/ip4/{a}.{b}.{c}.{d}/tcp/4001").parse().unwrap()
    }

    #[test]
    fn admits_up_to_the_cap_from_one_subnet_then_rejects_further_new_peers() {
        let mut admission = RoutingAdmission::with_max_per_subnet(2);
        let addr = addr_v4(10, 0, 0, 1);

        assert!(admission.try_admit(PeerId::random(), &addr));
        assert!(admission.try_admit(PeerId::random(), &addr));
        assert!(
            !admission.try_admit(PeerId::random(), &addr),
            "a third distinct peer from an already-full subnet must be rejected"
        );
    }

    #[test]
    fn re_admitting_an_already_known_peer_does_not_consume_a_fresh_slot() {
        let mut admission = RoutingAdmission::with_max_per_subnet(1);
        let addr = addr_v4(10, 0, 0, 1);
        let peer = PeerId::random();

        assert!(admission.try_admit(peer, &addr));
        assert!(
            admission.try_admit(peer, &addr),
            "the same peer id re-announcing must not be rejected just because the subnet is at capacity"
        );
    }

    #[test]
    fn peers_from_distinct_subnets_are_always_admitted() {
        let mut admission = RoutingAdmission::with_max_per_subnet(1);
        assert!(admission.try_admit(PeerId::random(), &addr_v4(10, 0, 0, 1)));
        assert!(admission.try_admit(PeerId::random(), &addr_v4(10, 0, 1, 1)));
        assert!(admission.try_admit(PeerId::random(), &addr_v4(192, 168, 1, 1)));
    }

    #[test]
    fn same_subnet_different_host_bits_still_counts_as_the_same_subnet() {
        let mut admission = RoutingAdmission::with_max_per_subnet(1);
        assert!(admission.try_admit(PeerId::random(), &addr_v4(10, 0, 0, 1)));
        assert!(
            !admission.try_admit(PeerId::random(), &addr_v4(10, 0, 0, 250)),
            "different host bits within the same /24 must still share the cap"
        );
    }

    #[test]
    fn an_address_with_no_ip_component_is_always_admitted() {
        let mut admission = RoutingAdmission::with_max_per_subnet(0);
        let relay_addr: Multiaddr = format!("/p2p/{}", PeerId::random()).parse().unwrap();
        assert!(admission.try_admit(PeerId::random(), &relay_addr));
    }
}
