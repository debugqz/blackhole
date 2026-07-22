//! Multi-hop onion routing (3+ hops, Tor/Session-style) over the DHT.
//! Prioritizes traffic-analysis resistance over latency by explicit design
//! choice. Same sealed-sender logic applies to call signaling, so the entry
//! node never learns who called whom. See `docs/SPEC.md` §2.3, §5.2.
//!
//! **Packet format: real Sphinx (Danezis-Goldberg), via `sphinx-packet`
//! (the Nym mixnet project's own production implementation), not a
//! hand-rolled construction.** An earlier version of this module used a
//! from-scratch, recursively-nested AEAD scheme with bucket padding —
//! real and tested, but provably incapable of hiding position-in-circuit:
//! each outer layer necessarily contains the *entire* previous layer's
//! wrapped packet plus its own header, so it can never be the same size
//! as what it wraps (an outer layer is always strictly larger). That's a
//! mathematical property of recursive AEAD wrapping, not a tuning
//! problem — no amount of extra padding buckets fixes it. Real Sphinx
//! solves this with a genuinely different construction: a *fixed-size*
//! header (independent of real route length, via a precomputed filler
//! string) plus a size-preserving payload cipher (Lioness, a wide-block
//! PRP, not AEAD-with-a-growing-tag). Hand-deriving that filler-string
//! algorithm from scratch is real mixnet-cryptography research — exactly
//! the kind of subtle, easy-to-get-wrong protocol work `docs/SPEC.md`
//! §2.2/§9 gate behind professional cryptographers and formal
//! verification, and exactly what this module's own history already
//! warned about being "the least precedented piece" of this codebase.
//! Depending on `sphinx-packet` (Apache-2.0, ~280k downloads, actively
//! maintained, the real implementation behind Nym's production mixnet)
//! is composition of an existing implementation — the same pattern as
//! `openmls` for MLS — not homegrown protocol crypto.
//!
//! **What this actually buys**: every packet this module produces, for
//! any supported route length (3 to [`MAX_HOPS`]) and any real payload up
//! to the fixed budget, is *exactly* `sphinx_packet::header::HEADER_SIZE
//! + PAYLOAD_SIZE` bytes — provably, not just "usually the same bucket."
//! An observer watching the wire between any two hops cannot distinguish
//! hop position, route length, or real payload size from ciphertext
//! length alone, full stop — see this module's own test
//! `every_hop_of_every_route_length_produces_an_identically_sized_packet`.
//!
//! **The tradeoff, same one every fixed-size mix packet format accepts**:
//! bandwidth, not anonymity, is what's spent to get this — every circuit
//! costs exactly [`PAYLOAD_SIZE`] bytes per hop even for a two-byte
//! message, and real content larger than the fixed budget is rejected
//! outright rather than silently truncated (see [`build_circuit_packet`]).
//! [`PAYLOAD_SIZE`] is sized for ordinary message-sized content (matching
//! `bh_crypto::envelope`'s own largest size bucket), not file transfer —
//! `bh-files` already handles large content through its own
//! chunked/resumable transport, deliberately independent of this module.
//!
//! **Still unreviewed**: depending on a real implementation instead of
//! hand-rolling one closes the specific "will the filler-string math be
//! correct" risk, but this integration itself — the address-hashing
//! scheme, the timestamp/freshness convention layered on top, the fixed
//! payload sizing — has not had independent review, consistent with
//! `docs/SPEC.md` §2.2/§9's standing caveat over every protocol decision
//! in this codebase.
//!
//! **Replay window, now checked only at the exit hop.** The previous
//! AEAD design embedded an authenticated timestamp in *every* layer, so
//! an intermediate hop could reject a stale packet immediately. Sphinx's
//! payload (where this module's own timestamp convention lives, prepended
//! to the real payload — see [`build_circuit_packet`]) stays opaque to
//! every hop except the exit, by design: that's the same property that
//! keeps intermediate hops from learning anything about content. A stale,
//! replayed packet is still never *delivered* (the exit hop rejects it —
//! see [`peel_layer`]), it just isn't rejected until then instead of at
//! hop one. Bounding the replay window at all is what actually matters
//! for the property this exists to protect (SPEC.md §5.2); which hop
//! notices is a secondary concern.

use sha2::{Digest, Sha256};
use sphinx_packet::header::delays::Delay;
use sphinx_packet::packet::builder::SphinxPacketBuilder;
use sphinx_packet::route::{
    Destination, DestinationAddressBytes, Node as SphinxNode, NodeAddressBytes,
};
use sphinx_packet::{ProcessedPacketData, SphinxPacket};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use x25519_dalek_v2::{PublicKey as X25519PublicKeyV2, StaticSecret as X25519SecretV2};

use crate::NetworkError;

pub const MIN_HOPS: usize = 3;
/// `sphinx-packet`'s own compile-time route-length ceiling
/// (`sphinx_packet::constants::MAX_PATH_LENGTH`) — the header is a fixed
/// size built to hold at most this many hop slots.
pub const MAX_HOPS: usize = sphinx_packet::constants::MAX_PATH_LENGTH;

/// How long a packet stays acceptable after it was built — see the
/// module doc on why this is checked only at the exit hop now. There is
/// no per-relay seen-packet cache here (this module is a stateless
/// peeling function; a real dispatch loop to own such a cache's lifetime
/// doesn't exist yet — this crate isn't wired into a live relay path, see
/// CLAUDE.md), so a captured packet can still be replayed verbatim
/// *within* this window.
const MAX_PACKET_AGE_SECONDS: i64 = 300;
/// How far into the future a `created_at` may be before it's rejected as
/// implausible, to tolerate reasonable clock skew between peers without
/// letting a peer mint an ever-fresh-looking replay by lying about time.
const MAX_CLOCK_SKEW_SECONDS: i64 = 60;
/// 8-byte big-endian unix-seconds timestamp, prepended to the real
/// payload before it's handed to Sphinx — see the module doc.
const TIMESTAMP_LEN: usize = 8;
/// Fixed payload budget every packet pays for regardless of real content
/// size — see the module doc's bandwidth-tradeoff note. Matches
/// `bh_crypto::envelope`'s own largest size bucket, since ordinary
/// message-sized content (not file-transfer chunks, which `bh-files`
/// carries separately) is what this module actually needs to fit.
const PAYLOAD_SIZE: usize = 65536;

fn to_v2_public(pk: &X25519PublicKey) -> X25519PublicKeyV2 {
    X25519PublicKeyV2::from(pk.to_bytes())
}

fn to_v2_secret(sk: &X25519Secret) -> X25519SecretV2 {
    X25519SecretV2::from(sk.to_bytes())
}

/// Maps an arbitrary-length libp2p peer id down to Sphinx's fixed
/// 32-byte node address. This module is already a stateless peeling
/// function, not wired into a live relay dispatcher (see CLAUDE.md) —
/// resolving this 32-byte circuit address back to a real transport
/// address (peer id / `Multiaddr`) is exactly the kind of dispatch-loop
/// work already flagged as a separate follow-up, not a regression
/// introduced here.
fn circuit_address(peer_id: &[u8]) -> NodeAddressBytes {
    let hash: [u8; 32] = Sha256::digest(peer_id).into();
    NodeAddressBytes::from_bytes(hash)
}

/// One hop of a route the caller has already chosen (see
/// `eclipse_resistance.rs` for how hops should actually be selected).
pub struct RouteHop {
    pub peer_id: Vec<u8>,
    pub public_key: X25519PublicKey,
}

/// Builds the Sphinx packet to hand to `route[0]` (the entry hop). Each
/// hop can only decrypt its own layer, learning nothing but the previous
/// hop it received from and the next hop to forward to — never the full
/// route, and never the payload unless it's the exit. `now` (unix
/// seconds) is stamped as an 8-byte prefix on `final_payload` so
/// [`peel_layer`] can reject the packet once it's stale at the exit hop
/// — see the module doc on why only there.
pub fn build_circuit_packet(
    route: &[RouteHop],
    final_payload: &[u8],
    now: i64,
) -> Result<Vec<u8>, NetworkError> {
    if route.len() < MIN_HOPS {
        return Err(NetworkError::Setup(format!(
            "onion circuit needs at least {MIN_HOPS} hops, got {}",
            route.len()
        )));
    }
    if route.len() > MAX_HOPS {
        return Err(NetworkError::Setup(format!(
            "onion circuit supports at most {MAX_HOPS} hops, got {}",
            route.len()
        )));
    }

    let sphinx_route: Vec<SphinxNode> = route
        .iter()
        .map(|hop| SphinxNode::new(circuit_address(&hop.peer_id), to_v2_public(&hop.public_key)))
        .collect();

    // Blackhole has no SURB/reply-block concept and delivery is implicit
    // ("this hop is the exit, hand the payload to the caller") — a fixed,
    // unused placeholder destination, identical across every packet this
    // module ever builds, so it can't leak anything by varying.
    let destination = Destination::new(DestinationAddressBytes::from_bytes([0u8; 32]), [0u8; 16]);

    // Zero mix-net timing delay at every hop: this module's job is
    // hiding *position and content*, not adding Loopix-style timing
    // obfuscation — a separate mitigation this codebase doesn't attempt
    // (see `cover_traffic.rs` for the dummy-traffic angle it does take).
    let delays = vec![Delay::new_from_millis(0); route.len()];

    let mut message = Vec::with_capacity(TIMESTAMP_LEN + final_payload.len());
    message.extend_from_slice(&now.to_be_bytes());
    message.extend_from_slice(final_payload);

    let packet = SphinxPacketBuilder::default()
        .with_payload_size(PAYLOAD_SIZE)
        .build_packet(message, &sphinx_route, &destination, &delays)
        .map_err(|e| NetworkError::Setup(format!("onion: failed to build packet: {e}")))?;

    Ok(packet.to_bytes())
}

/// What a relay does with a packet it just received: either forward the
/// remainder to `next_hop`, or deliver `payload` locally (this hop is the
/// exit).
pub enum PeelResult {
    Forward { next_hop: Vec<u8>, packet: Vec<u8> },
    Deliver { payload: Vec<u8> },
}

/// A relay's side: peel exactly one layer using its own static X25519
/// secret. At the exit hop, the authenticated `created_at` prefix is
/// checked against `[now - MAX_PACKET_AGE_SECONDS, now + MAX_CLOCK_SKEW_SECONDS]`
/// — see the module doc on why only the exit hop can check this.
pub fn peel_layer(
    my_secret: &X25519Secret,
    packet_bytes: &[u8],
    now: i64,
) -> Result<PeelResult, NetworkError> {
    let packet = SphinxPacket::from_bytes(packet_bytes)
        .map_err(|e| NetworkError::Query(format!("onion: malformed packet: {e}")))?;
    let processed = packet
        .process(&to_v2_secret(my_secret))
        .map_err(|e| NetworkError::Query(format!("onion: failed to peel layer: {e}")))?;

    match processed.data {
        ProcessedPacketData::ForwardHop {
            next_hop_packet,
            next_hop_address,
            ..
        } => Ok(PeelResult::Forward {
            next_hop: next_hop_address.as_bytes().to_vec(),
            packet: next_hop_packet.to_bytes(),
        }),
        ProcessedPacketData::FinalHop { payload, .. } => {
            let plaintext = payload.recover_plaintext().map_err(|e| {
                NetworkError::Query(format!("onion: failed to recover payload: {e}"))
            })?;
            if plaintext.len() < TIMESTAMP_LEN {
                return Err(NetworkError::Query(
                    "onion: payload too short to contain a timestamp".to_string(),
                ));
            }
            let (ts_bytes, payload_bytes) = plaintext.split_at(TIMESTAMP_LEN);
            let created_at = i64::from_be_bytes(ts_bytes.try_into().expect("split at 8 bytes"));

            let age = now.saturating_sub(created_at);
            if !(-MAX_CLOCK_SKEW_SECONDS..=MAX_PACKET_AGE_SECONDS).contains(&age) {
                return Err(NetworkError::Query(format!(
                    "onion: packet is outside the acceptable freshness window (age {age}s)"
                )));
            }

            Ok(PeelResult::Deliver {
                payload: payload_bytes.to_vec(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Relay {
        peer_id: Vec<u8>,
        secret: X25519Secret,
    }

    impl Relay {
        fn new(peer_id: &str) -> Self {
            Self {
                peer_id: peer_id.as_bytes().to_vec(),
                secret: X25519Secret::random(),
            }
        }

        fn route_hop(&self) -> RouteHop {
            RouteHop {
                peer_id: self.peer_id.clone(),
                public_key: X25519PublicKey::from(&self.secret),
            }
        }
    }

    fn relays(n: usize) -> Vec<Relay> {
        (0..n).map(|i| Relay::new(&format!("relay-{i}"))).collect()
    }

    #[test]
    fn three_hop_circuit_delivers_payload_to_exit() {
        let relays = relays(3);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();

        let mut packet = build_circuit_packet(&route, b"hello via onion", 1_000).unwrap();

        for (i, relay) in relays.iter().enumerate() {
            match peel_layer(&relay.secret, &packet, 1_000).unwrap() {
                PeelResult::Forward {
                    next_hop,
                    packet: forwarded,
                } => {
                    assert!(i < relays.len() - 1, "only non-exit hops should forward");
                    assert_eq!(next_hop, circuit_address(&relays[i + 1].peer_id).as_bytes());
                    packet = forwarded;
                }
                PeelResult::Deliver { payload } => {
                    assert_eq!(i, relays.len() - 1, "only the exit hop should deliver");
                    assert_eq!(payload, b"hello via onion");
                }
            }
        }
    }

    #[test]
    fn intermediate_hops_cannot_read_final_payload() {
        let relays = relays(3);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let packet = build_circuit_packet(&route, b"secret payload", 1_000).unwrap();

        assert!(!packet
            .windows(b"secret payload".len())
            .any(|w| w == b"secret payload"));

        match peel_layer(&relays[0].secret, &packet, 1_000).unwrap() {
            PeelResult::Forward {
                packet: forwarded, ..
            } => {
                assert!(!forwarded
                    .windows(b"secret payload".len())
                    .any(|w| w == b"secret payload"));
            }
            PeelResult::Deliver { .. } => panic!("relay 1 is not the exit"),
        }
    }

    #[test]
    fn wrong_relay_key_fails_to_peel() {
        let relays = relays(3);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let packet = build_circuit_packet(&route, b"payload", 1_000).unwrap();

        let impostor = Relay::new("not-relay-1");
        assert!(peel_layer(&impostor.secret, &packet, 1_000).is_err());
    }

    /// Regression test bounding the replay window: the exit hop must
    /// reject a packet whose authenticated `created_at` is further in the
    /// past than `MAX_PACKET_AGE_SECONDS`, or further in the future than
    /// `MAX_CLOCK_SKEW_SECONDS` — see the module doc on why only the exit
    /// hop can check this with the Sphinx payload format.
    #[test]
    fn peel_layer_rejects_a_stale_or_implausibly_future_packet_at_the_exit() {
        let relays = relays(3);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();

        let fresh_ok = |built_at: i64, checked_at: i64| {
            let mut packet = build_circuit_packet(&route, b"payload", built_at).unwrap();
            for relay in &relays {
                match peel_layer(&relay.secret, &packet, checked_at) {
                    Ok(PeelResult::Forward {
                        packet: forwarded, ..
                    }) => packet = forwarded,
                    Ok(PeelResult::Deliver { .. }) => return Ok(()),
                    Err(e) => return Err(e),
                }
            }
            unreachable!("3-hop route must deliver by the third peel")
        };

        assert!(fresh_ok(1_000, 1_000).is_ok());
        assert!(fresh_ok(1_000, 1_000 + MAX_PACKET_AGE_SECONDS).is_ok());
        assert!(
            fresh_ok(1_000, 1_000 + MAX_PACKET_AGE_SECONDS + 1).is_err(),
            "a packet older than MAX_PACKET_AGE_SECONDS must be rejected"
        );
        assert!(
            fresh_ok(1_000, 1_000 - MAX_CLOCK_SKEW_SECONDS - 1).is_err(),
            "a packet claiming to be from further in the future than clock skew allows must be rejected"
        );
    }

    #[test]
    fn rejects_routes_shorter_than_minimum_hops() {
        let relays = relays(2);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        assert!(build_circuit_packet(&route, b"payload", 1_000).is_err());
    }

    #[test]
    fn rejects_routes_longer_than_max_hops() {
        let relays = relays(MAX_HOPS + 1);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        assert!(build_circuit_packet(&route, b"payload", 1_000).is_err());
    }

    #[test]
    fn works_at_the_maximum_supported_hop_count() {
        let relays = relays(MAX_HOPS);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let mut packet = build_circuit_packet(&route, b"max hop payload", 1_000).unwrap();

        for relay in &relays {
            match peel_layer(&relay.secret, &packet, 1_000).unwrap() {
                PeelResult::Forward {
                    packet: forwarded, ..
                } => packet = forwarded,
                PeelResult::Deliver { payload } => {
                    assert_eq!(payload, b"max hop payload");
                }
            }
        }
    }

    /// The actual property this whole rewrite is about: every hop of
    /// every supported route length, for payloads from tiny up to the
    /// fixed budget, produces a wire packet of *exactly* the same length
    /// — not "usually the same bucket" the way the old AEAD design's
    /// bucket-padding scheme only approximated.
    #[test]
    fn every_hop_of_every_route_length_produces_an_identically_sized_packet() {
        let mut sizes = std::collections::HashSet::new();

        for hop_count in MIN_HOPS..=MAX_HOPS {
            let relays = relays(hop_count);
            let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();

            for payload in [b"hi".to_vec(), vec![b'x'; 300], vec![b'y'; 40_000]] {
                let mut packet = build_circuit_packet(&route, &payload, 1_000).unwrap();
                sizes.insert(packet.len());
                for relay in &relays {
                    match peel_layer(&relay.secret, &packet, 1_000).unwrap() {
                        PeelResult::Forward {
                            packet: forwarded, ..
                        } => {
                            sizes.insert(forwarded.len());
                            packet = forwarded;
                        }
                        PeelResult::Deliver { .. } => break,
                    }
                }
            }
        }

        assert_eq!(
            sizes.len(),
            1,
            "every packet at every hop of every route length/payload size must be the same length, got {sizes:?}"
        );
    }

    #[test]
    fn oversized_payload_is_rejected_not_truncated_or_panicked_on() {
        let relays = relays(3);
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        // Past the fixed payload budget — must be a clean error, not a
        // panic or silent truncation.
        let too_big = vec![b'z'; PAYLOAD_SIZE * 2];
        assert!(build_circuit_packet(&route, &too_big, 1_000).is_err());
    }
}
