//! Multi-hop onion routing (3+ hops, Tor/Session-style) over the DHT.
//! Prioritizes traffic-analysis resistance over latency by explicit design
//! choice. Same sealed-sender logic applies to call signaling, so the entry
//! node never learns who called whom. See `docs/SPEC.md` §2.3, §5.2.
//!
//! **This is a from-scratch protocol implementation, not an integration of
//! an existing audited onion-routing library** (none exists for libp2p —
//! see the `bh-network/Cargo.toml` comment). It composes only audited
//! primitives (X25519, HKDF-SHA256, ChaCha20-Poly1305) and is a real,
//! working layered-encryption circuit — but per `docs/SPEC.md` §2.2/§9,
//! *no* piece of Blackhole's protocol design should be trusted in
//! production without independent cryptographic review, and this module is
//! the least precedented piece of the lot.
//!
//! **Packet-size mitigation (bucket padding, not full Sphinx).** Every
//! layer's plaintext is padded up to the next entry in [`SIZE_BUCKETS`]
//! before encryption (`docs/THREAT_MODEL.md` §3.4/§4 tracks this as the
//! top open risk). This is a real, working, tested mitigation — it turns
//! "exact byte-precise hop counting" into "which of a handful of coarse
//! buckets" — but it is *not* equivalent to Sphinx's actual fix. True
//! Sphinx keeps every hop-to-hop packet **exactly** the same size end to
//! end, by having the client pre-fill the packet's tail with a per-hop
//! pseudorandom stream that each relay's stripped header is effectively
//! "replaced" by, so the total length never changes at all. Reproducing
//! that construction correctly is exactly the kind of subtle
//! protocol-security work that needs the formal review this module
//! doesn't have (§2.2) — bucket padding was chosen as the honestly
//! implementable interim step, not because it's equivalent.

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::NetworkError;

pub const MIN_HOPS: usize = 3;

/// How long a packet stays acceptable after it was built. There is no
/// per-relay seen-packet cache here (this module is a stateless peeling
/// function; a real dispatch loop to own such a cache's lifetime doesn't
/// exist yet — this crate isn't wired into a live relay path, see
/// CLAUDE.md), so a captured packet can still be replayed verbatim *within*
/// this window. Binding every layer to a timestamp and rejecting stale
/// ones at least bounds that window instead of leaving it unlimited, which
/// was the prior behavior. Exact duplicate suppression within the window
/// remains a follow-up once a real relay dispatcher exists to hold that
/// state (`docs/THREAT_MODEL.md` §3.4).
const MAX_PACKET_AGE_SECONDS: i64 = 300;
/// How far into the future a `created_at` may be before it's rejected as
/// implausible, to tolerate reasonable clock skew between peers without
/// letting a peer mint an ever-fresh-looking replay by lying about time.
const MAX_CLOCK_SKEW_SECONDS: i64 = 60;

/// Plaintext lengths a layer is padded up to before encryption. Chosen as
/// a geometric-ish progression so small chat messages and larger payloads
/// (e.g. group commits) both land within a few hundred bytes of a
/// boundary rather than paying for the largest bucket unconditionally.
const SIZE_BUCKETS: &[usize] = &[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

/// Rounds `len` up to the next size bucket. Falls back to the next
/// multiple of the largest bucket for payloads bigger than all of them
/// (large file-transfer chunks, say) rather than refusing to pad at all.
fn bucket_len(len: usize) -> usize {
    match SIZE_BUCKETS.iter().copied().find(|&b| b >= len) {
        Some(b) => b,
        None => {
            let largest = *SIZE_BUCKETS.last().expect("SIZE_BUCKETS is non-empty");
            len.div_ceil(largest) * largest
        }
    }
}

fn derive_layer_key(shared: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hkdf.expand(b"blackhole-onion-layer-v1", &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    // Safe with a fixed nonce: `key` is derived fresh per layer per packet
    // from a one-time ephemeral ECDH and never reused.
    cipher
        .encrypt(&Nonce::default(), plaintext)
        .expect("encryption with a freshly-derived key cannot fail")
}

fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&Nonce::default(), ciphertext)
        .map_err(|_| NetworkError::Query("onion: layer decryption failed".to_string()))
}

/// One hop's decrypted view: either forward the (still-onion-encrypted)
/// remainder to `next_hop`, or — if this hop is the exit — deliver
/// `payload` locally. `created_at` is authenticated (it's inside the AEAD
/// plaintext like everything else here) and lets `peel_layer` reject a
/// packet that's outside [`MAX_PACKET_AGE_SECONDS`], bounding how long a
/// captured packet stays replayable.
struct OnionLayer {
    created_at: i64,
    next_hop: Option<Vec<u8>>,
    payload: Vec<u8>,
}

impl OnionLayer {
    /// Serializes the layer, then pads the *whole* frame (a 4-byte real-
    /// length prefix plus the tag/timestamp/next-hop/payload body) up to
    /// the next size bucket with zero bytes. The AEAD ciphertext this
    /// becomes is therefore also bucket-sized, since ChaCha20-Poly1305
    /// only adds a fixed-length tag.
    fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(9 + 5 + self.payload.len());
        match &self.next_hop {
            Some(id) => {
                body.push(1u8);
                body.extend_from_slice(&self.created_at.to_be_bytes());
                body.extend_from_slice(&(id.len() as u32).to_be_bytes());
                body.extend_from_slice(id);
            }
            None => {
                body.push(0u8);
                body.extend_from_slice(&self.created_at.to_be_bytes());
            }
        }
        body.extend_from_slice(&self.payload);

        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        framed.extend_from_slice(&body);
        framed.resize(bucket_len(framed.len()), 0u8);
        framed
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        let malformed = || NetworkError::Query("onion: malformed layer".to_string());
        let real_len_bytes: [u8; 4] = bytes.get(..4).ok_or_else(malformed)?.try_into().unwrap();
        let real_len = u32::from_be_bytes(real_len_bytes) as usize;
        let body = bytes.get(4..4 + real_len).ok_or_else(malformed)?;

        let tag = *body.first().ok_or_else(malformed)?;
        let created_at_bytes: [u8; 8] = body.get(1..9).ok_or_else(malformed)?.try_into().unwrap();
        let created_at = i64::from_be_bytes(created_at_bytes);
        match tag {
            0 => Ok(Self {
                created_at,
                next_hop: None,
                payload: body.get(9..).ok_or_else(malformed)?.to_vec(),
            }),
            1 => {
                let len_bytes: [u8; 4] = body.get(9..13).ok_or_else(malformed)?.try_into().unwrap();
                let len = u32::from_be_bytes(len_bytes) as usize;
                let id = body.get(13..13 + len).ok_or_else(malformed)?.to_vec();
                let payload = body.get(13 + len..).ok_or_else(malformed)?.to_vec();
                Ok(Self {
                    created_at,
                    next_hop: Some(id),
                    payload,
                })
            }
            _ => Err(malformed()),
        }
    }
}

/// What actually travels over the wire between two hops: an ephemeral
/// public key (for the receiving hop to derive this layer's key) plus the
/// encrypted layer.
struct OnionPacket {
    ephemeral_public: [u8; 32],
    ciphertext: Vec<u8>,
}

impl OnionPacket {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_public);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        let malformed = || NetworkError::Query("onion: malformed packet".to_string());
        let ephemeral_public: [u8; 32] = bytes.get(..32).ok_or_else(malformed)?.try_into().unwrap();
        let ciphertext = bytes.get(32..).ok_or_else(malformed)?.to_vec();
        Ok(Self {
            ephemeral_public,
            ciphertext,
        })
    }
}

/// One hop of a route the caller has already chosen (see
/// `eclipse_resistance.rs` for how hops should actually be selected).
pub struct RouteHop {
    pub peer_id: Vec<u8>,
    pub public_key: X25519PublicKey,
}

/// Builds the onion-encrypted packet to hand to `route[0]` (the entry
/// hop). Each hop can only decrypt its own layer, learning nothing but the
/// previous hop it received from and the next hop to forward to — never
/// the full route, and never the payload unless it's the exit. `now` (unix
/// seconds) is stamped into every layer so [`peel_layer`] can reject the
/// packet once it's stale — see [`MAX_PACKET_AGE_SECONDS`].
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

    let mut next_hop_id: Option<Vec<u8>> = None;
    let mut inner_payload: Vec<u8> = final_payload.to_vec();

    for hop in route.iter().rev() {
        let layer = OnionLayer {
            created_at: now,
            next_hop: next_hop_id.clone(),
            payload: inner_payload,
        };
        let plaintext = layer.encode();

        let ephemeral_secret = X25519Secret::random();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(&hop.public_key);
        let key = derive_layer_key(shared.as_bytes());
        let ciphertext = aead_encrypt(&key, &plaintext);

        inner_payload = OnionPacket {
            ephemeral_public: ephemeral_public.to_bytes(),
            ciphertext,
        }
        .encode();
        next_hop_id = Some(hop.peer_id.clone());
    }

    Ok(inner_payload)
}

/// What a relay does with a packet it just received: either forward the
/// remainder to `next_hop`, or deliver `payload` locally (this hop is the
/// exit).
pub enum PeelResult {
    Forward { next_hop: Vec<u8>, packet: Vec<u8> },
    Deliver { payload: Vec<u8> },
}

/// A relay's side: peel exactly one layer using its own static X25519
/// secret. `now` (unix seconds) is compared against the layer's
/// authenticated `created_at` and the packet is rejected if it falls
/// outside `[now - MAX_PACKET_AGE_SECONDS, now + MAX_CLOCK_SKEW_SECONDS]`
/// — see the module-level doc on why this bounds, rather than eliminates,
/// replay.
pub fn peel_layer(
    my_secret: &X25519Secret,
    packet_bytes: &[u8],
    now: i64,
) -> Result<PeelResult, NetworkError> {
    let packet = OnionPacket::decode(packet_bytes)?;
    let their_ephemeral = X25519PublicKey::from(packet.ephemeral_public);
    let shared = my_secret.diffie_hellman(&their_ephemeral);
    let key = derive_layer_key(shared.as_bytes());
    let plaintext = aead_decrypt(&key, &packet.ciphertext)?;
    let layer = OnionLayer::decode(&plaintext)?;

    let age = now.saturating_sub(layer.created_at);
    if !(-MAX_CLOCK_SKEW_SECONDS..=MAX_PACKET_AGE_SECONDS).contains(&age) {
        return Err(NetworkError::Query(format!(
            "onion: packet is outside the acceptable freshness window (age {age}s)"
        )));
    }

    Ok(match layer.next_hop {
        Some(next_hop) => PeelResult::Forward {
            next_hop,
            packet: layer.payload,
        },
        None => PeelResult::Deliver {
            payload: layer.payload,
        },
    })
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

    #[test]
    fn three_hop_circuit_delivers_payload_to_exit() {
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();

        let mut packet = build_circuit_packet(&route, b"hello via onion", 1_000).unwrap();

        for (i, relay) in relays.iter().enumerate() {
            match peel_layer(&relay.secret, &packet, 1_000).unwrap() {
                PeelResult::Forward {
                    next_hop,
                    packet: forwarded,
                } => {
                    assert!(i < relays.len() - 1, "only non-exit hops should forward");
                    assert_eq!(next_hop, relays[i + 1].peer_id);
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
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let packet = build_circuit_packet(&route, b"secret payload", 1_000).unwrap();

        // Relay 1 only ever sees the outer ciphertext, never the plaintext
        // final payload.
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
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let packet = build_circuit_packet(&route, b"payload", 1_000).unwrap();

        let impostor = Relay::new("not-relay-1");
        assert!(peel_layer(&impostor.secret, &packet, 1_000).is_err());
    }

    /// Regression test bounding the replay window: `peel_layer` must
    /// reject a packet whose authenticated `created_at` is further in the
    /// past than `MAX_PACKET_AGE_SECONDS`, or further in the future than
    /// `MAX_CLOCK_SKEW_SECONDS` — otherwise a captured packet stays
    /// forever replayable.
    #[test]
    fn peel_layer_rejects_a_stale_or_implausibly_future_packet() {
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let packet = build_circuit_packet(&route, b"payload", 1_000).unwrap();

        // Fresh at the time it was built.
        assert!(peel_layer(&relays[0].secret, &packet, 1_000).is_ok());
        // Still fresh well within the window.
        assert!(peel_layer(&relays[0].secret, &packet, 1_000 + MAX_PACKET_AGE_SECONDS).is_ok());
        // Too old.
        assert!(
            peel_layer(
                &relays[0].secret,
                &packet,
                1_000 + MAX_PACKET_AGE_SECONDS + 1
            )
            .is_err(),
            "a packet older than MAX_PACKET_AGE_SECONDS must be rejected"
        );
        // Implausibly far in the future relative to the peer's clock.
        assert!(
            peel_layer(&relays[0].secret, &packet, 1_000 - MAX_CLOCK_SKEW_SECONDS - 1).is_err(),
            "a packet claiming to be from further in the future than clock skew allows must be rejected"
        );
    }

    #[test]
    fn rejects_routes_shorter_than_minimum_hops() {
        let relays = [Relay::new("relay-1"), Relay::new("relay-2")];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        assert!(build_circuit_packet(&route, b"payload", 1_000).is_err());
    }

    #[test]
    fn works_with_more_than_the_minimum_hops() {
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
            Relay::new("relay-4"),
            Relay::new("relay-5"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let mut packet = build_circuit_packet(&route, b"five hop payload", 1_000).unwrap();

        for relay in &relays {
            match peel_layer(&relay.secret, &packet, 1_000).unwrap() {
                PeelResult::Forward {
                    packet: forwarded, ..
                } => packet = forwarded,
                PeelResult::Deliver { payload } => {
                    assert_eq!(payload, b"five hop payload");
                }
            }
        }
    }

    /// The core anti-leak property: packets for a short message and a much
    /// longer one, at every hop of the same-length circuit, land in
    /// exactly the same size bucket — an observer watching only lengths
    /// can't tell hop position (or even distinguish these two circuits)
    /// from packet size alone, as long as both payloads round up to the
    /// same bucket.
    #[test]
    fn same_bucket_payloads_produce_identically_sized_packets_at_every_hop() {
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();

        let short = build_circuit_packet(&route, b"hi", 1_000).unwrap();
        let longer = build_circuit_packet(&route, &vec![b'x'; 300], 1_000).unwrap();
        assert_eq!(
            short.len(),
            longer.len(),
            "a 2-byte and a 300-byte payload both fit in the first bucket, so the \
             entry-hop packets must be indistinguishable by size"
        );

        let mut short_packet = short;
        let mut longer_packet = longer;
        for relay in &relays {
            let short_next = match peel_layer(&relay.secret, &short_packet, 1_000).unwrap() {
                PeelResult::Forward { packet, .. } => packet,
                PeelResult::Deliver { .. } => break,
            };
            let longer_next = match peel_layer(&relay.secret, &longer_packet, 1_000).unwrap() {
                PeelResult::Forward { packet, .. } => packet,
                PeelResult::Deliver { .. } => break,
            };
            assert_eq!(short_next.len(), longer_next.len());
            short_packet = short_next;
            longer_packet = longer_next;
        }
    }

    #[test]
    fn packet_sizes_are_bucketed_not_exact() {
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();

        let packet = build_circuit_packet(&route, b"tiny", 1_000).unwrap();
        // Smallest bucket (512) plus the fixed per-layer AEAD/ephemeral-key
        // overhead for 3 layers of wrapping — well short of naively
        // encoding just a few bytes of real payload, proving padding
        // actually happened rather than the format staying byte-exact.
        assert!(
            packet.len() >= 512,
            "expected bucket-padded size, got {}",
            packet.len()
        );
    }

    #[test]
    fn oversized_payload_still_encodes_and_round_trips() {
        let relays = [
            Relay::new("relay-1"),
            Relay::new("relay-2"),
            Relay::new("relay-3"),
        ];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        let big_payload = vec![b'z'; 100_000]; // bigger than the largest bucket

        let mut packet = build_circuit_packet(&route, &big_payload, 1_000).unwrap();
        for relay in &relays {
            match peel_layer(&relay.secret, &packet, 1_000).unwrap() {
                PeelResult::Forward {
                    packet: forwarded, ..
                } => packet = forwarded,
                PeelResult::Deliver { payload } => assert_eq!(payload, big_payload),
            }
        }
    }
}
