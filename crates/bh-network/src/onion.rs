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
//! the least precedented piece of the lot. Concretely: unlike Sphinx (the
//! packet format Tor actually uses), packet size here shrinks by a fixed
//! amount at every hop, which leaks a relay's position in the circuit to
//! anyone who can observe packet sizes. Fixed-size padding per hop is the
//! known fix and is not implemented yet.

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::NetworkError;

pub const MIN_HOPS: usize = 3;

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
/// `payload` locally.
struct OnionLayer {
    next_hop: Option<Vec<u8>>,
    payload: Vec<u8>,
}

impl OnionLayer {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.payload.len());
        match &self.next_hop {
            Some(id) => {
                out.push(1u8);
                out.extend_from_slice(&(id.len() as u32).to_be_bytes());
                out.extend_from_slice(id);
            }
            None => out.push(0u8),
        }
        out.extend_from_slice(&self.payload);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, NetworkError> {
        let malformed = || NetworkError::Query("onion: malformed layer".to_string());
        let tag = *bytes.first().ok_or_else(malformed)?;
        match tag {
            0 => Ok(Self {
                next_hop: None,
                payload: bytes.get(1..).ok_or_else(malformed)?.to_vec(),
            }),
            1 => {
                let len_bytes: [u8; 4] = bytes.get(1..5).ok_or_else(malformed)?.try_into().unwrap();
                let len = u32::from_be_bytes(len_bytes) as usize;
                let id = bytes.get(5..5 + len).ok_or_else(malformed)?.to_vec();
                let payload = bytes.get(5 + len..).ok_or_else(malformed)?.to_vec();
                Ok(Self {
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
/// the full route, and never the payload unless it's the exit.
pub fn build_circuit_packet(
    route: &[RouteHop],
    final_payload: &[u8],
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
/// secret.
pub fn peel_layer(
    my_secret: &X25519Secret,
    packet_bytes: &[u8],
) -> Result<PeelResult, NetworkError> {
    let packet = OnionPacket::decode(packet_bytes)?;
    let their_ephemeral = X25519PublicKey::from(packet.ephemeral_public);
    let shared = my_secret.diffie_hellman(&their_ephemeral);
    let key = derive_layer_key(shared.as_bytes());
    let plaintext = aead_decrypt(&key, &packet.ciphertext)?;
    let layer = OnionLayer::decode(&plaintext)?;

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

        let mut packet = build_circuit_packet(&route, b"hello via onion").unwrap();

        for (i, relay) in relays.iter().enumerate() {
            match peel_layer(&relay.secret, &packet).unwrap() {
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
        let packet = build_circuit_packet(&route, b"secret payload").unwrap();

        // Relay 1 only ever sees the outer ciphertext, never the plaintext
        // final payload.
        assert!(!packet
            .windows(b"secret payload".len())
            .any(|w| w == b"secret payload"));

        match peel_layer(&relays[0].secret, &packet).unwrap() {
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
        let packet = build_circuit_packet(&route, b"payload").unwrap();

        let impostor = Relay::new("not-relay-1");
        assert!(peel_layer(&impostor.secret, &packet).is_err());
    }

    #[test]
    fn rejects_routes_shorter_than_minimum_hops() {
        let relays = [Relay::new("relay-1"), Relay::new("relay-2")];
        let route: Vec<RouteHop> = relays.iter().map(Relay::route_hop).collect();
        assert!(build_circuit_packet(&route, b"payload").is_err());
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
        let mut packet = build_circuit_packet(&route, b"five hop payload").unwrap();

        for relay in &relays {
            match peel_layer(&relay.secret, &packet).unwrap() {
                PeelResult::Forward {
                    packet: forwarded, ..
                } => packet = forwarded,
                PeelResult::Deliver { payload } => {
                    assert_eq!(payload, b"five hop payload");
                }
            }
        }
    }
}
