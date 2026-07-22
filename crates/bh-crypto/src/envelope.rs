//! The plaintext content structure carried *inside* a Double Ratchet/MLS
//! ciphertext (SPEC.md §2.1, §2.3). `ratchet.rs`/`mls.rs` only know about
//! opaque bytes; this module is where "what kinds of things can a message
//! actually say" lives — text, quote-reply, reactions, delivery/read
//! receipts, and call signaling all travel as the same kind of ciphertext,
//! so anything outside the recipient's own decryption (a mailbox, a relay,
//! the operator) sees identical-looking encrypted blobs regardless of which
//! variant is inside. That's what makes receipts and reactions
//! metadata-free from the operator's point of view (SPEC.md §2.3) — the
//! alternative of a separate "receipt protocol" with its own wire framing
//! would leak "these two parties are exchanging receipts right now" even
//! if the receipt's content stayed encrypted.
//!
//! Encoding is plain `serde_json` (already used the same way in
//! `bh-network::sealed_sender`), length-prefixed and then padded up to a
//! fixed size bucket (see [`bucket_len`]) before it's handed to the
//! ratchet/MLS layer for encryption. Padding is what actually closes the
//! metadata gap the module-level comment above describes: without it, a
//! `Reaction` (tiny JSON) and a `Call(Offer)` (an SDP blob, often a few KB)
//! would produce distinguishably different ciphertext lengths even though
//! both are opaque to anyone but the recipient — an observer could infer
//! "this pair just started a call" from size alone. Same bucket-padding
//! approach as `bh-network::onion`, and the same caveat: this collapses
//! exact length down to one of a handful of buckets, it doesn't achieve
//! Sphinx-style perfectly-constant size (see that module's doc comment for
//! why that's harder and out of scope here too).

use serde::{Deserialize, Serialize};

use crate::CryptoError;

const SIZE_BUCKETS: &[usize] = &[128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

/// Rounds `len` up to the next size bucket, falling back to the next
/// multiple of the largest bucket for anything bigger than all of them.
fn bucket_len(len: usize) -> usize {
    match SIZE_BUCKETS.iter().copied().find(|&b| b >= len) {
        Some(b) => b,
        None => {
            let largest = *SIZE_BUCKETS.last().expect("SIZE_BUCKETS is non-empty");
            len.div_ceil(largest) * largest
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptKind {
    Delivered,
    Read,
}

/// One call-signaling message, carried end-to-end alongside (or instead
/// of) chat content over the same already-authenticated session — see
/// `docs/SPEC.md` calls section for why signaling reuses this channel
/// rather than inventing a parallel one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallSignal {
    /// Proposes a call and carries the caller's ephemeral X25519 public key
    /// used to derive the call's SFrame base key (see `call_keys.rs`) —
    /// independent of, but authenticated by, the underlying session.
    Offer {
        call_id: String,
        caller_ephemeral_public: [u8; 32],
        /// Opaque SDP-like session description (ICE ufrag/pwd, codecs,
        /// etc.) produced by the WebRTC transport layer (`bh-calls`). This
        /// module doesn't parse it — it only ferries it end-to-end encrypted
        /// instead of over an unauthenticated signaling server.
        transport_description: Vec<u8>,
        video: bool,
    },
    Answer {
        call_id: String,
        callee_ephemeral_public: [u8; 32],
        transport_description: Vec<u8>,
    },
    /// One edge of a full-mesh group call's signaling (`bh_calls::group`):
    /// offers the WebRTC transport description for the connection from
    /// `from_participant` to `to_participant`. Unlike `Offer`, this
    /// carries no ephemeral public key — the SFrame base key for the whole
    /// call comes from the MLS group's own exporter secret
    /// (`bh_crypto::mls::Group::export_call_base_key`), already implicitly
    /// shared by every current member without any additional per-edge
    /// key-agreement round trip, so there is nothing to negotiate here
    /// beyond the WebRTC transport description itself.
    GroupOffer {
        call_id: String,
        from_participant: u8,
        to_participant: u8,
        transport_description: Vec<u8>,
        video: bool,
    },
    /// Answers a [`CallSignal::GroupOffer`] for the same mesh edge.
    GroupAnswer {
        call_id: String,
        from_participant: u8,
        to_participant: u8,
        transport_description: Vec<u8>,
    },
    IceCandidate {
        call_id: String,
        candidate: Vec<u8>,
    },
    /// Ratchets the SFrame base key mid-call (e.g. on participant
    /// change in a group call) — carries the new key wrapped for the
    /// recipient, never in the clear.
    KeyUpdate {
        call_id: String,
        epoch: u32,
    },
    Hangup {
        call_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Envelope {
    Text {
        body: String,
        reply_to_message_id: Option<String>,
    },
    Reaction {
        message_id: String,
        emoji: String,
        /// `true` removes a previously-sent reaction with this emoji.
        remove: bool,
    },
    Receipt {
        message_ids: Vec<String>,
        kind: ReceiptKind,
    },
    /// Local user disabled/enabled/changed the disappearing-messages timer
    /// for this conversation — sent so the peer's client applies the same
    /// timer to messages it sends back, mirroring Signal's own behavior.
    DisappearingTimerChanged {
        timer_secs: Option<i64>,
    },
    Call(CallSignal),
    /// Ephemeral "is typing…" presence ping (opt-in — see
    /// `bh-api::presence`). Carries no payload beyond the variant tag
    /// itself: there is nothing to persist, nothing to read back later,
    /// just a marker that gets encrypted and decrypted exactly like any
    /// other envelope — going through the same sealed session/mailbox
    /// channel is what makes it metadata-free from the operator's point of
    /// view — same reasoning as `Receipt` above, and the same ciphertext a
    /// mailbox/relay/operator would see either way.
    Typing,
}

impl Envelope {
    /// Serializes and pads to a fixed size bucket. See the module doc
    /// comment for why the padding matters, not just the JSON.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let json = serde_json::to_vec(self)
            .map_err(|_| CryptoError::NotImplemented("envelope: encode failed"))?;

        let mut framed = Vec::with_capacity(4 + json.len());
        framed.extend_from_slice(&(json.len() as u32).to_be_bytes());
        framed.extend_from_slice(&json);
        framed.resize(bucket_len(framed.len()), 0u8);
        Ok(framed)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let malformed = || CryptoError::NotImplemented("envelope: malformed payload");
        let real_len_bytes: [u8; 4] = bytes.get(..4).ok_or_else(malformed)?.try_into().unwrap();
        let real_len = u32::from_be_bytes(real_len_bytes) as usize;
        let json = bytes.get(4..4 + real_len).ok_or_else(malformed)?;
        serde_json::from_slice(json).map_err(|_| malformed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_envelope_roundtrips() {
        let env = Envelope::Text {
            body: "hello".into(),
            reply_to_message_id: Some("m0".into()),
        };
        let decoded = Envelope::decode(&env.encode().unwrap()).unwrap();
        matches!(decoded, Envelope::Text { body, reply_to_message_id }
            if body == "hello" && reply_to_message_id == Some("m0".to_string()));
    }

    #[test]
    fn receipt_envelope_roundtrips() {
        let env = Envelope::Receipt {
            message_ids: vec!["m1".into(), "m2".into()],
            kind: ReceiptKind::Read,
        };
        let bytes = env.encode().unwrap();
        let Envelope::Receipt { message_ids, kind } = Envelope::decode(&bytes).unwrap() else {
            panic!("expected Receipt variant");
        };
        assert_eq!(message_ids, vec!["m1".to_string(), "m2".to_string()]);
        assert_eq!(kind, ReceiptKind::Read);
    }

    #[test]
    fn call_offer_envelope_roundtrips() {
        let env = Envelope::Call(CallSignal::Offer {
            call_id: "call-1".into(),
            caller_ephemeral_public: [7u8; 32],
            transport_description: vec![1, 2, 3],
            video: true,
        });
        let bytes = env.encode().unwrap();
        let Envelope::Call(CallSignal::Offer {
            call_id,
            caller_ephemeral_public,
            video,
            ..
        }) = Envelope::decode(&bytes).unwrap()
        else {
            panic!("expected Call(Offer) variant");
        };
        assert_eq!(call_id, "call-1");
        assert_eq!(caller_ephemeral_public, [7u8; 32]);
        assert!(video);
    }

    #[test]
    fn garbage_bytes_are_rejected_not_panicked_on() {
        assert!(Envelope::decode(b"not json").is_err());
    }

    /// The point of the padding: a tiny reaction and a receipt covering
    /// several messages land in the same size bucket, so measuring
    /// encoded length alone can't distinguish "someone reacted" from
    /// "someone read several messages."
    #[test]
    fn different_small_variants_pad_to_the_same_bucket() {
        let reaction = Envelope::Reaction {
            message_id: "m1".into(),
            emoji: "👍".into(),
            remove: false,
        };
        let receipt = Envelope::Receipt {
            message_ids: vec!["m1".into(), "m2".into(), "m3".into()],
            kind: ReceiptKind::Read,
        };
        assert_eq!(
            reaction.encode().unwrap().len(),
            receipt.encode().unwrap().len()
        );
    }

    #[test]
    fn encoded_length_is_always_a_known_bucket_size() {
        let env = Envelope::Text {
            body: "hi".into(),
            reply_to_message_id: None,
        };
        let len = env.encode().unwrap().len();
        assert!(
            SIZE_BUCKETS.contains(&len),
            "expected one of {SIZE_BUCKETS:?}, got {len}"
        );
    }

    #[test]
    fn oversized_payload_still_round_trips() {
        let env = Envelope::Call(CallSignal::Offer {
            call_id: "call-1".into(),
            caller_ephemeral_public: [1u8; 32],
            transport_description: vec![9u8; 200_000], // bigger than the largest bucket
            video: true,
        });
        let bytes = env.encode().unwrap();
        let Envelope::Call(CallSignal::Offer {
            transport_description,
            ..
        }) = Envelope::decode(&bytes).unwrap()
        else {
            panic!("expected Call(Offer) variant");
        };
        assert_eq!(transport_description.len(), 200_000);
    }

    #[test]
    fn typing_envelope_roundtrips() {
        let env = Envelope::Typing;
        let decoded = Envelope::decode(&env.encode().unwrap()).unwrap();
        assert!(matches!(decoded, Envelope::Typing));
    }

    #[test]
    fn group_offer_and_answer_envelopes_roundtrip() {
        let offer_env = Envelope::Call(CallSignal::GroupOffer {
            call_id: "group-call-1".into(),
            from_participant: 0,
            to_participant: 2,
            transport_description: vec![4, 5, 6],
            video: false,
        });
        let bytes = offer_env.encode().unwrap();
        let Envelope::Call(CallSignal::GroupOffer {
            call_id,
            from_participant,
            to_participant,
            transport_description,
            video,
        }) = Envelope::decode(&bytes).unwrap()
        else {
            panic!("expected Call(GroupOffer) variant");
        };
        assert_eq!(call_id, "group-call-1");
        assert_eq!(from_participant, 0);
        assert_eq!(to_participant, 2);
        assert_eq!(transport_description, vec![4, 5, 6]);
        assert!(!video);

        let answer_env = Envelope::Call(CallSignal::GroupAnswer {
            call_id: "group-call-1".into(),
            from_participant: 2,
            to_participant: 0,
            transport_description: vec![7, 8, 9],
        });
        let bytes = answer_env.encode().unwrap();
        let Envelope::Call(CallSignal::GroupAnswer {
            from_participant,
            to_participant,
            ..
        }) = Envelope::decode(&bytes).unwrap()
        else {
            panic!("expected Call(GroupAnswer) variant");
        };
        assert_eq!(from_participant, 2);
        assert_eq!(to_participant, 0);
    }
}
