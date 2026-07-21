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
//! `bh-network::sealed_sender`) — compactness doesn't matter here since the
//! whole thing is encrypted before it ever reaches a byte the network can
//! measure at that granularity; the ciphertext *length* leaking coarse
//! content-type information is a separate, already-tracked risk (see
//! `docs/THREAT_MODEL.md` onion packet-size entry).

use serde::{Deserialize, Serialize};

use crate::CryptoError;

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
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(self).map_err(|_| CryptoError::NotImplemented("envelope: encode failed"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes)
            .map_err(|_| CryptoError::NotImplemented("envelope: malformed payload"))
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
}
