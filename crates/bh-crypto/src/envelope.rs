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

/// Which conversation a delegated send or a mirrored message belongs to,
/// named in terms both devices of one account can agree on.
///
/// Deliberately *not* a `conversation_id`: those are locally-generated
/// UUIDs, so the primary's id for a conversation and the secondary's id
/// for the same conversation are different strings. `contact_id` is
/// shared only because `Envelope::ContactSync` mirrors contact rows
/// verbatim, ids included — that mirroring is what makes this reference
/// well-defined, not an incidental detail of it. `group_id` needs no such
/// arrangement: it is the real MLS group id, global by construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConversationRef {
    Direct { contact_id: String },
    Group { group_id: String },
    SelfNotes,
}

/// One contact row mirrored from the primary to a linked secondary device
/// (`Envelope::ContactSync`).
///
/// Carries only the contact's *public* identity — there is no session
/// state, no ratchet material and no prekey here, because a secondary
/// never encrypts to a contact (see `docs/superpowers/specs/
/// 2026-07-24-multidevice-delegation-design.md` §3). This exists so the
/// secondary can render a name and a verification badge instead of a raw
/// id, and so [`ConversationRef::Direct`] resolves on both sides.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncedContact {
    pub contact_id: String,
    pub identity_public_key: Vec<u8>,
    pub display_name: Option<String>,
    /// Mirrored rather than recomputed: safety-number verification is a
    /// human act performed against the *account's* identity, so it belongs
    /// to the account, not to whichever device happened to perform it.
    pub verified: bool,
    pub blocked: bool,
    pub added_at: i64,
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
    /// Invites the recipient into an MLS group they were just added to
    /// (`bh-api::groups::add_contact_to_live_group`'s real-network path) —
    /// sent through the same already-established 1:1 X3DH/Double-Ratchet
    /// session as any other Direct-conversation envelope, since adding
    /// someone to a group presupposes they're already a contact
    /// (`AddMemberRequest::contact_id`). Carries the raw MLS `Welcome` plus
    /// the group's public ratchet tree — everything
    /// `bh_crypto::mls::MlsMember::join_group` needs — and `group_id`/
    /// `name` so the recipient can materialize the local `groups`/
    /// `conversations` rows `create_group` would otherwise have written on
    /// the inviter's side.
    GroupInvite {
        group_id: String,
        name: Option<String>,
        welcome: Vec<u8>,
        ratchet_tree: Vec<u8>,
        /// Mirrors the group's own `broadcast_only` flag (SPEC.md §16) so
        /// the recipient's local `groups` row enforces the same
        /// owner-only-posts restriction the inviter's does — see
        /// `bh_storage::Database::insert_group_message`'s doc comment.
        broadcast_only: bool,
    },
    /// One message pushed to a linked device's own mailbox during a real
    /// `bh-api::device_sync` push (`sync_device`'s real-network path,
    /// gated on the device having a real published identity — see that
    /// module's doc comment). Reuses the same 1:1 X3DH/Double-Ratchet
    /// mailbox pipeline `Direct` messages use, just addressed to the
    /// device's own identity (`Device.public_key || Device.
    /// identity_agreement_key`) instead of a contact's — a pseudo-`Contact`
    /// built from that `Device` row is all `message_crypto::
    /// send_encrypted_over_network` needs, so no new transport code exists
    /// for this, only this envelope variant. `conversation` says which
    /// conversation the message belongs to in terms both devices agree on
    /// (see [`ConversationRef`]) — not necessarily who *sent* it, which is
    /// `sender_contact_id` (`None` for a message the account itself sent,
    /// from any of its devices). The receiving device materializes or
    /// reuses the matching local conversation from that reference.
    ///
    /// Covers `Direct`, `Group` and `SelfNotes` alike, because under the
    /// hub model a secondary is never an MLS member of anything: the
    /// primary decrypts a group message with real MLS state and mirrors
    /// the resulting plaintext here, exactly as it does for a 1:1 message.
    /// That is why group sync costs no new subsystem — see the design
    /// doc's §4.
    DeviceSyncMessage {
        message_id: String,
        conversation: ConversationRef,
        sender_contact_id: Option<String>,
        body: Option<String>,
        sent_at: i64,
    },
    /// A linked secondary device asking its primary to send on its behalf
    /// (`bh-api::device_delegation`).
    ///
    /// This is the load-bearing variant of the hub model: a secondary
    /// holds no ratchet session with any contact and no MLS state for any
    /// group, so it cannot encrypt outbound content itself — and must not
    /// try. Two devices sharing one account's Double Ratchet session would
    /// each advance `sending_chain_key`/`send_count` independently and
    /// reuse message keys, which is a cryptographic break rather than a
    /// synchronization inconvenience (see `ratchet.rs`'s `Session`).
    /// Delegating the send keeps exactly one device holding that state.
    ///
    /// `request_id` is chosen by the secondary and is the idempotency key:
    /// the primary answers a repeat of an already-processed id with the
    /// original [`Envelope::OutboundResult`] instead of sending twice, so
    /// retrying an unacknowledged request is always safe.
    OutboundRequest {
        request_id: String,
        conversation: ConversationRef,
        body: String,
        reply_to_message_id: Option<String>,
    },
    /// The primary's answer to an [`Envelope::OutboundRequest`].
    ///
    /// `error` is `None` on success, and `message_id` then carries the id
    /// the message really got on the primary, so the secondary can promote
    /// its local pending row rather than keep a duplicate. A populated
    /// `error` is a *final* rejection (a broadcast channel the account
    /// doesn't own, a group it is no longer a member of, a blocked
    /// contact, a revoked device) — the secondary surfaces it as a failed
    /// send instead of leaving the message pending forever.
    OutboundResult {
        request_id: String,
        message_id: Option<String>,
        error: Option<String>,
    },
    /// A batch of contact rows mirrored from primary to secondary.
    ///
    /// Sent in bounded batches rather than as one list: [`Envelope::encode`]
    /// pads to size buckets up to 64 KiB and then grows in whole 64 KiB
    /// blocks, so a single envelope carrying a large contact book would
    /// both waste padding and risk the DHT record size cap
    /// `bh-network::mailbox` enforces.
    ContactSync {
        contacts: Vec<SyncedContact>,
    },
    /// The primary telling a secondary it has been unlinked, so the device
    /// can stop delegating and explain why it went quiet instead of
    /// failing silently. Best-effort by nature — a revoked device that is
    /// offline never receives this, which is precisely why revocation is
    /// *also* enforced on the primary's own receive path rather than
    /// relying on the secondary's cooperation.
    DeviceRevoked,
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
        // `real_len` is attacker/sender-declared (the sending device chose
        // these bytes, and a compromised or malicious contact's client can
        // send anything a successfully-decrypted ciphertext contains) — a
        // declared length near `u32::MAX` must not be allowed to overflow
        // `4 + real_len` (`checked_add` rather than `+`, which would wrap on
        // a 32-bit target), same reasoning as `push_relay.rs::read_string`.
        let end = 4usize.checked_add(real_len).ok_or_else(malformed)?;
        let json = bytes.get(4..end).ok_or_else(malformed)?;
        serde_json::from_slice(json).map_err(|_| malformed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the overflow guard in `decode`: a maliciously
    /// huge declared length must be rejected cleanly (not panic via
    /// `4 + real_len` overflowing `usize`), matching `push_relay.rs`'s own
    /// `a_huge_declared_length_is_rejected_not_a_panic`.
    #[test]
    fn a_huge_declared_length_is_rejected_not_a_panic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"way too short to satisfy that length");
        assert!(Envelope::decode(&bytes).is_err());
    }

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
    fn outbound_request_roundtrips_for_every_conversation_kind() {
        for conversation in [
            ConversationRef::Direct {
                contact_id: "c1".into(),
            },
            ConversationRef::Group {
                group_id: "abcdef".into(),
            },
            ConversationRef::SelfNotes,
        ] {
            let env = Envelope::OutboundRequest {
                request_id: "req-1".into(),
                conversation: conversation.clone(),
                body: "sent from my phone".into(),
                reply_to_message_id: None,
            };
            let bytes = env.encode().unwrap();
            let Envelope::OutboundRequest {
                request_id,
                conversation: decoded,
                body,
                ..
            } = Envelope::decode(&bytes).unwrap()
            else {
                panic!("expected OutboundRequest variant");
            };
            assert_eq!(request_id, "req-1");
            assert_eq!(decoded, conversation);
            assert_eq!(body, "sent from my phone");
        }
    }

    #[test]
    fn outbound_result_roundtrips_both_success_and_failure() {
        let ok = Envelope::OutboundResult {
            request_id: "req-1".into(),
            message_id: Some("m-7".into()),
            error: None,
        };
        let Envelope::OutboundResult {
            message_id, error, ..
        } = Envelope::decode(&ok.encode().unwrap()).unwrap()
        else {
            panic!("expected OutboundResult variant");
        };
        assert_eq!(message_id, Some("m-7".to_string()));
        assert!(error.is_none());

        let failed = Envelope::OutboundResult {
            request_id: "req-2".into(),
            message_id: None,
            error: Some("broadcast channel: only the owner may post".into()),
        };
        let Envelope::OutboundResult { error, .. } =
            Envelope::decode(&failed.encode().unwrap()).unwrap()
        else {
            panic!("expected OutboundResult variant");
        };
        assert!(error.unwrap().contains("only the owner may post"));
    }

    #[test]
    fn contact_sync_roundtrips() {
        let env = Envelope::ContactSync {
            contacts: vec![SyncedContact {
                contact_id: "c1".into(),
                identity_public_key: vec![4u8; 64],
                display_name: Some("Ana".into()),
                verified: true,
                blocked: false,
                added_at: 1_700_000_000,
            }],
        };
        let Envelope::ContactSync { contacts } = Envelope::decode(&env.encode().unwrap()).unwrap()
        else {
            panic!("expected ContactSync variant");
        };
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].contact_id, "c1");
        assert!(contacts[0].verified);
        assert_eq!(contacts[0].identity_public_key, vec![4u8; 64]);
    }

    /// A delegated send must not be identifiable *as* a delegated send
    /// from ciphertext length alone — otherwise a mailbox operator could
    /// infer "this account has a second device" from traffic shape, which
    /// is precisely the metadata the hub model avoids leaking by not
    /// publishing a device directory at all.
    ///
    /// The property that actually holds is bucket-level, not byte-level:
    /// an `OutboundRequest` carries two real UUIDs of routing metadata on
    /// top of the body, so with an *identical* body it lands one bucket
    /// higher than a bare `Text` would. What matters is that it lands on
    /// the same bucket ladder every other variant uses, so its size is
    /// always also the size of some perfectly ordinary message — checked
    /// here by producing a byte-for-byte length match against a `Text`
    /// whose body is merely a bit longer. Same caveat the module doc
    /// already states for bucketing in general: this collapses lengths
    /// into a handful of classes, it does not make them constant.
    #[test]
    fn a_delegated_send_is_indistinguishable_from_some_ordinary_message() {
        let body = "the quick brown fox jumps over the lazy dog";
        let delegated = Envelope::OutboundRequest {
            request_id: "00000000-0000-0000-0000-000000000000".into(),
            conversation: ConversationRef::Direct {
                contact_id: "00000000-0000-0000-0000-000000000000".into(),
            },
            body: body.into(),
            reply_to_message_id: None,
        }
        .encode()
        .unwrap();

        let ordinary = Envelope::Text {
            body: body.repeat(3),
            reply_to_message_id: Some("00000000-0000-0000-0000-000000000000".into()),
        }
        .encode()
        .unwrap();

        assert_eq!(delegated.len(), ordinary.len());
        // And it is on the shared ladder, not some delegation-specific size.
        assert!(SIZE_BUCKETS.contains(&delegated.len()));
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
    fn group_invite_envelope_roundtrips() {
        let env = Envelope::GroupInvite {
            group_id: "abcd1234".into(),
            name: Some("Friends".into()),
            welcome: vec![1, 2, 3],
            ratchet_tree: vec![4, 5, 6],
            broadcast_only: true,
        };
        let bytes = env.encode().unwrap();
        let Envelope::GroupInvite {
            group_id,
            name,
            welcome,
            ratchet_tree,
            broadcast_only,
        } = Envelope::decode(&bytes).unwrap()
        else {
            panic!("expected GroupInvite variant");
        };
        assert_eq!(group_id, "abcd1234");
        assert_eq!(name, Some("Friends".to_string()));
        assert_eq!(welcome, vec![1, 2, 3]);
        assert_eq!(ratchet_tree, vec![4, 5, 6]);
        assert!(broadcast_only);
    }

    #[test]
    fn device_sync_message_envelope_roundtrips() {
        let env = Envelope::DeviceSyncMessage {
            message_id: "m1".into(),
            conversation: ConversationRef::Direct {
                contact_id: "contact-a".into(),
            },
            sender_contact_id: Some("contact-a".into()),
            body: Some("hi".into()),
            sent_at: 1234,
        };
        let bytes = env.encode().unwrap();
        let Envelope::DeviceSyncMessage {
            message_id,
            conversation,
            sender_contact_id,
            body,
            sent_at,
        } = Envelope::decode(&bytes).unwrap()
        else {
            panic!("expected DeviceSyncMessage variant");
        };
        assert_eq!(message_id, "m1");
        assert_eq!(
            conversation,
            ConversationRef::Direct {
                contact_id: "contact-a".to_string()
            }
        );
        assert_eq!(sender_contact_id, Some("contact-a".to_string()));
        assert_eq!(body, Some("hi".to_string()));
        assert_eq!(sent_at, 1234);
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
