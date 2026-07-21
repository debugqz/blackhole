//! Turns `bh_crypto`'s call-signaling primitives into a small state
//! machine for one call: who's calling whom, the ephemeral ECDH exchange,
//! and the `SframeContext` both sides end up sharing. Transport-agnostic —
//! this module knows nothing about WebRTC; the `transport_description`
//! byte blobs it ferries are opaque here and come from/go to
//! `transport.rs`. The signals this module produces travel end-to-end
//! encrypted inside `bh_crypto::envelope::Envelope::Call`, riding the same
//! already-authenticated Double Ratchet/MLS session as chat messages — see
//! `docs/SPEC.md`.

use bh_crypto::call_keys::{derive_base_key, CallEphemeralKeyPair, SframeContext};
use bh_crypto::envelope::CallSignal;

use crate::CallError;

/// Sender tag the caller's outgoing SFrame frames are marked with; the
/// callee uses this to decrypt frames arriving *from* the caller and
/// [`CALLEE_SENDER_TAG`] for its own outgoing frames.
pub const CALLER_SENDER_TAG: u8 = 0;
pub const CALLEE_SENDER_TAG: u8 = 1;

/// The caller's side of setting up a call, up through sending the offer.
pub struct OutgoingCall {
    pub call_id: String,
    ephemeral: CallEphemeralKeyPair,
    video: bool,
}

impl OutgoingCall {
    pub fn new(call_id: impl Into<String>, video: bool) -> Self {
        Self {
            call_id: call_id.into(),
            ephemeral: CallEphemeralKeyPair::generate(),
            video,
        }
    }

    /// The signal to send the callee, wrapping whatever
    /// `transport_description` `bh_calls::transport` produced for the
    /// local offer.
    pub fn offer(&self, transport_description: Vec<u8>) -> CallSignal {
        CallSignal::Offer {
            call_id: self.call_id.clone(),
            caller_ephemeral_public: self.ephemeral.public(),
            transport_description,
            video: self.video,
        }
    }

    /// Consumes the callee's answer, deriving the call's shared SFrame
    /// context. Returns the context plus the callee's transport
    /// description, which the caller hands to `transport.rs` to complete
    /// the WebRTC handshake. The caller marks its own outgoing frames with
    /// [`CALLER_SENDER_TAG`] and expects [`CALLEE_SENDER_TAG`] on incoming
    /// ones.
    pub fn accept_answer(
        &self,
        answer: &CallSignal,
    ) -> Result<(SframeContext, Vec<u8>), CallError> {
        let CallSignal::Answer {
            call_id,
            callee_ephemeral_public,
            transport_description,
        } = answer
        else {
            return Err(CallError::UnexpectedSignal);
        };
        if *call_id != self.call_id {
            return Err(CallError::CallIdMismatch);
        }
        let base_key = derive_base_key(&self.call_id, &self.ephemeral, callee_ephemeral_public);
        Ok((SframeContext::new(base_key), transport_description.clone()))
    }
}

/// The callee's side: what arrived in an offer, before it's been answered.
pub struct IncomingCall {
    pub call_id: String,
    pub caller_ephemeral_public: [u8; 32],
    pub video: bool,
    pub transport_description: Vec<u8>,
}

impl IncomingCall {
    pub fn from_offer(offer: &CallSignal) -> Result<Self, CallError> {
        let CallSignal::Offer {
            call_id,
            caller_ephemeral_public,
            transport_description,
            video,
        } = offer
        else {
            return Err(CallError::UnexpectedSignal);
        };
        Ok(Self {
            call_id: call_id.clone(),
            caller_ephemeral_public: *caller_ephemeral_public,
            video: *video,
            transport_description: transport_description.clone(),
        })
    }

    /// Answers the call: generates the callee's own ephemeral key, derives
    /// the shared SFrame context, and builds the signal to send back.
    /// `transport_description` is whatever `transport.rs` produced for the
    /// local answer.
    pub fn answer(&self, transport_description: Vec<u8>) -> (CallSignal, SframeContext) {
        let ephemeral = CallEphemeralKeyPair::generate();
        let base_key = derive_base_key(&self.call_id, &ephemeral, &self.caller_ephemeral_public);
        let signal = CallSignal::Answer {
            call_id: self.call_id.clone(),
            callee_ephemeral_public: ephemeral.public(),
            transport_description,
        };
        (signal, SframeContext::new(base_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_and_callee_derive_the_same_sframe_context() {
        let outgoing = OutgoingCall::new("call-1", true);
        let offer = outgoing.offer(b"caller-sdp".to_vec());

        let incoming = IncomingCall::from_offer(&offer).unwrap();
        assert_eq!(incoming.call_id, "call-1");
        assert!(incoming.video);
        assert_eq!(incoming.transport_description, b"caller-sdp");

        let (answer, callee_ctx) = incoming.answer(b"callee-sdp".to_vec());
        let (caller_ctx, transport_description) = outgoing.accept_answer(&answer).unwrap();
        assert_eq!(transport_description, b"callee-sdp");

        // Both sides derived the same SFrame base key: a frame encrypted
        // by one decrypts cleanly with the other.
        let frame = caller_ctx
            .encrypt_frame(0, CALLER_SENDER_TAG, 0, b"hello from caller")
            .unwrap();
        let (_, _, _, plaintext) = callee_ctx.decrypt_frame(&frame).unwrap();
        assert_eq!(plaintext, b"hello from caller");
    }

    #[test]
    fn mismatched_call_id_in_answer_is_rejected() {
        let outgoing = OutgoingCall::new("call-1", false);
        let bad_answer = bh_crypto::envelope::CallSignal::Answer {
            call_id: "call-2".to_string(),
            callee_ephemeral_public: [0u8; 32],
            transport_description: vec![],
        };
        assert!(matches!(
            outgoing.accept_answer(&bad_answer),
            Err(CallError::CallIdMismatch)
        ));
    }

    #[test]
    fn wrong_signal_variant_is_rejected() {
        let outgoing = OutgoingCall::new("call-1", false);
        let hangup = bh_crypto::envelope::CallSignal::Hangup {
            call_id: "call-1".to_string(),
        };
        assert!(matches!(
            outgoing.accept_answer(&hangup),
            Err(CallError::UnexpectedSignal)
        ));
        assert!(matches!(
            IncomingCall::from_offer(&hangup),
            Err(CallError::UnexpectedSignal)
        ));
    }
}
