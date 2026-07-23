//! Group (N-party) calls: full-mesh WebRTC. There's no SFU/TURN wired up
//! yet (same limitation `transport.rs`/`docs/SPEC.md` already document for
//! 1:1 calls), so instead of routing media through a central mixer, every
//! participant opens one direct [`RTCPeerConnection`] to every *other*
//! participant — one [`GroupCallSession`] per participant, holding one
//! mesh edge per peer.
//!
//! Unlike 1:1 calls (`session.rs`), a group call's SFrame base key does
//! not come from a fresh per-edge ephemeral ECDH handshake
//! (`signaling.rs`/`call_keys::derive_base_key`) — that would give a mesh
//! of N*(N-1)/2 *different* keys for what should be a single logical
//! call. Instead every participant derives the *same* base key from the
//! call's MLS group via [`bh_crypto::mls::Group::export_call_base_key`]:
//! MLS group members already share epoch secrets after processing the
//! same commits, so no additional key-agreement round trip is needed, and
//! this reuses MLS's own audited key schedule rather than inventing a
//! bespoke group DH (`docs/SPEC.md` §2.2's "no custom crypto primitives"
//! non-negotiable, applied here). Frames from different participants never
//! collide because each mesh edge is still encrypted per the sending
//! participant's own [`ParticipantTag`], exactly the "assign one per
//! participant" extension `call_keys::SenderTag`'s doc comment already
//! anticipated.
//!
//! Capped at [`MAX_GROUP_CALL_PARTICIPANTS`] — see that constant's docs
//! for why.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex as TokioMutex};
use webrtc::media::io::sample_builder::SampleBuilder;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp::codecs::opus::OpusPacket;
use webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use webrtc::rtp_transceiver::RTCRtpTransceiver;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

use bh_crypto::call_keys::SframeContext;
use bh_crypto::envelope::CallSignal;

use crate::media_crypto::{FrameDecryptor, FrameEncryptor};
use crate::{transport, CallError};

const OPUS_CLOCK_RATE: u32 = 48_000;
/// Mirrors `session.rs`'s `SAMPLE_BUILDER_MAX_LATE` — see that constant's
/// doc comment.
const SAMPLE_BUILDER_MAX_LATE: u16 = 50;

/// Full mesh means each participant keeps `N - 1` simultaneous peer
/// connections (and, per connection, its own encode/decode/jitter-buffer
/// work) alive at once, with total connection count across the call
/// growing O(N^2). Six participants means five simultaneous audio streams
/// per participant, which a typical desktop CPU/uplink can sustain without
/// an SFU; it also keeps this squarely a "local simulation of the real
/// mesh protocol" in the same spirit as this workspace's other
/// no-live-network stand-ins (see `docs/SPEC.md`/`CLAUDE.md`) rather than
/// a claim that mesh calling scales further than it really does — beyond
/// this, a real deployment would need an SFU, which is out of scope until
/// STUN/TURN (and a relay) exist at all.
pub const MAX_GROUP_CALL_PARTICIPANTS: usize = 6;

/// Identifies one participant's frames on the call's shared
/// [`SframeContext`] — reuses `call_keys::SenderTag`'s type, just with one
/// distinct value per participant instead of only the two 1:1 constants
/// (`CALLER_SENDER_TAG`/`CALLEE_SENDER_TAG`).
pub type ParticipantTag = bh_crypto::call_keys::SenderTag;

fn to_call_error(err: impl std::fmt::Display) -> CallError {
    CallError::Transport(err.to_string())
}

fn sdp_from_bytes(bytes: Vec<u8>) -> Result<String, CallError> {
    String::from_utf8(bytes).map_err(|e| CallError::Transport(e.to_string()))
}

/// A live group call from one participant's point of view: a full mesh of
/// direct [`RTCPeerConnection`]s, one per other participant, all sharing
/// the one [`SframeContext`] derived for the call (see module docs) and
/// distinguished only by [`ParticipantTag`].
pub struct GroupCallSession {
    pub call_id: String,
    pub local_tag: ParticipantTag,
    audio_track: Arc<TrackLocalStaticSample>,
    encryptor: FrameEncryptor,
    sframe: SframeContext,
    edges: HashMap<ParticipantTag, Arc<RTCPeerConnection>>,
    frame_tx: mpsc::UnboundedSender<(ParticipantTag, Vec<u8>)>,
    frame_rx: Option<mpsc::UnboundedReceiver<(ParticipantTag, Vec<u8>)>>,
}

impl GroupCallSession {
    /// Starts this participant's side of a group call. `sframe` is the
    /// call's shared base key — every participant must be constructed with
    /// the *same* one (see [`bh_crypto::mls::Group::export_call_base_key`])
    /// — and `local_tag` must be unique among the call's participants.
    pub fn new(
        call_id: impl Into<String>,
        local_tag: ParticipantTag,
        sframe: SframeContext,
    ) -> Self {
        let call_id = call_id.into();
        let audio_track = transport::new_audio_track(&call_id);
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        Self {
            encryptor: FrameEncryptor::new(sframe.clone(), local_tag),
            call_id,
            local_tag,
            audio_track,
            sframe,
            edges: HashMap::new(),
            frame_tx,
            frame_rx: Some(frame_rx),
        }
    }

    /// How many participants (including the local one) are currently
    /// meshed into this call.
    pub fn participant_count(&self) -> usize {
        self.edges.len() + 1
    }

    /// Takes ownership of this session's decrypted-remote-audio-frame
    /// stream, tagged by which participant sent each frame. A group
    /// session fans frames in from several edges at once, so this hands
    /// back a channel rather than the single callback 1:1's
    /// `CallSession::on_remote_audio_frame` uses — callers doing real
    /// decode/playback should drain it promptly. Returns `None` if already
    /// taken.
    pub fn take_frame_receiver(
        &mut self,
    ) -> Option<mpsc::UnboundedReceiver<(ParticipantTag, Vec<u8>)>> {
        self.frame_rx.take()
    }

    fn check_capacity_for_one_more(&self) -> Result<(), CallError> {
        let would_be = self.edges.len() + 2; // existing edges + local + the new edge
        if would_be > MAX_GROUP_CALL_PARTICIPANTS {
            return Err(CallError::Transport(format!(
                "group call {} would have {would_be} participants, capped at {MAX_GROUP_CALL_PARTICIPANTS}",
                self.call_id
            )));
        }
        Ok(())
    }

    async fn new_edge_pc(&self) -> Result<Arc<RTCPeerConnection>, CallError> {
        let pc = transport::new_peer_connection(transport::default_ice_servers()).await?;
        pc.add_track(self.audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(to_call_error)?;
        Ok(pc)
    }

    /// Wires up decrypt-and-forward for whatever remote track arrives on
    /// this edge, filtered to frames actually tagged as coming from
    /// `remote_tag` (same defense-in-depth filter `CallSession::
    /// on_remote_audio_frame` applies for 1:1).
    fn wire_remote_audio(&self, pc: &Arc<RTCPeerConnection>, remote_tag: ParticipantTag) {
        let decryptor = Arc::new(FrameDecryptor::new(self.sframe.clone()));
        let tx = self.frame_tx.clone();
        pc.on_track(Box::new(
            move |track: Arc<TrackRemote>,
                  _receiver: Arc<RTCRtpReceiver>,
                  _transceiver: Arc<RTCRtpTransceiver>| {
                let decryptor = decryptor.clone();
                let tx = tx.clone();
                Box::pin(async move {
                    let sample_builder = Arc::new(TokioMutex::new(SampleBuilder::new(
                        SAMPLE_BUILDER_MAX_LATE,
                        OpusPacket,
                        OPUS_CLOCK_RATE,
                    )));
                    let mut buf = vec![0u8; 1500];
                    while let Ok((packet, _attrs)) = track.read(&mut buf).await {
                        let mut builder = sample_builder.lock().await;
                        builder.push(packet);
                        while let Some(sample) = builder.pop() {
                            if let Ok((_, tag, _, plaintext)) = decryptor.decrypt(&sample.data) {
                                if tag == remote_tag {
                                    let _ = tx.send((remote_tag, plaintext));
                                }
                            }
                        }
                    }
                })
            },
        ));
    }

    /// Opens a new mesh edge to `remote_tag` and produces the offer signal
    /// to send them. Mirrors `session::PendingOutgoingCall::start`, but
    /// keyed to one specific remote participant, sharing this call's
    /// existing audio track/SFrame context rather than deriving fresh
    /// ones per edge.
    pub async fn offer_to(
        &mut self,
        remote_tag: ParticipantTag,
        video: bool,
    ) -> Result<CallSignal, CallError> {
        self.check_capacity_for_one_more()?;
        let pc = self.new_edge_pc().await?;
        let offer_sdp = transport::create_local_offer(&pc).await?;
        self.wire_remote_audio(&pc, remote_tag);
        self.edges.insert(remote_tag, pc);
        Ok(CallSignal::GroupOffer {
            call_id: self.call_id.clone(),
            from_participant: self.local_tag,
            to_participant: remote_tag,
            transport_description: offer_sdp.into_bytes(),
            video,
        })
    }

    /// Accepts an incoming mesh-edge offer from another participant,
    /// returning the answer signal to send back. Rejects offers for a
    /// different call or addressed to a different participant tag than
    /// this session's own.
    pub async fn accept_offer(&mut self, offer: &CallSignal) -> Result<CallSignal, CallError> {
        let CallSignal::GroupOffer {
            call_id,
            from_participant,
            to_participant,
            transport_description,
            ..
        } = offer
        else {
            return Err(CallError::UnexpectedSignal);
        };
        if *call_id != self.call_id {
            return Err(CallError::CallIdMismatch);
        }
        if *to_participant != self.local_tag {
            return Err(CallError::UnexpectedSignal);
        }
        let remote_tag = *from_participant;
        self.check_capacity_for_one_more()?;
        let pc = self.new_edge_pc().await?;
        let answer_sdp =
            transport::create_local_answer(&pc, sdp_from_bytes(transport_description.clone())?)
                .await?;
        self.wire_remote_audio(&pc, remote_tag);
        self.edges.insert(remote_tag, pc);
        Ok(CallSignal::GroupAnswer {
            call_id: self.call_id.clone(),
            from_participant: self.local_tag,
            to_participant: remote_tag,
            transport_description: answer_sdp.into_bytes(),
        })
    }

    /// Completes a mesh edge previously started with [`offer_to`](Self::offer_to),
    /// applying the remote's answer.
    pub async fn complete_edge(&mut self, answer: &CallSignal) -> Result<(), CallError> {
        let CallSignal::GroupAnswer {
            call_id,
            from_participant,
            to_participant,
            transport_description,
        } = answer
        else {
            return Err(CallError::UnexpectedSignal);
        };
        if *call_id != self.call_id {
            return Err(CallError::CallIdMismatch);
        }
        if *to_participant != self.local_tag {
            return Err(CallError::UnexpectedSignal);
        }
        let remote_tag = *from_participant;
        let pc = self
            .edges
            .get(&remote_tag)
            .ok_or(CallError::UnexpectedSignal)?;
        transport::apply_remote_answer(pc, sdp_from_bytes(transport_description.clone())?).await
    }

    /// Encrypts one already-Opus-encoded audio frame with this
    /// participant's own sender tag and broadcasts it to every meshed
    /// edge at once. Broadcast, not a per-edge encrypt: every edge shares
    /// the call's one [`SframeContext`], and `TrackLocalStaticSample`
    /// natively supports being bound to multiple peer connections, so one
    /// write here fans the same ciphertext frame out to every other
    /// participant — exactly what a real mesh call does (each remote peer
    /// gets an identical encrypted frame; only DTLS-SRTP's per-hop
    /// encryption on top of it differs edge to edge).
    pub async fn send_audio_frame(
        &self,
        opus_frame: &[u8],
        duration: Duration,
    ) -> Result<(), CallError> {
        let encrypted = self.encryptor.encrypt(opus_frame)?;
        transport::write_encrypted_sample(&self.audio_track, encrypted, duration).await
    }

    /// Closes every mesh edge. Best-effort: keeps closing the rest even if
    /// one edge fails to close cleanly, and only reports the first error.
    pub async fn hangup(&self) -> Result<(), CallError> {
        let mut first_err = None;
        for pc in self.edges.values() {
            if let Err(e) = pc.close().await {
                first_err.get_or_insert_with(|| to_call_error(e));
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    use bh_crypto::mls::MlsMember;

    async fn wait_connected(pc: &Arc<RTCPeerConnection>) {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let tx = std::sync::Arc::new(tx);
        pc.on_peer_connection_state_change(Box::new(move |state| {
            if state == RTCPeerConnectionState::Connected {
                let tx = tx.clone();
                return Box::pin(async move {
                    let _ = tx.send(()).await;
                });
            }
            Box::pin(async {})
        }));
        if pc.connection_state() == RTCPeerConnectionState::Connected {
            return;
        }
        tokio::time::timeout(StdDuration::from_secs(30), rx.recv())
            .await
            .expect("peer connection did not reach Connected in time")
            .expect("state-change channel closed");
    }

    /// Builds a real 3-member MLS group (via `bh_crypto::mls`, the same
    /// crate/API `docs/SPEC.md`'s group messaging uses) purely to exercise
    /// `Group::export_call_base_key` end to end, confirming what
    /// `bh_crypto::mls`'s own test already asserts in isolation: every
    /// member derives the same call base key without any extra
    /// key-agreement round trip.
    fn three_party_call_base_keys(call_id: &str) -> [[u8; 32]; 3] {
        let alice = MlsMember::new(b"group-call-alice").unwrap();
        let bob = MlsMember::new(b"group-call-bob").unwrap();
        let carol = MlsMember::new(b"group-call-carol").unwrap();

        let mut alice_group = alice.create_group().unwrap();
        let added_bob = alice_group
            .add_member(&alice, &bob.generate_key_package().unwrap())
            .unwrap();
        let mut bob_group = bob
            .join_group(&added_bob.welcome, &added_bob.ratchet_tree)
            .unwrap();

        let added_carol = alice_group
            .add_member(&alice, &carol.generate_key_package().unwrap())
            .unwrap();
        bob_group.decrypt(&bob, &added_carol.commit).unwrap();
        let carol_group = carol
            .join_group(&added_carol.welcome, &added_carol.ratchet_tree)
            .unwrap();

        [
            alice_group.export_call_base_key(&alice, call_id).unwrap(),
            bob_group.export_call_base_key(&bob, call_id).unwrap(),
            carol_group.export_call_base_key(&carol, call_id).unwrap(),
        ]
    }

    /// End-to-end: three real local `RTCPeerConnection`-backed
    /// [`GroupCallSession`]s (tags 0/1/2), keyed from a genuinely-derived
    /// MLS group export secret, complete a full three-way mesh handshake
    /// (three edges total: 0-1, 0-2, 1-2) and exchange SFrame-encrypted
    /// "audio" frames pairwise over real RTP. Generalizes `transport.rs`'s
    /// two-peer local WebRTC test to N > 2 participants.
    #[tokio::test]
    async fn three_participants_complete_a_full_mesh_and_exchange_encrypted_audio() {
        let keys = three_party_call_base_keys("group-call-1");
        let mut sessions: Vec<GroupCallSession> = keys
            .iter()
            .enumerate()
            .map(|(tag, key)| {
                GroupCallSession::new("group-call-1", tag as u8, SframeContext::new(*key))
            })
            .collect();

        // Full mesh: every unordered pair (i, j) with i < j gets one edge.
        let pairs: [(usize, usize); 3] = [(0, 1), (0, 2), (1, 2)];
        for (i, j) in pairs {
            let offer = sessions[i].offer_to(j as u8, false).await.unwrap();
            let answer = sessions[j].accept_offer(&offer).await.unwrap();
            sessions[i].complete_edge(&answer).await.unwrap();
        }

        for s in &sessions {
            assert_eq!(
                s.participant_count(),
                3,
                "every session should see all 3 participants"
            );
        }

        // Confirm the underlying transport is actually connected, not just
        // that signaling completed — same sanity check `transport.rs`'s
        // own test performs, generalized to every edge this mesh has.
        for s in &sessions {
            for pc in s.edges.values() {
                wait_connected(pc).await;
            }
        }

        let mut receivers: Vec<_> = sessions
            .iter_mut()
            .map(|s| s.take_frame_receiver().unwrap())
            .collect();

        // Tag 0 sends a frame; tags 1 and 2 should both receive and
        // decrypt it (same broadcast, since every edge shares one SFrame
        // context and `send_audio_frame` writes once and fans out).
        for i in 0..5 {
            sessions[0]
                .send_audio_frame(
                    format!("frame-{i}").as_bytes(),
                    StdDuration::from_millis(20),
                )
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        // Flush frames, same technique `transport.rs`'s test uses: the
        // receive-side `SampleBuilder` needs a later-timestamped packet
        // before it will release the previous one.
        for _ in 0..3 {
            sessions[0]
                .send_audio_frame(b"__flush__", StdDuration::from_millis(20))
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }

        for receiver_idx in [1usize, 2usize] {
            let mut received = Vec::new();
            let deadline = tokio::time::Instant::now() + StdDuration::from_secs(15);
            while received.len() < 5 && tokio::time::Instant::now() < deadline {
                match tokio::time::timeout(
                    StdDuration::from_millis(500),
                    receivers[receiver_idx].recv(),
                )
                .await
                {
                    Ok(Some((tag, plaintext))) => {
                        assert_eq!(
                            tag, 0,
                            "frames on this receiver should only come from tag 0"
                        );
                        received.push(plaintext);
                    }
                    _ => continue,
                }
            }
            assert_eq!(
                received.len(),
                5,
                "participant {receiver_idx} should receive all 5 frames from tag 0"
            );
            for (i, frame) in received.iter().enumerate() {
                assert_eq!(frame, format!("frame-{i}").as_bytes());
            }
        }

        for s in &sessions {
            s.hangup().await.unwrap();
        }
    }

    #[test]
    fn group_offer_to_the_wrong_participant_is_rejected() {
        // Purely synchronous validation, no transport needed: construct
        // two sessions and confirm a misaddressed offer/answer is caught
        // before any transport work happens.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sframe = SframeContext::new([3u8; 32]);
            let mut session0 = GroupCallSession::new("call-x", 0, sframe.clone());
            let mut session1 = GroupCallSession::new("call-x", 1, sframe.clone());
            let mut session2 = GroupCallSession::new("call-x", 2, sframe);

            let offer = session0.offer_to(1, false).await.unwrap();
            // Session 2 was not the intended recipient.
            assert!(matches!(
                session2.accept_offer(&offer).await,
                Err(CallError::UnexpectedSignal)
            ));
            // Session 1 (the real recipient) still accepts it fine.
            assert!(session1.accept_offer(&offer).await.is_ok());
        });
    }

    #[test]
    fn capacity_cap_is_enforced() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sframe = SframeContext::new([9u8; 32]);
            let mut session0 = GroupCallSession::new("call-cap", 0, sframe.clone());
            // Fill up to exactly the cap (local participant + 5 edges = 6).
            for remote in 1..=(MAX_GROUP_CALL_PARTICIPANTS as u8 - 1) {
                session0.offer_to(remote, false).await.unwrap();
            }
            assert_eq!(session0.participant_count(), MAX_GROUP_CALL_PARTICIPANTS);
            // One more edge would exceed the cap.
            let result = session0
                .offer_to(MAX_GROUP_CALL_PARTICIPANTS as u8, false)
                .await;
            assert!(matches!(result, Err(CallError::Transport(_))));
        });
    }
}
