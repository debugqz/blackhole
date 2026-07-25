//! Real WebRTC (ICE/DTLS/SRTP) transport via `webrtc-rs`. This is the hop-
//! security layer — it protects each leg to/from a relay, same as any
//! other WebRTC app. `media_crypto.rs`'s SFrame layer rides on top,
//! encrypting/decrypting the encoded audio/video *samples* before they're
//! handed to (or read from) the RTP (de)packetizers here, so the payload
//! stays confidential end-to-end even from a coerced/malicious relay.
//!
//! STUN is wired in via [`default_ice_servers`] (a public server by
//! default, configurable via `BLACKHOLE_STUN_SERVERS`). TURN is now
//! configurable too, via `BLACKHOLE_TURN_SERVERS` (comma-separated
//! `turn:`/`turns:` URLs) plus one of two credential schemes — but no TURN
//! server is deployed for this project, so unless an operator sets one of
//! them, a symmetric NAT on either side still won't connect; STUN alone
//! only resolves the more common NAT types.
//!
//! - `BLACKHOLE_TURN_USERNAME`/`BLACKHOLE_TURN_CREDENTIAL`: one fixed
//!   long-term-credential pair (coturn's `lt-cred-mech`). Simple, but a
//!   leaked credential is leaked forever until an operator rotates it and
//!   restarts every daemon.
//! - `BLACKHOLE_TURN_AUTH_SECRET`: coturn's TURN REST API scheme
//!   (`use-auth-secret`/`static-auth-secret` on the coturn side) instead —
//!   a shared secret never leaves this process; what actually goes out on
//!   the wire to the ICE-server config is a fresh `username`/`credential`
//!   pair per call, time-limited (`BLACKHOLE_TURN_CREDENTIAL_TTL_SECS`,
//!   default 24h) via HMAC-SHA1 over an expiry-embedding username, exactly
//!   as coturn's own REST API spec defines it (HMAC-SHA1 because that's
//!   what coturn interop requires, not a choice made here — same "audited
//!   primitive composition" pattern `bh-crypto::webhook.rs` already uses
//!   for HMAC-SHA256). Preferred when available: closes the "a leaked
//!   credential is leaked forever" gap `infra/README.md`'s TURN section
//!   used to call out as needing a code change first — this is that
//!   change. Takes priority over the static pair if both are set.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_OPUS, MIME_TYPE_VP8};
use webrtc::api::APIBuilder;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{
    RTCRtpCodecCapability, RTCRtpHeaderExtensionCapability, RTPCodecType,
};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;

/// Standard IANA-registered RTP header extension URIs (RFC 8843/9143).
/// `webrtc-rs` needs both registered on the `MediaEngine` whenever a peer
/// connection can carry more than one track of the same kind bundled over
/// one transport (audio+video+screen here, all sharing one ICE/DTLS
/// session) — without them, a packet whose SSRC hasn't yet been matched
/// to a track via the SDP's own `a=ssrc` lines (a race that can happen
/// under real network jitter/CI resource contention, not just simulcast)
/// falls back to MID-based demuxing, which `webrtc-rs` hard-errors on
/// (`ErrPeerConnSimulcastMidRTPExtensionRequired`/
/// `ErrPeerConnSimulcastStreamIDRTPExtensionRequired`) if these aren't
/// registered — silently and permanently losing that track's RTP stream
/// for the rest of the call, not just delaying it.
const SDES_MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const SDES_RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";

use crate::CallError;

fn to_call_error(err: impl std::fmt::Display) -> CallError {
    CallError::Transport(err.to_string())
}

fn parse_url_list(env_var: &str) -> Vec<String> {
    std::env::var(env_var)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Default TTL for a `BLACKHOLE_TURN_AUTH_SECRET`-derived credential
/// (seconds) when `BLACKHOLE_TURN_CREDENTIAL_TTL_SECS` isn't set —
/// generous since a fresh credential is minted per [`default_ice_servers`]
/// call (i.e. per connection) rather than reused across many calls, so
/// this only needs to outlast one call's duration, not a long-lived
/// session.
const DEFAULT_TURN_CREDENTIAL_TTL_SECS: u64 = 24 * 60 * 60;

/// Builds a coturn TURN-REST-API username: `"<expiry-unix-ts>"`, or
/// `"<expiry-unix-ts>:<user_label>"` when a non-empty label is given —
/// exactly the format coturn's `use-auth-secret` mode expects to find the
/// embedded expiry in.
fn ephemeral_turn_username(user_label: &str, ttl_secs: u64) -> String {
    let expiry_unix_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(ttl_secs);
    if user_label.is_empty() {
        expiry_unix_secs.to_string()
    } else {
        format!("{expiry_unix_secs}:{user_label}")
    }
}

/// The credential half of coturn's TURN REST API scheme:
/// `base64(HMAC-SHA1(secret, username))`. coturn recomputes this same
/// value from its own `static-auth-secret` and the username the client
/// presented — matching confirms both the credential is authentic *and*
/// (by checking the embedded expiry) not stale, without the secret itself
/// ever having to leave this process.
fn ephemeral_turn_credential(secret: &str, username: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Resolves which of the two TURN credential schemes documented on this
/// module is configured, if either — see the module doc for
/// `BLACKHOLE_TURN_AUTH_SECRET` vs
/// `BLACKHOLE_TURN_USERNAME`/`BLACKHOLE_TURN_CREDENTIAL`. Returns `None`
/// (after a `tracing::warn!`) when neither scheme is fully configured, so
/// [`default_ice_servers`] doesn't build a TURN config `webrtc-rs` would
/// reject at connection time with a much less obvious error. Only called
/// once `BLACKHOLE_TURN_SERVERS` itself is known to be non-empty.
fn resolve_turn_credentials() -> Option<(String, String)> {
    let auth_secret = std::env::var("BLACKHOLE_TURN_AUTH_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    let username_env = std::env::var("BLACKHOLE_TURN_USERNAME").unwrap_or_default();
    let static_credential = std::env::var("BLACKHOLE_TURN_CREDENTIAL").unwrap_or_default();

    if let Some(secret) = auth_secret {
        if !static_credential.is_empty() {
            tracing::warn!(
                "both BLACKHOLE_TURN_AUTH_SECRET and BLACKHOLE_TURN_CREDENTIAL are set — \
                 using ephemeral REST-API credentials derived from BLACKHOLE_TURN_AUTH_SECRET \
                 and ignoring the static BLACKHOLE_TURN_CREDENTIAL"
            );
        }
        let ttl_secs = std::env::var("BLACKHOLE_TURN_CREDENTIAL_TTL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TURN_CREDENTIAL_TTL_SECS);
        let username = ephemeral_turn_username(&username_env, ttl_secs);
        let credential = ephemeral_turn_credential(&secret, &username);
        return Some((username, credential));
    }

    if username_env.is_empty() || static_credential.is_empty() {
        tracing::warn!(
            "BLACKHOLE_TURN_SERVERS is set but neither BLACKHOLE_TURN_AUTH_SECRET nor a \
             complete BLACKHOLE_TURN_USERNAME/_CREDENTIAL pair is — skipping TURN, calls \
             will only work for NAT types STUN alone can traverse"
        );
        return None;
    }

    Some((username_env, static_credential))
}

/// Default ICE server list: `BLACKHOLE_STUN_SERVERS` (comma-separated
/// `stun:host:port` URLs) if set, otherwise a single public STUN server
/// (Google's, widely used as a default by other WebRTC apps — no account
/// or credentials needed for STUN, unlike TURN). A second `RTCIceServer`
/// entry for TURN is appended when `BLACKHOLE_TURN_SERVERS` (comma-
/// separated `turn:`/`turns:` URLs) is set *and* [`resolve_turn_credentials`]
/// finds one of the two credential schemes documented on this module fully
/// configured — see the module doc for `BLACKHOLE_TURN_AUTH_SECRET` vs
/// `BLACKHOLE_TURN_USERNAME`/`BLACKHOLE_TURN_CREDENTIAL`.
pub fn default_ice_servers() -> Vec<webrtc::ice_transport::ice_server::RTCIceServer> {
    use webrtc::ice_transport::ice_server::RTCIceServer;

    let stun_urls = {
        let urls = parse_url_list("BLACKHOLE_STUN_SERVERS");
        if urls.is_empty() {
            vec!["stun:stun.l.google.com:19302".to_owned()]
        } else {
            urls
        }
    };

    let mut servers = vec![RTCIceServer {
        urls: stun_urls,
        ..Default::default()
    }];

    let turn_urls = parse_url_list("BLACKHOLE_TURN_SERVERS");
    if !turn_urls.is_empty() {
        if let Some((username, credential)) = resolve_turn_credentials() {
            servers.push(RTCIceServer {
                urls: turn_urls,
                username,
                credential,
            });
        }
    }

    servers
}

/// Builds a fresh peer connection with Opus/VP8 (and the rest of
/// webrtc-rs's default codec set) registered. Pass [`default_ice_servers`]
/// for the normal STUN-enabled configuration, or an explicit list (e.g.
/// `vec![]` in tests that only need same-machine loopback connectivity).
pub async fn new_peer_connection(
    ice_servers: Vec<webrtc::ice_transport::ice_server::RTCIceServer>,
) -> Result<Arc<RTCPeerConnection>, CallError> {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .map_err(to_call_error)?;
    for uri in [SDES_MID_URI, SDES_RTP_STREAM_ID_URI] {
        for kind in [RTPCodecType::Audio, RTPCodecType::Video] {
            media_engine
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability {
                        uri: uri.to_owned(),
                    },
                    kind,
                    None,
                )
                .map_err(to_call_error)?;
        }
    }
    let api = APIBuilder::new().with_media_engine(media_engine).build();
    let config = RTCConfiguration {
        ice_servers,
        ..Default::default()
    };
    let pc = api
        .new_peer_connection(config)
        .await
        .map_err(to_call_error)?;
    Ok(Arc::new(pc))
}

pub fn new_audio_track(stream_id: &str) -> Arc<TrackLocalStaticSample> {
    Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48_000,
            channels: 2,
            ..Default::default()
        },
        "audio".to_owned(),
        stream_id.to_owned(),
    ))
}

pub fn new_video_track(stream_id: &str) -> Arc<TrackLocalStaticSample> {
    Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90_000,
            ..Default::default()
        },
        "video".to_owned(),
        stream_id.to_owned(),
    ))
}

/// A second, parallel VP8 track for screen-share video — same codec
/// capability as [`new_video_track`], just a distinct track id ("screen"
/// vs "video") so the receive side can tell which source a given remote
/// `TrackRemote` is (see `TrackRemote::id`) and depacketize/route it
/// separately from camera video, even though both carry SFrame-encrypted
/// VP8 samples produced by the exact same encoder/encryption path.
pub fn new_screen_share_track(stream_id: &str) -> Arc<TrackLocalStaticSample> {
    Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90_000,
            ..Default::default()
        },
        "screen".to_owned(),
        stream_id.to_owned(),
    ))
}

/// Writes one already-SFrame-encrypted sample (an encrypted Opus or VP8
/// frame) to a local track. webrtc-rs packetizes it into RTP and DTLS-SRTP
/// encrypts that for the hop to whatever's on the other end — our own
/// encryption is already baked into `data` by the time it gets here.
pub async fn write_encrypted_sample(
    track: &TrackLocalStaticSample,
    encrypted_frame: Vec<u8>,
    duration: Duration,
) -> Result<(), CallError> {
    track
        .write_sample(&Sample {
            data: encrypted_frame.into(),
            timestamp: SystemTime::now(),
            duration,
            ..Default::default()
        })
        .await
        .map_err(to_call_error)
}

/// Creates a local offer, waits for ICE gathering to finish, and returns
/// the resulting SDP (candidates included — "vanilla"/non-trickle ICE,
/// simplest to ferry as a single opaque blob inside
/// `envelope::CallSignal::Offer`).
pub async fn create_local_offer(pc: &RTCPeerConnection) -> Result<String, CallError> {
    let offer = pc.create_offer(None).await.map_err(to_call_error)?;
    let mut gather_complete = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .map_err(to_call_error)?;
    let _ = gather_complete.recv().await;
    let desc = pc
        .local_description()
        .await
        .ok_or_else(|| CallError::Transport("no local description after offer".into()))?;
    Ok(desc.sdp)
}

/// Applies a remote offer, creates the matching local answer, waits for
/// ICE gathering, and returns the answer's SDP.
pub async fn create_local_answer(
    pc: &RTCPeerConnection,
    remote_offer_sdp: String,
) -> Result<String, CallError> {
    let offer = RTCSessionDescription::offer(remote_offer_sdp).map_err(to_call_error)?;
    pc.set_remote_description(offer)
        .await
        .map_err(to_call_error)?;

    let answer = pc.create_answer(None).await.map_err(to_call_error)?;
    let mut gather_complete = pc.gathering_complete_promise().await;
    pc.set_local_description(answer)
        .await
        .map_err(to_call_error)?;
    let _ = gather_complete.recv().await;
    let desc = pc
        .local_description()
        .await
        .ok_or_else(|| CallError::Transport("no local description after answer".into()))?;
    Ok(desc.sdp)
}

/// The caller's side: applies the callee's answer to finish the handshake.
pub async fn apply_remote_answer(
    pc: &RTCPeerConnection,
    remote_answer_sdp: String,
) -> Result<(), CallError> {
    let answer = RTCSessionDescription::answer(remote_answer_sdp).map_err(to_call_error)?;
    pc.set_remote_description(answer)
        .await
        .map_err(to_call_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration as StdDuration;

    use webrtc::media::io::sample_builder::SampleBuilder;
    use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
    use webrtc::rtp::codecs::opus::OpusPacket;
    use webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
    use webrtc::rtp_transceiver::RTCRtpTransceiver;
    use webrtc::track::track_remote::TrackRemote;

    use crate::media_crypto::{FrameDecryptor, FrameEncryptor};
    use crate::signaling::{IncomingCall, OutgoingCall, CALLER_SENDER_TAG};

    // `cargo test` runs tests in this file concurrently by default, and
    // the tests below mutate the same process-wide `BLACKHOLE_STUN_SERVERS`/
    // `BLACKHOLE_TURN_*` env vars — without this lock they race, causing
    // sporadic failures unrelated to any test's actual logic (same
    // reasoning `daemon_lifecycle.rs`'s own env-var tests rely on).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard {
        name: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var(name).ok();
            // SAFETY: every caller holds `ENV_LOCK` for the duration of the
            // test that uses this guard.
            unsafe { std::env::set_var(name, value) };
            Self { name, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => unsafe { std::env::set_var(self.name, v) },
                None => unsafe { std::env::remove_var(self.name) },
            }
        }
    }

    #[test]
    fn default_ice_servers_falls_back_to_a_public_stun_server_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var("BLACKHOLE_STUN_SERVERS").ok();
        // SAFETY: serialized against the other test in this module via
        // `ENV_LOCK`, and the var is restored before returning.
        unsafe { std::env::remove_var("BLACKHOLE_STUN_SERVERS") };
        let servers = default_ice_servers();
        match previous {
            Some(v) => unsafe { std::env::set_var("BLACKHOLE_STUN_SERVERS", v) },
            None => unsafe { std::env::remove_var("BLACKHOLE_STUN_SERVERS") },
        }
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].urls, vec!["stun:stun.l.google.com:19302"]);
    }

    #[test]
    fn default_ice_servers_honors_the_env_var_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var("BLACKHOLE_STUN_SERVERS").ok();
        unsafe {
            std::env::set_var(
                "BLACKHOLE_STUN_SERVERS",
                " stun:a.example:3478 , stun:b.example:3478 ",
            );
        }
        let servers = default_ice_servers();
        match previous {
            Some(v) => unsafe { std::env::set_var("BLACKHOLE_STUN_SERVERS", v) },
            None => unsafe { std::env::remove_var("BLACKHOLE_STUN_SERVERS") },
        }
        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0].urls,
            vec!["stun:a.example:3478", "stun:b.example:3478"]
        );
    }

    #[test]
    fn default_ice_servers_adds_no_turn_entry_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _turn = EnvVarGuard::set("BLACKHOLE_STUN_SERVERS", "stun:stun.example:3478");
        // SAFETY: serialized via `ENV_LOCK`.
        unsafe { std::env::remove_var("BLACKHOLE_TURN_SERVERS") };
        let servers = default_ice_servers();
        assert_eq!(servers.len(), 1);
    }

    #[test]
    fn default_ice_servers_adds_a_turn_entry_when_fully_configured() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _stun = EnvVarGuard::set("BLACKHOLE_STUN_SERVERS", "stun:stun.example:3478");
        let _turn_urls = EnvVarGuard::set("BLACKHOLE_TURN_SERVERS", "turn:turn.example:3478");
        let _turn_user = EnvVarGuard::set("BLACKHOLE_TURN_USERNAME", "alice");
        let _turn_cred = EnvVarGuard::set("BLACKHOLE_TURN_CREDENTIAL", "s3cret");

        let servers = default_ice_servers();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[1].urls, vec!["turn:turn.example:3478"]);
        assert_eq!(servers[1].username, "alice");
        assert_eq!(servers[1].credential, "s3cret");
    }

    #[test]
    fn default_ice_servers_skips_turn_when_credentials_are_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _stun = EnvVarGuard::set("BLACKHOLE_STUN_SERVERS", "stun:stun.example:3478");
        let _turn_urls = EnvVarGuard::set("BLACKHOLE_TURN_SERVERS", "turn:turn.example:3478");
        // SAFETY: serialized via `ENV_LOCK`.
        unsafe {
            std::env::remove_var("BLACKHOLE_TURN_USERNAME");
            std::env::remove_var("BLACKHOLE_TURN_CREDENTIAL");
        }

        let servers = default_ice_servers();
        assert_eq!(servers.len(), 1);
    }

    #[test]
    fn default_ice_servers_uses_ephemeral_rest_credentials_when_auth_secret_is_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _stun = EnvVarGuard::set("BLACKHOLE_STUN_SERVERS", "stun:stun.example:3478");
        let _turn_urls = EnvVarGuard::set("BLACKHOLE_TURN_SERVERS", "turn:turn.example:3478");
        let _secret = EnvVarGuard::set("BLACKHOLE_TURN_AUTH_SECRET", "top-secret");
        let _label = EnvVarGuard::set("BLACKHOLE_TURN_USERNAME", "blackhole");
        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("BLACKHOLE_TURN_CREDENTIAL");
            std::env::remove_var("BLACKHOLE_TURN_CREDENTIAL_TTL_SECS");
        }

        let servers = default_ice_servers();
        assert_eq!(servers.len(), 2);
        let turn = &servers[1];
        assert_eq!(turn.urls, vec!["turn:turn.example:3478"]);

        let (expiry_str, label) = turn
            .username
            .split_once(':')
            .expect("username must embed expiry:label");
        assert_eq!(label, "blackhole");
        let expiry: u64 = expiry_str.parse().expect("expiry must be a unix timestamp");
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(expiry > now, "expiry must be in the future");
        assert!(
            expiry <= now + DEFAULT_TURN_CREDENTIAL_TTL_SECS + 5,
            "expiry must respect the default TTL"
        );

        let expected_credential = ephemeral_turn_credential("top-secret", &turn.username);
        assert_eq!(turn.credential, expected_credential);
    }

    #[test]
    fn default_ice_servers_prefers_auth_secret_over_a_static_credential_when_both_are_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _stun = EnvVarGuard::set("BLACKHOLE_STUN_SERVERS", "stun:stun.example:3478");
        let _turn_urls = EnvVarGuard::set("BLACKHOLE_TURN_SERVERS", "turn:turn.example:3478");
        let _secret = EnvVarGuard::set("BLACKHOLE_TURN_AUTH_SECRET", "top-secret");
        let _user = EnvVarGuard::set("BLACKHOLE_TURN_USERNAME", "alice");
        let _cred = EnvVarGuard::set("BLACKHOLE_TURN_CREDENTIAL", "s3cret-static");
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::remove_var("BLACKHOLE_TURN_CREDENTIAL_TTL_SECS") };

        let servers = default_ice_servers();
        assert_eq!(servers.len(), 2);
        assert_ne!(
            servers[1].credential, "s3cret-static",
            "must not fall back to the static credential when the auth secret is present"
        );
    }

    #[test]
    fn ephemeral_turn_username_embeds_expiry_and_optional_label() {
        let without_label = ephemeral_turn_username("", 60);
        assert!(!without_label.contains(':'));
        without_label
            .parse::<u64>()
            .expect("must be a bare unix timestamp");

        let with_label = ephemeral_turn_username("alice", 60);
        let (expiry_str, label) = with_label.split_once(':').unwrap();
        assert_eq!(label, "alice");
        expiry_str
            .parse::<u64>()
            .expect("prefix must be a unix timestamp");
    }

    #[test]
    fn ephemeral_turn_credential_is_a_deterministic_hmac_sha1_of_the_username() {
        let a = ephemeral_turn_credential("secret", "1234567890:alice");
        let b = ephemeral_turn_credential("secret", "1234567890:alice");
        assert_eq!(a, b, "same inputs must produce the same credential");

        let different = ephemeral_turn_credential("secret", "1234567890:bob");
        assert_ne!(
            a, different,
            "different usernames must produce different credentials"
        );
    }

    async fn wait_connected(pc: &Arc<RTCPeerConnection>) {
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
        // Generous timeout: this is real local UDP/ICE/DTLS negotiation,
        // not a mock, so it's sensitive to system load — e.g. running
        // alongside other test binaries in a full `cargo test --workspace`
        // pass.
        tokio::time::timeout(StdDuration::from_secs(30), rx.recv())
            .await
            .expect("peer connection did not reach Connected in time")
            .expect("state-change channel closed");
    }

    /// End-to-end: two real local `RTCPeerConnection`s complete a full
    /// offer/answer/ICE handshake, the caller sends SFrame-encrypted
    /// "audio" frames over a real Opus track, and the callee receives them
    /// over real RTP and decrypts them with the SFrame context derived via
    /// `signaling.rs`'s key agreement. Confirms the whole
    /// signaling+crypto+transport stack actually interoperates, not just
    /// each piece in isolation.
    #[tokio::test]
    async fn encrypted_audio_frames_survive_a_real_local_webrtc_connection() {
        let caller_pc = new_peer_connection(vec![]).await.unwrap();
        let callee_pc = new_peer_connection(vec![]).await.unwrap();

        let audio_track = new_audio_track("bh-calls-test-audio");
        caller_pc
            .add_track(audio_track.clone()
                as Arc<dyn webrtc::track::track_local::TrackLocal + Send + Sync>)
            .await
            .unwrap();

        let received_track: Arc<tokio::sync::Mutex<Option<Arc<TrackRemote>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let received_track_clone = received_track.clone();
        callee_pc.on_track(Box::new(
            move |track: Arc<TrackRemote>,
                  _receiver: Arc<RTCRtpReceiver>,
                  _transceiver: Arc<RTCRtpTransceiver>| {
                let received_track_clone = received_track_clone.clone();
                Box::pin(async move {
                    *received_track_clone.lock().await = Some(track);
                })
            },
        ));

        // Signaling + key agreement (bh-crypto, via signaling.rs) — happens
        // "out of band" here (in production: inside an encrypted chat
        // envelope), interleaved with the real transport handshake.
        let outgoing = OutgoingCall::new("test-call-1", false);
        let offer_sdp = create_local_offer(&caller_pc).await.unwrap();
        let offer_signal = outgoing.offer(offer_sdp.into_bytes());

        let incoming = IncomingCall::from_offer(&offer_signal).unwrap();
        let answer_sdp = create_local_answer(
            &callee_pc,
            String::from_utf8(incoming.transport_description.clone()).unwrap(),
        )
        .await
        .unwrap();
        let (answer_signal, callee_sframe) = incoming.answer(answer_sdp.into_bytes());

        let (caller_sframe, callee_answer_sdp) = outgoing.accept_answer(&answer_signal).unwrap();
        apply_remote_answer(&caller_pc, String::from_utf8(callee_answer_sdp).unwrap())
            .await
            .unwrap();

        wait_connected(&caller_pc).await;
        wait_connected(&callee_pc).await;

        let encryptor = FrameEncryptor::new(caller_sframe, CALLER_SENDER_TAG);
        let decryptor = FrameDecryptor::new(callee_sframe);

        // Send a handful of frames at a realistic 20ms Opus cadence.
        let plaintexts: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("opus-frame-{i}").into_bytes())
            .collect();
        for plaintext in &plaintexts {
            let encrypted = encryptor.encrypt(plaintext).unwrap();
            write_encrypted_sample(&audio_track, encrypted, StdDuration::from_millis(20))
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        // `SampleBuilder` needs a *later*-timestamped packet to arrive
        // before it will consider the previous one complete — send a few
        // trailing filler frames purely to flush the last real frame out
        // on the receive side (filtered out of the assertion below, not
        // part of what's being verified).
        for _ in 0..3 {
            let encrypted = encryptor.encrypt(b"__flush__").unwrap();
            write_encrypted_sample(&audio_track, encrypted, StdDuration::from_millis(20))
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }

        let track = tokio::time::timeout(StdDuration::from_secs(15), async {
            loop {
                if let Some(t) = received_track.lock().await.clone() {
                    return t;
                }
                tokio::time::sleep(StdDuration::from_millis(20)).await;
            }
        })
        .await
        .expect("callee never received the remote track");

        let mut sample_builder = SampleBuilder::new(50, OpusPacket, 48_000);
        let mut decrypted_plaintexts = Vec::new();
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(15);
        let mut buf = vec![0u8; 1500];
        let received_any = AtomicBool::new(false);
        while decrypted_plaintexts.len() < plaintexts.len()
            && tokio::time::Instant::now() < deadline
        {
            match tokio::time::timeout(StdDuration::from_millis(500), track.read(&mut buf)).await {
                Ok(Ok((packet, _attrs))) => {
                    received_any.store(true, Ordering::SeqCst);
                    sample_builder.push(packet);
                    while let Some(sample) = sample_builder.pop() {
                        let (_, _, _, plaintext) = decryptor.decrypt(&sample.data).unwrap();
                        decrypted_plaintexts.push(plaintext);
                    }
                }
                _ => continue,
            }
        }

        assert!(
            received_any.load(Ordering::SeqCst),
            "never read any RTP packets"
        );
        assert_eq!(
            decrypted_plaintexts, plaintexts,
            "the real frames (filler frames excluded) must decrypt in order"
        );

        let _ = caller_pc.close().await;
        let _ = callee_pc.close().await;
    }

    /// Same shape as the audio test above, but for the screen-share track
    /// ([`new_screen_share_track`]): confirms a *second*, independent VP8
    /// track (distinct id from camera video, `"screen"`) survives a real
    /// local WebRTC connection end to end through SFrame encryption too —
    /// i.e. screen sharing rides the same transport+crypto stack as
    /// audio/video, just on its own track, not a special-cased path.
    #[tokio::test]
    async fn encrypted_screen_share_frames_survive_a_real_local_webrtc_connection() {
        let caller_pc = new_peer_connection(vec![]).await.unwrap();
        let callee_pc = new_peer_connection(vec![]).await.unwrap();

        let screen_track = new_screen_share_track("bh-calls-test-screen");
        caller_pc
            .add_track(screen_track.clone()
                as Arc<dyn webrtc::track::track_local::TrackLocal + Send + Sync>)
            .await
            .unwrap();

        let received_track: Arc<tokio::sync::Mutex<Option<Arc<TrackRemote>>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let received_track_clone = received_track.clone();
        callee_pc.on_track(Box::new(
            move |track: Arc<TrackRemote>,
                  _receiver: Arc<RTCRtpReceiver>,
                  _transceiver: Arc<RTCRtpTransceiver>| {
                let received_track_clone = received_track_clone.clone();
                Box::pin(async move {
                    *received_track_clone.lock().await = Some(track);
                })
            },
        ));

        let outgoing = OutgoingCall::new("test-call-screen-1", true);
        let offer_sdp = create_local_offer(&caller_pc).await.unwrap();
        let offer_signal = outgoing.offer(offer_sdp.into_bytes());

        let incoming = IncomingCall::from_offer(&offer_signal).unwrap();
        let answer_sdp = create_local_answer(
            &callee_pc,
            String::from_utf8(incoming.transport_description.clone()).unwrap(),
        )
        .await
        .unwrap();
        let (answer_signal, callee_sframe) = incoming.answer(answer_sdp.into_bytes());

        let (caller_sframe, callee_answer_sdp) = outgoing.accept_answer(&answer_signal).unwrap();
        apply_remote_answer(&caller_pc, String::from_utf8(callee_answer_sdp).unwrap())
            .await
            .unwrap();

        wait_connected(&caller_pc).await;
        wait_connected(&callee_pc).await;

        let encryptor = FrameEncryptor::new(caller_sframe, CALLER_SENDER_TAG);
        let decryptor = FrameDecryptor::new(callee_sframe);

        // Screen-share frames at a realistic-ish cadence for a low-fps
        // screen share (here: every 100ms, i.e. ~10fps) — stands in for
        // already-VP8-encoded frame payloads (this test exercises
        // transport+crypto, not the codec, same as the audio test above).
        let plaintexts: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("vp8-screen-frame-{i}").into_bytes())
            .collect();
        for plaintext in &plaintexts {
            let encrypted = encryptor.encrypt(plaintext).unwrap();
            write_encrypted_sample(&screen_track, encrypted, StdDuration::from_millis(100))
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        for _ in 0..3 {
            let encrypted = encryptor.encrypt(b"__flush__").unwrap();
            write_encrypted_sample(&screen_track, encrypted, StdDuration::from_millis(100))
                .await
                .unwrap();
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }

        let track = tokio::time::timeout(StdDuration::from_secs(15), async {
            loop {
                if let Some(t) = received_track.lock().await.clone() {
                    return t;
                }
                tokio::time::sleep(StdDuration::from_millis(20)).await;
            }
        })
        .await
        .expect("callee never received the remote screen-share track");
        assert_eq!(
            track.id(),
            "screen",
            "must be the screen-share track, not camera video"
        );

        let mut sample_builder =
            SampleBuilder::new(50, webrtc::rtp::codecs::vp8::Vp8Packet::default(), 90_000);
        let mut decrypted_plaintexts = Vec::new();
        let deadline = tokio::time::Instant::now() + StdDuration::from_secs(15);
        let mut buf = vec![0u8; 1500];
        let received_any = AtomicBool::new(false);
        while decrypted_plaintexts.len() < plaintexts.len()
            && tokio::time::Instant::now() < deadline
        {
            match tokio::time::timeout(StdDuration::from_millis(500), track.read(&mut buf)).await {
                Ok(Ok((packet, _attrs))) => {
                    received_any.store(true, Ordering::SeqCst);
                    sample_builder.push(packet);
                    while let Some(sample) = sample_builder.pop() {
                        let (_, _, _, plaintext) = decryptor.decrypt(&sample.data).unwrap();
                        decrypted_plaintexts.push(plaintext);
                    }
                }
                _ => continue,
            }
        }

        assert!(
            received_any.load(Ordering::SeqCst),
            "never read any RTP packets on the screen-share track"
        );
        assert_eq!(
            decrypted_plaintexts, plaintexts,
            "the real screen-share frames (filler frames excluded) must decrypt in order"
        );

        let _ = caller_pc.close().await;
        let _ = callee_pc.close().await;
    }
}
