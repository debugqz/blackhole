//! Local, daemon-side endpoint for the opt-in "opaque wake" push feature
//! (see `crates/bh-push-relay` for the actual relay design/rationale, and
//! `docs/SPEC.md` §5.6). Manages *this identity's own* registration state
//! — whether wake pings are enabled, the opaque rotating token, and, now,
//! the `relay_url` of the `bh-push-relay` instance that token was
//! registered with.
//!
//! When a live network is attached and `relay_url` is supplied, enabling
//! push actually: (1) calls the relay's real `POST /register`, and (2)
//! signs and publishes a `bh_crypto::push_relay::PushRelayRecord` to the
//! DHT (`bh_network::push_relay_directory`) so a contact's daemon can
//! discover it and call `POST {relay_url}/wake/{token}` after a real send
//! — see `message_crypto.rs`'s `wake_recipient_best_effort`, the send-side
//! half of this wiring (previously the `// TODO(real-push)` marker next to
//! `bh_network::mailbox::Mailbox::push` this module's own doc used to
//! point at). Both the relay call and the DHT publish must succeed before
//! anything is written to local storage — see `set_push_registration`'s
//! own comment for why "enabled" must be atomic with "actually reachable."
//! With no live network (tests, or a daemon that hasn't attached one) or
//! no `relay_url` supplied, this falls back to the pre-existing
//! local-storage-only behavior, same posture every other
//! network-touching feature in this codebase already has.
//!
//! The token generated here is intentionally *not* derived from the
//! identity key or any contact/conversation id — it's random bytes, with
//! no way to link it back to who's messaging whom even if the relay
//! operator is fully compromised. It rotates every time push is
//! (re-)enabled, rather than being a fixed, permanently-issued value.
//!
//! Push is opt-in and defaults to off: enabling it costs a small amount of
//! metadata (the relay learns "some client, at roughly this time, wants a
//! wake") that a fully-offline/manually-polling user doesn't pay.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use bh_crypto::identity::recipient_key_hash;
use bh_crypto::push_relay::PushRelayRecord;
use bh_network::push_relay_directory;
use bh_network::supervised::SupervisedNetwork;
use bh_storage::models::PushRegistration;
use serde::{Deserialize, Serialize};

use crate::AppState;

const TOKEN_BYTES: usize = 32;
/// Interactive calls (the user is waiting on the `POST /push/registration`
/// response) — short enough not to hang the request indefinitely against
/// an unreachable relay.
const RELAY_REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Shared client for every daemon-to-relay HTTP call in this crate
/// (`push.rs`'s own `/register` call, and `message_crypto.rs`'s
/// `/wake/:token` call) — a fresh `reqwest::Client` per request would
/// rebuild its own connection pool every time for no benefit. No
/// client-wide default timeout; each call site sets its own explicit
/// per-request `.timeout(..)` instead, since "interactive register" and
/// "best-effort background wake" want different bounds.
pub(crate) fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Env var that disables this module's SSRF guard on `relay_url` — off by
/// default, and a genuine, labeled downgrade (same posture as
/// `BLACKHOLE_KEYSTORE_BACKEND=file`, THREAT_MODEL.md §3.7), not a free
/// fix: a real deployment should never need this, since `bh-push-relay` is
/// by design "a small, separate, internet-facing binary" (its own module
/// doc) — nothing legitimate runs it on a loopback/private address a
/// remote contact could ever need to reach. Exists only so local
/// development and this crate's own integration test
/// (`sending_a_message_wakes_the_recipients_real_push_relay`, which
/// necessarily binds its test relay to `127.0.0.1` — no real internet
/// access in CI) can keep exercising the real HTTP round trip without a
/// live public relay. Note this only ever weakens a *local* daemon's own
/// checks on a URL it's about to fetch — a remote contact can never set an
/// env var on someone else's machine, so this cannot be used to reopen the
/// SSRF gap for anyone who hasn't explicitly opted in on their own daemon.
const ALLOW_PRIVATE_RELAY_ENV: &str = "BLACKHOLE_ALLOW_PRIVATE_RELAY_URL";

fn private_relay_urls_allowed() -> bool {
    std::env::var_os(ALLOW_PRIVATE_RELAY_ENV).is_some()
}

/// Same loopback/private/link-local/multicast checks as
/// `client/desktop/src-tauri/src/link_preview.rs`'s `is_non_public_ip` —
/// same class of SSRF guard, same fix, different call site (a daemon-side
/// `reqwest` call instead of the Tauri client's `ureq` fetch).
fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            // `Ipv6Addr::is_unique_local`/`is_unicast_link_local` are still
            // unstable on stable Rust, hence the manual range checks for
            // fc00::/7 (unique local) and fe80::/10 (link-local).
            let seg0 = v6.segments()[0];
            (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// Companion to [`is_non_public_ip`] — covers the case where the host is a
/// literal IP (checked directly, no string round-trip) or the
/// `localhost`/`*.localhost` domain names, which never round-trip through
/// DNS at all. Takes `url::Host` rather than re-parsing `host_str()`
/// because `Url::host_str()` returns an IPv6 literal *with* its brackets
/// (e.g. `"[::1]"`, the form the URL's own string representation needs) —
/// `"[::1]".parse::<IpAddr>()` fails on those brackets, silently falling
/// through this function's old string-only version to the "must be a
/// domain name" branch and treating a bracketed loopback/private/
/// link-local IPv6 literal as an ordinary public hostname. `Url::host()`
/// hands back the already-parsed address directly, sidestepping the
/// bracket issue entirely rather than needing to strip it by hand.
fn is_blocked_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(v4) => is_non_public_ip(IpAddr::V4(*v4)),
        url::Host::Ipv6(v6) => is_non_public_ip(IpAddr::V6(*v6)),
        url::Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain.is_empty() || domain == "localhost" || domain.ends_with(".localhost")
        }
    }
}

/// Validates `raw` is a well-formed http(s) URL and — unless
/// [`ALLOW_PRIVATE_RELAY_ENV`] opts out — isn't pointed at a
/// loopback/private/link-local/metadata address. This is the string-level
/// fast-path check; [`pinned_relay_client`] closes the DNS-rebinding gap
/// this alone can't (a public domain name that resolves to an internal
/// address), by re-checking the *resolved* address before connecting —
/// same two-layer approach `link_preview.rs`'s `is_blocked_host`/
/// `PinningResolver` pair already uses for the analogous client-side case.
pub(crate) fn validate_relay_url(raw: &str) -> Result<url::Url, &'static str> {
    let parsed = url::Url::parse(raw.trim()).map_err(|_| "not a valid URL")?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("only http/https relay URLs are allowed");
    }
    let host = parsed.host().ok_or("relay URL has no host")?;
    if !private_relay_urls_allowed() && is_blocked_host(&host) {
        return Err("refusing to use a local/private relay URL");
    }
    Ok(parsed)
}

/// Resolves `url`'s host and returns an HTTP client whose DNS resolution
/// for that host is pinned to the address that was actually checked here —
/// so the address `reqwest` ends up connecting to for this call can't
/// silently differ from the one [`is_non_public_ip`] validated a moment
/// earlier (the classic DNS-rebinding attack against a naive
/// check-then-separately-connect guard). Implemented via
/// `reqwest::ClientBuilder::resolve` (a per-host static override) rather
/// than a custom resolver trait, since that's the override point `reqwest`
/// itself exposes. Skipped entirely when [`ALLOW_PRIVATE_RELAY_ENV`] is
/// set, falling back to the shared [`http_client`] with ordinary
/// resolution.
pub(crate) async fn pinned_relay_client(url: &url::Url) -> Result<reqwest::Client, &'static str> {
    if private_relay_urls_allowed() {
        return Ok(http_client().clone());
    }
    let host = url.host_str().ok_or("relay URL has no host")?;
    let port = url
        .port_or_known_default()
        .ok_or("relay URL has no resolvable port")?;
    // A literal IP has nothing to "rebind" — [`validate_relay_url`] (every
    // caller's own precondition) already checked it directly via
    // `is_blocked_host`, so resolve it straight to itself instead of
    // routing it through `lookup_host`, which needs a bracket-free string
    // for an IPv6 literal host (`Url::host_str()` keeps the brackets its
    // own string form needs, e.g. `"[::1]"`) and would otherwise fail to
    // resolve a perfectly valid `http://[<ipv6>]:port` relay URL.
    let literal_ip = match url.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        _ => None,
    };
    let addr = if let Some(ip) = literal_ip {
        std::net::SocketAddr::new(ip, port)
    } else {
        let mut addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| "failed to resolve relay host")?;
        addrs
            .find(|addr| !is_non_public_ip(addr.ip()))
            .ok_or("relay host resolves only to non-public addresses")?
    };
    reqwest::Client::builder()
        .resolve(host, addr)
        .build()
        .map_err(|_| "failed to build a DNS-pinned relay HTTP client")
}

#[derive(Deserialize)]
struct RelayRegisterResponse {
    registered: bool,
}

/// Calls the relay's real `POST /register` (`bh-push-relay/src/server.rs`'s
/// `RegisterRequest`/`RegisterResponse` contract).
async fn register_with_relay(relay_url: &str, token: &str) -> Result<(), StatusCode> {
    let parsed = validate_relay_url(relay_url).map_err(|_| StatusCode::BAD_REQUEST)?;
    let client = pinned_relay_client(&parsed)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let response = client
        .post(format!("{}/register", relay_url.trim_end_matches('/')))
        .timeout(RELAY_REGISTER_TIMEOUT)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !response.status().is_success() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let body: RelayRegisterResponse = response
        .json()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if body.registered {
        Ok(())
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before 1970")
        .as_secs() as i64
}

fn generate_token() -> Result<String, StatusCode> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(hex::encode(bytes))
}

#[derive(Deserialize)]
pub struct SetPushRegistrationRequest {
    pub enabled: bool,
    /// Base URL of the `bh-push-relay` instance to register with (e.g.
    /// `https://relay.example`) — required for push to actually work over
    /// the real network (see module doc); omitting it keeps the
    /// pre-existing local-only behavior. Ignored when `enabled` is
    /// `false`.
    #[serde(default)]
    pub relay_url: Option<String>,
}

#[derive(Serialize)]
pub struct PushRegistrationResponse {
    pub enabled: bool,
    /// Only present in the response to a request that just (re-)enabled
    /// push — this is the opaque token this device would register with
    /// the relay. Never the identity key, never a contact or conversation
    /// id. Deliberately omitted from plain status checks (`GET`) so it
    /// isn't handed out on every idle poll.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The relay this registration is (or was) pointed at — unlike
    /// `token`, not secret, so it's returned on plain status checks too
    /// (the client's settings UI pre-fills this field from here rather
    /// than making the user retype it every time they open settings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
}

/// Signs and publishes this identity's `PushRelayRecord` to the DHT (used
/// both by [`set_push_registration`] at enable-time and by
/// [`republish_own_registration_best_effort`] on the daemon's periodic
/// tick).
async fn publish_own_push_registration(
    state: &AppState,
    network: &SupervisedNetwork,
    relay_url: &str,
    token: &str,
) -> Result<(), StatusCode> {
    let identity = crate::message_crypto::own_identity_keypair(state)?;
    let record = PushRelayRecord::sign(&identity, relay_url.to_string(), token.to_string());
    let key_hash = recipient_key_hash(&identity.public_identity_bytes());
    push_relay_directory::publish_own_registration(&network.dht(), &key_hash, record.to_bytes())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

/// Enables or disables push registration for the active profile. Enabling
/// generates a fresh opaque token (rotating it, if one already existed).
///
/// If a live network is attached and `relay_url` is supplied, this also
/// registers the token with the relay and publishes a signed
/// `PushRelayRecord` to the DHT *before* writing anything to local
/// storage — "enabled" must be atomic with "actually reachable," the same
/// reasoning `message_crypto.rs`'s `load_or_establish_session` doc comment
/// gives for not persisting a session before its handshake is actually
/// delivered. A relay/DHT failure here surfaces as `503` rather than
/// silently leaving the profile in a state where it thinks push is on but
/// no contact could ever actually reach it.
///
/// Disabling deletes the stored registration entirely, token included —
/// there's no relay-side unregister call to make (`bh-push-relay` has none
/// today; a stale token simply stops being used, and carries no linkable
/// metadata on its own, SPEC.md §5.6).
pub async fn set_push_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetPushRegistrationRequest>,
) -> Result<Json<PushRegistrationResponse>, StatusCode> {
    if req.enabled {
        if let Some(relay_url) = &req.relay_url {
            if validate_relay_url(relay_url).is_err() {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let token = generate_token()?;

        if let (Some(network), Some(relay_url)) = (state.network.as_ref(), &req.relay_url) {
            register_with_relay(relay_url, &token).await?;
            publish_own_push_registration(&state, network, relay_url, &token).await?;
        }

        state
            .db()
            .set_push_registration(&PushRegistration {
                token: token.clone(),
                enabled: true,
                updated_at: now(),
                relay_url: req.relay_url.clone(),
            })
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(PushRegistrationResponse {
            enabled: true,
            token: Some(token),
            relay_url: req.relay_url,
        }))
    } else {
        state
            .db()
            .clear_push_registration()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(PushRegistrationResponse {
            enabled: false,
            token: None,
            relay_url: None,
        }))
    }
}

/// Re-publishes this profile's `PushRelayRecord` to the DHT, if push is
/// enabled with a `relay_url` on record — Kademlia records expire, so a
/// long-lived daemon needs to redo this periodically, same reasoning
/// `prekey_directory`'s own doc comment gives and the same pattern
/// `tree_head::publish_own_tree_head` already established. Does **not**
/// re-call the relay's `POST /register` — unlike a DHT record, the
/// relay-side registration doesn't expire, so there's nothing to redo
/// there. Best-effort: logs and returns on any failure, never propagates
/// one, since this runs on a background tick with no caller to report to.
pub async fn republish_own_registration_best_effort(
    state: &Arc<AppState>,
    network: &SupervisedNetwork,
) {
    let reg = match state.db().get_push_registration() {
        Ok(Some(reg)) => reg,
        Ok(None) => return,
        Err(err) => {
            tracing::debug!(%err, "push: failed to read registration, skipping republish");
            return;
        }
    };
    if !reg.enabled {
        return;
    }
    let Some(relay_url) = reg.relay_url else {
        return;
    };
    if let Err(err) = publish_own_push_registration(state, network, &relay_url, &reg.token).await {
        tracing::warn!(
            %err,
            "push: failed to republish push-relay registration (will retry next tick)"
        );
    }
}

/// Current status only — never returns the token itself (see
/// `PushRegistrationResponse::token` doc comment).
pub async fn get_push_registration(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PushRegistrationResponse>, StatusCode> {
    let reg = state
        .db()
        .get_push_registration()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let enabled = reg.as_ref().map(|r| r.enabled).unwrap_or(false);
    let relay_url = reg.and_then(|r| r.relay_url);
    Ok(Json(PushRegistrationResponse {
        enabled,
        token: None,
        relay_url,
    }))
}

#[cfg(test)]
mod ssrf_guard_tests {
    use super::*;

    // These deliberately never touch `ALLOW_PRIVATE_RELAY_ENV` (no
    // `std::env::set_var`) — unlike `crates/bh-api/tests/api_smoke.rs`'s
    // whole-binary `Once`-gated override, these run alongside every other
    // `#[test]` in this crate's own unit-test binary, and mutating shared
    // process env here would race with them. They only assert the default
    // (env var unset) strict behavior, which is what every real deployment
    // actually runs with.

    #[test]
    fn rejects_non_http_schemes() {
        assert!(validate_relay_url("file:///etc/passwd").is_err());
        assert!(validate_relay_url("ftp://relay.example/x").is_err());
    }

    #[test]
    fn rejects_loopback_and_private_hosts() {
        assert!(validate_relay_url("http://localhost:8080").is_err());
        assert!(validate_relay_url("http://LOCALHOST:8080").is_err());
        assert!(validate_relay_url("http://127.0.0.1:8080").is_err());
        assert!(validate_relay_url("http://[::1]:8080").is_err());
        // Cloud metadata endpoint — the classic SSRF target.
        assert!(validate_relay_url("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_relay_url("http://10.0.0.5:8080").is_err());
        assert!(validate_relay_url("http://172.16.0.5:8080").is_err());
        assert!(validate_relay_url("http://192.168.1.1:8080").is_err());
        assert!(validate_relay_url("http://[fe80::1]:8080").is_err());
        assert!(validate_relay_url("http://[fc00::1]:8080").is_err());
    }

    #[test]
    fn accepts_a_well_formed_public_url() {
        assert!(validate_relay_url("https://relay.example.com").is_ok());
        assert!(validate_relay_url("  https://relay.example.com/  ").is_ok());
    }

    #[test]
    fn rejects_garbage_input() {
        assert!(validate_relay_url("not a url").is_err());
        assert!(validate_relay_url("").is_err());
    }
}
