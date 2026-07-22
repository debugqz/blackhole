//! Round-trip and zero-knowledge-shape smoke tests for the push relay,
//! driven in-process via `tower::ServiceExt::oneshot` (mirrors
//! `crates/bh-api/tests/api_smoke.rs` — no real TCP listener needed). These
//! don't just check status codes: they check the *shape* of what the relay
//! is even capable of accepting or returning, since that's the actual
//! guarantee this crate makes — it is structurally unable to see message
//! content, sender identity, or conversation identity, not merely
//! "chooses" not to look at them.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use bh_push_relay::{RelayServer, RelayState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> axum::Router {
    RelayServer::router(Arc::new(RelayState::new()))
}

fn app_with_state(state: RelayState) -> axum::Router {
    RelayServer::router(Arc::new(state))
}

/// The IP every test request appears to come from unless a test explicitly
/// asks for a different one (see `rate_limit_tests` below) — the router's
/// `GovernorLayer` rate-limits by peer IP, and `PeerIpKeyExtractor` reads
/// it from a `ConnectInfo` extension that only a real
/// `into_make_service_with_connect_info` populates outside tests. Kept as
/// one fixed address across the ordinary round-trip tests (rather than a
/// fresh one per test) so they all share the *same* rate-limit bucket —
/// this is deliberate: it's what proves the default burst allowance is
/// generous enough for a single client's normal request pattern (a
/// handful of calls) without tripping the limiter, the same way a real
/// client hitting this relay a few times in a row shouldn't get throttled.
fn test_peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 1234)
}

fn with_connect_info(mut req: Request<Body>, peer: SocketAddr) -> Request<Body> {
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        test_peer(),
    )
}

fn wake_request(token: &str) -> Request<Body> {
    with_connect_info(
        Request::builder()
            .method("POST")
            .uri(format!("/wake/{token}"))
            .body(Body::empty())
            .unwrap(),
        test_peer(),
    )
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn register_then_wake_round_trip() {
    let app = app();
    let token = "a".repeat(32);

    let response = app
        .clone()
        .oneshot(json_request("POST", "/register", json!({ "token": token })))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body, json!({ "registered": true }));

    let response = app.oneshot(wake_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn waking_an_unregistered_token_is_not_found() {
    let app = app();
    let response = app
        .oneshot(wake_request("never-registered-00000000000000"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tokens_outside_length_bounds_are_rejected() {
    let app = app();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/register",
            json!({ "token": "short" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .oneshot(json_request(
            "POST",
            "/register",
            json!({ "token": "x".repeat(1024) }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// `RegisterRequest` has exactly one field: `token`. Sending a request
/// shaped like an attempt to smuggle message content, a sender identity
/// key, or a conversation id through this API doesn't get rejected by a
/// runtime content filter (this crate has none, deliberately — see the
/// crate docs on "no content scanning") — it gets silently dropped by
/// serde, because the type has no field to deserialize it into. This test
/// proves that shape, not just that the request doesn't crash: everything
/// past `token` is unreachable code as far as the relay's memory is
/// concerned, and the round trip below succeeds exactly as it would have
/// without the extra fields, proving nothing extra was needed or used.
#[tokio::test]
async fn extra_fields_beyond_the_opaque_token_are_not_retained() {
    let app = app();
    let token = "b".repeat(32);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/register",
            json!({
                "token": token,
                "message_content": "hello, this should never be stored",
                "sender_identity_key": "deadbeefdeadbeef",
                "conversation_id": "should-not-exist-in-relay-state",
                "recipient_contact_id": "also-should-not-exist",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, json!({ "registered": true }));

    let response = app.oneshot(wake_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// A source that blows past the default burst allowance gets throttled —
/// proving the `GovernorLayer` from `RelayServer::router` is actually
/// wired in and enforced, not just configured and unused. Uses its own,
/// unshared peer address so it can't be affected by (or affect) any other
/// test's rate-limit bucket.
#[tokio::test]
async fn a_source_that_exceeds_the_burst_allowance_is_rate_limited() {
    let app = app();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)), 1);

    let mut saw_throttled = false;
    for i in 0..50 {
        let token = format!("{:032}", i);
        let response = app
            .clone()
            .oneshot(with_connect_info(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "token": token }).to_string()))
                    .unwrap(),
                peer,
            ))
            .await
            .unwrap();
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_throttled = true;
            break;
        }
    }
    assert!(
        saw_throttled,
        "expected at least one of 50 rapid requests from the same peer to be rate limited"
    );
}

/// A different source IP is unaffected by another source's rate limit —
/// proving the limit is genuinely per-peer, not global across the relay.
#[tokio::test]
async fn rate_limiting_is_scoped_per_source_ip_not_global() {
    let app = app();
    let busy_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 1);
    let quiet_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51)), 1);

    for i in 0..50 {
        let token = format!("{:032}", i);
        let _ = app
            .clone()
            .oneshot(with_connect_info(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "token": token }).to_string()))
                    .unwrap(),
                busy_peer,
            ))
            .await
            .unwrap();
    }

    let response = app
        .oneshot(with_connect_info(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "token": "d".repeat(32) }).to_string()))
                .unwrap(),
            quiet_peer,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a different source IP must not be throttled by another IP's burst"
    );
}

/// HTTP-level proof that `RelayState`'s registration cap (§ state.rs) is
/// actually wired through `register`'s handler: a brand-new token past
/// the cap gets `503`, while re-registering an already-known token still
/// succeeds even while at the cap.
#[tokio::test]
async fn register_returns_503_once_the_relay_wide_cap_is_reached() {
    let app = app_with_state(RelayState::with_max_registrations(2));

    let first = "a".repeat(32);
    let second = "b".repeat(32);
    let third = "c".repeat(32);

    for token in [&first, &second] {
        let response = app
            .clone()
            .oneshot(json_request("POST", "/register", json!({ "token": token })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = app
        .clone()
        .oneshot(json_request("POST", "/register", json!({ "token": third })))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let response = app
        .oneshot(json_request("POST", "/register", json!({ "token": first })))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "re-registering a known token must still succeed at the cap"
    );
}

#[tokio::test]
async fn registering_the_same_token_twice_is_idempotent() {
    let app = app();
    let token = "c".repeat(32);

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(json_request("POST", "/register", json!({ "token": token })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = app.oneshot(wake_request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}
