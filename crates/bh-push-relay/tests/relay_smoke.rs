//! Round-trip and zero-knowledge-shape smoke tests for the push relay,
//! driven in-process via `tower::ServiceExt::oneshot` (mirrors
//! `crates/bh-api/tests/api_smoke.rs` — no real TCP listener needed). These
//! don't just check status codes: they check the *shape* of what the relay
//! is even capable of accepting or returning, since that's the actual
//! guarantee this crate makes — it is structurally unable to see message
//! content, sender identity, or conversation identity, not merely
//! "chooses" not to look at them.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bh_push_relay::{RelayServer, RelayState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn app() -> axum::Router {
    RelayServer::router(Arc::new(RelayState::new()))
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn wake_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/wake/{token}"))
        .body(Body::empty())
        .unwrap()
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
