//! End-to-end HTTP smoke tests over the daemon's whole route table, driven
//! in-process via `tower::ServiceExt::oneshot` (no real TCP listener, no
//! real OS keychain — this crate's other manual verification during
//! development already covers that combination; a mock keychain here keeps
//! this test deterministic in CI/headless environments where real
//! Keychain/Credential-Manager prompts can't be answered interactively).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bh_api::server::ApiServer;
use bh_api::state::ProfileSession;
use bh_api::AppState;
use bh_storage::keystore::DB_KEY_LABEL;
use bh_storage::profiles::ProfileManager;
use bh_storage::Database;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

fn use_mock_keychain() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    });
}

fn test_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bh-api-smoke-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn open_profile_session(manager: &ProfileManager, profile_id: &str, fresh: bool) -> ProfileSession {
    let keystore = manager.keystore_for(profile_id);
    let db_key: [u8; 32] = if fresh {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        keystore.store_key(DB_KEY_LABEL, &key).unwrap();
        key
    } else {
        keystore
            .load_key(DB_KEY_LABEL)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap()
    };
    let db = Database::open(manager.profile_db_path(profile_id), &db_key).unwrap();
    ProfileSession {
        profile_id: profile_id.to_string(),
        db,
        keystore,
        data_dir: manager.profile_data_dir(profile_id),
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).unwrap()
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn health_check_responds_ok() {
    use_mock_keychain();
    let dir = test_dir("health");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-health");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app.oneshot(get_request("/health")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Exercises the full multi-account lifecycle end to end: create an
/// identity on the default profile, spin up a second profile, switch to it
/// and confirm it's a genuinely empty/isolated database, then switch back
/// and confirm the original identity is still there untouched.
#[tokio::test]
async fn multi_account_profiles_are_isolated_and_switchable() {
    use_mock_keychain();
    let dir = test_dir("multi-account");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-multi-account");
    let default = manager.create_profile("Default", 0).unwrap();
    let default_id = default.id.clone();
    let session = open_profile_session(&manager, &default_id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    // Create an identity on the default profile.
    let response = app
        .clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Create a second profile — doesn't switch to it yet.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/profiles",
            json!({"display_name": "Work"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = body_json(response).await;
    let work_id = created["id"].as_str().unwrap().to_string();
    assert_ne!(work_id, default_id);

    // Still on the default profile — identity should still read initialized.
    let response = app.clone().oneshot(get_request("/identity")).await.unwrap();
    let identity = body_json(response).await;
    assert_eq!(identity["initialized"], json!(true));

    // Switch to the new profile.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/profiles/{work_id}/activate"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request("/profiles/active"))
        .await
        .unwrap();
    let active = body_json(response).await;
    assert_eq!(active["profile_id"], json!(work_id));

    // The new profile's database is a fresh, separate one: no identity yet.
    let response = app.clone().oneshot(get_request("/identity")).await.unwrap();
    let identity = body_json(response).await;
    assert_eq!(identity["initialized"], json!(false));

    // Switch back to the default profile — its identity is untouched.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/profiles/{default_id}/activate"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app.clone().oneshot(get_request("/identity")).await.unwrap();
    let identity = body_json(response).await;
    assert_eq!(identity["initialized"], json!(true));

    // Can't delete the currently-active profile.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/profiles/{default_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// A full messaging-feature round trip: contact -> conversation -> message
/// with a disappearing-messages timer -> reaction -> receipt -> encrypted
/// export -> import into a second (already-provisioned) profile.
#[tokio::test]
async fn messaging_features_round_trip_end_to_end() {
    use_mock_keychain();
    let dir = test_dir("messaging");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-messaging");
    let profile_a = manager.create_profile("A", 0).unwrap();
    let session_a = open_profile_session(&manager, &profile_a.id, true);
    let state_a = Arc::new(AppState::new(manager, session_a));
    let app_a = ApiServer::router(state_a);

    let fake_key = "22".repeat(64);
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": fake_key}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            "/conversations",
            json!({"contact_id": "c1"}),
        ))
        .await
        .unwrap();
    let conversation = body_json(response).await;
    let conversation_id = conversation["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/disappearing-timer"),
            json!({"timer_secs": 30}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/messages"),
            json!({"body": "hello bob"}),
        ))
        .await
        .unwrap();
    let sent = body_json(response).await;
    let message_id = sent["message"]["message_id"].as_str().unwrap().to_string();
    let sent_at = sent["message"]["sent_at"].as_i64().unwrap();
    let expires_at = sent["message"]["expires_at"].as_i64().unwrap();
    assert_eq!(expires_at, sent_at + 30);

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/messages/{message_id}/reactions"),
            json!({"emoji": "👍"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/messages/{message_id}/receipts"),
            json!({"contact_id": "c1", "status": "read"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/export"),
            json!({"passphrase": "correct horse battery staple"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let exported = body_json(response).await;
    let sealed = exported["sealed_base64"].as_str().unwrap().to_string();

    // A second, independent profile — simulating a different device that
    // already knows the same contact — imports the exported bundle.
    let manager_b = ProfileManager::new(&dir, "bh-api-smoke-messaging");
    let profile_b = manager_b.create_profile("B", 0).unwrap();
    let session_b = open_profile_session(&manager_b, &profile_b.id, true);
    let state_b = Arc::new(AppState::new(manager_b, session_b));
    let app_b = ApiServer::router(state_b);

    let response = app_b
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": fake_key}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app_b
        .clone()
        .oneshot(json_request(
            "POST",
            "/conversations/import",
            json!({"passphrase": "correct horse battery staple", "sealed_base64": sealed}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let imported = body_json(response).await;
    assert_eq!(imported["messages_imported"], json!(1));

    let response = app_b
        .clone()
        .oneshot(json_request(
            "POST",
            "/conversations/import",
            json!({"passphrase": "wrong passphrase", "sealed_base64": sealed}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Safety-number verification and expiring invites, also end to end.
#[tokio::test]
async fn safety_number_and_invites_round_trip() {
    use_mock_keychain();
    let dir = test_dir("safety-and-invites");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-safety-invites");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();

    let fake_key = "55".repeat(64);
    app.clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": fake_key}),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(get_request("/contacts/c1/safety-number"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let safety_number = body_json(response).await;
    assert_eq!(safety_number["digits"].as_str().unwrap().len(), 60);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts/c1/verify",
            json!({"verified": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A single-use invite: the first consume succeeds, the second is
    // refused because the use limit was already reached.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/invites",
            json!({"display_name": "me", "max_uses": 1}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let invite = body_json(response).await;
    let token = invite["token"].as_str().unwrap().to_string();
    let link = invite["link"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/invites/decode",
            json!({"link": link}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let decoded = body_json(response).await;
    assert_eq!(decoded["display_name"], json!("me"));
    assert_eq!(decoded["locally_expired"], json!(false));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/invites/{token}/consume"),
            json!({}),
        ))
        .await
        .unwrap();
    let validity = body_json(response).await;
    assert_eq!(validity["validity"], json!("valid"));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/invites/{token}/consume"),
            json!({}),
        ))
        .await
        .unwrap();
    let validity = body_json(response).await;
    assert_eq!(validity["validity"], json!("use_limit_reached"));
}
