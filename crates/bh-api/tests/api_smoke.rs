//! End-to-end HTTP smoke tests over the daemon's whole route table, driven
//! in-process via `tower::ServiceExt::oneshot` (no real TCP listener, no
//! real OS keychain — this crate's other manual verification during
//! development already covers that combination; a mock keychain here keeps
//! this test deterministic in CI/headless environments where real
//! Keychain/Credential-Manager prompts can't be answered interactively).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bh_api::device_sync::DeviceSyncRegistry;
use bh_api::groups::GroupRegistry;
use bh_api::presence::PresenceRegistry;
use bh_api::server::ApiServer;
use bh_api::state::ProfileSession;
use bh_api::AppState;
use bh_crypto::mls_storage::PersistentMlsProvider;
use bh_storage::keystore::{DB_KEY_LABEL, MLS_DB_KEY_LABEL, PAYMENTS_DB_KEY_LABEL};
use bh_storage::models::{Contact, Message};
use bh_storage::profiles::ProfileManager;
use bh_storage::{Database, PaymentsDatabase};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Fixed value every test request authenticates with — `AppState::
/// with_expiry_sweep_interval` reads `BLACKHOLE_API_TOKEN` if set (rather
/// than generating a random token per `AppState`), so every `AppState`
/// this test binary constructs ends up using this same known value,
/// letting `json_request`/`get_request`/`signed_paid_request` attach a
/// fixed `Authorization` header instead of reading each `AppState`'s
/// generated token back individually.
const TEST_API_TOKEN: &str = "test-api-token-not-a-real-secret";

fn use_mock_keychain() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        // SAFETY: set once, before any test spawns threads that read env
        // vars concurrently (`Once` guarantees this runs before any test
        // body executes), and never removed/changed afterward.
        unsafe { std::env::set_var("BLACKHOLE_API_TOKEN", TEST_API_TOKEN) };
    });
}

fn test_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bh-api-smoke-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn load_or_create_key(
    keystore: &bh_storage::keystore::Keystore,
    label: &str,
    fresh: bool,
) -> [u8; 32] {
    if fresh {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).unwrap();
        keystore.store_key(label, &key).unwrap();
        key
    } else {
        keystore
            .load_key(label)
            .unwrap()
            .unwrap()
            .try_into()
            .unwrap()
    }
}

fn open_profile_session(manager: &ProfileManager, profile_id: &str, fresh: bool) -> ProfileSession {
    let keystore = manager.keystore_for(profile_id);
    let db_key = load_or_create_key(&keystore, DB_KEY_LABEL, fresh);
    let db = Database::open(manager.profile_db_path(profile_id), &db_key).unwrap();
    let payments_db_key = load_or_create_key(&keystore, PAYMENTS_DB_KEY_LABEL, fresh);
    let payments_db =
        PaymentsDatabase::open(manager.payments_db_path(profile_id), &payments_db_key).unwrap();
    bh_api::cosmetics::seed_default_catalog(&payments_db).unwrap();
    let mls_db_key = load_or_create_key(&keystore, MLS_DB_KEY_LABEL, fresh);
    let mls_db_path = manager.mls_db_path(profile_id);
    // Opened once here just to fail loudly on a bad key, same as `db`/
    // `payments_db` above — `ProfileSession` itself only keeps path+key.
    PersistentMlsProvider::open(&mls_db_path, &mls_db_key).unwrap();
    ProfileSession {
        profile_id: profile_id.to_string(),
        db,
        payments_db,
        keystore,
        data_dir: manager.profile_data_dir(profile_id),
        mls_db_path,
        mls_db_key,
        groups: Arc::new(GroupRegistry::default()),
        device_sync: Arc::new(DeviceSyncRegistry::default()),
        presence: Arc::new(PresenceRegistry::default()),
    }
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(&bytes).unwrap()
}

fn auth_header() -> String {
    format!("Bearer {TEST_API_TOKEN}")
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", auth_header())
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", auth_header())
        .body(Body::empty())
        .unwrap()
}

/// A `POST` carrying a valid `x-blackhole-webhook-signature` header for
/// `purchase_id`, as `bh_api::cosmetics::mark_purchase_paid` now requires.
fn signed_paid_request(uri: &str, secret: &[u8; 32], purchase_id: &str) -> Request<Body> {
    let signature = bh_crypto::webhook::sign(secret, purchase_id.as_bytes());
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-blackhole-webhook-signature", hex::encode(signature))
        .header("authorization", auth_header())
        .body(Body::from("{}"))
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

/// A request with no `Authorization` header at all — not even a request
/// carrying the *wrong* token, just none — must be rejected. This is the
/// actual proof `require_bearer_token` (`server.rs`) is wired in and
/// enforced on the router, not merely present in the source: every other
/// test in this file goes through `get_request`/`json_request`, which
/// always attach the correct header, so without a test like this the
/// whole suite would pass identically whether the middleware layer was
/// there or not.
#[tokio::test]
async fn requests_without_a_bearer_token_are_rejected() {
    use_mock_keychain();
    let dir = test_dir("no-auth");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-no-auth");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .header("authorization", "Bearer wrong-token-entirely")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

fn expired_message(message_id: &str, conversation_id: &str) -> Message {
    Message {
        message_id: message_id.into(),
        conversation_id: conversation_id.into(),
        sender_contact_id: None,
        body: Some("gone soon".into()),
        sent_at: 0,
        received_at: None,
        // Real epoch seconds are always well past 1 — this is
        // unconditionally already-expired against the sweeper's real
        // wall-clock `now`, no fake clock needed at this level (that's
        // already covered by `bh_storage::expiry`'s own unit test).
        expires_at: Some(1),
        deleted_at: None,
        reply_to_message_id: None,
        edited_at: None,
    }
}

/// The expiry sweeper (`AppState::restart_expiry_sweeper`) used to be
/// spawned once against whichever profile was active at daemon startup and
/// never moved — switching the active profile at runtime left it purging
/// the *old* profile forever (THREAT_MODEL.md's former "known limitation"
/// on the sweeper). Confirms it now follows: an expired message in the
/// starting profile gets purged, and after switching to a second profile,
/// an expired message *there* gets purged too — not just left to next
/// restart.
#[tokio::test]
async fn expiry_sweeper_follows_profile_switches() {
    use_mock_keychain();
    let dir = test_dir("sweeper-follows");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-sweeper-follows");
    let default = manager.create_profile("Default", 0).unwrap();
    let default_id = default.id.clone();
    let default_session = open_profile_session(&manager, &default_id, true);
    let default_db = default_session.db.clone();

    let state = Arc::new(AppState::with_expiry_sweep_interval(
        manager,
        default_session,
        Duration::from_millis(20),
    ));
    let app = ApiServer::router(state.clone());

    default_db
        .upsert_contact(&Contact {
            contact_id: "c1".into(),
            identity_public_key: vec![1],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
    default_db
        .create_direct_conversation("conv-default", "c1", 0)
        .unwrap();
    default_db
        .insert_message(&expired_message("m-default", "conv-default"))
        .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        default_db
            .list_messages("conv-default", 10)
            .unwrap()
            .is_empty(),
        "sweeper should have purged the expired message on the starting profile"
    );

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
    let work_id = body_json(response).await["id"]
        .as_str()
        .unwrap()
        .to_string();

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

    let work_db = state.db();
    work_db
        .upsert_contact(&Contact {
            contact_id: "c2".into(),
            identity_public_key: vec![2],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
    work_db
        .create_direct_conversation("conv-work", "c2", 0)
        .unwrap();
    work_db
        .insert_message(&expired_message("m-work", "conv-work"))
        .unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        work_db.list_messages("conv-work", 10).unwrap().is_empty(),
        "sweeper should have followed the switch and purged the expired message on the new profile too"
    );
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

    // In-chat crypto payment request (SPEC.md §15): create it, confirm the
    // address-only QR/deep-link view, then mark it paid — a purely local
    // flag, never an on-chain check (see crates/bh-api/src/payment_requests.rs).
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/payment-requests"),
            json!({
                "asset": "ETH",
                "address": "0x000102030405060708090a0b0c0d0e0f10111213",
                "amount": "0.05",
                "memo": "for dinner",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payment_sent = body_json(response).await;
    let payment_message_id = payment_sent["message"]["message_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(payment_sent["payment_request"]["asset"], json!("ETH"));
    assert_eq!(
        payment_sent["payment_request"]["privacy_label"],
        json!("public on-chain")
    );
    assert_eq!(payment_sent["payment_request"]["paid_at"], Value::Null);
    assert!(payment_sent["payment_request"]["qr_svg"]
        .as_str()
        .unwrap()
        .contains("<svg"));

    // Rejects a structurally invalid address before it ever becomes a
    // message — never even inserted.
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/payment-requests"),
            json!({"asset": "ETH", "address": "not-an-address"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Marking paid without the out-of-band confirmation flag is refused
    // outright — the server itself won't flip the flag on a bare/false
    // request, not just the UI (THREAT_MODEL.md §3.11/§4 item 13). No DB
    // write happens: a follow-up GET still shows `paid_at: null`.
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/messages/{payment_message_id}/payment-request/paid"),
            json!({"confirmed_out_of_band": false}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);

    let response = app_a
        .clone()
        .oneshot(get_request(&format!(
            "/messages/{payment_message_id}/payment-request"
        )))
        .await
        .unwrap();
    let unpaid_payment_request = body_json(response).await;
    assert_eq!(unpaid_payment_request["paid_at"], Value::Null);

    // A request body missing the field entirely is rejected before the
    // handler ever runs (axum's `Json` extractor bounces malformed/
    // incomplete bodies).
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/messages/{payment_message_id}/payment-request/paid"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = app_a
        .clone()
        .oneshot(get_request(&format!(
            "/messages/{payment_message_id}/payment-request"
        )))
        .await
        .unwrap();
    let still_unpaid_payment_request = body_json(response).await;
    assert_eq!(still_unpaid_payment_request["paid_at"], Value::Null);

    // With explicit confirmation, the mark actually goes through.
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/messages/{payment_message_id}/payment-request/paid"),
            json!({"confirmed_out_of_band": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app_a
        .clone()
        .oneshot(get_request(&format!(
            "/messages/{payment_message_id}/payment-request"
        )))
        .await
        .unwrap();
    let payment_request = body_json(response).await;
    assert!(payment_request["paid_at"].is_number());

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
    assert_eq!(imported["messages_imported"], json!(2));

    // The payment request rode along in the export bundle, including the
    // fact that it had already been marked paid on profile A.
    let response = app_b
        .clone()
        .oneshot(get_request(&format!(
            "/messages/{payment_message_id}/payment-request"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let imported_payment_request = body_json(response).await;
    assert_eq!(imported_payment_request["asset"], json!("ETH"));
    assert!(imported_payment_request["paid_at"].is_number());

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

/// Full 4-step device-linking simulation (see `device_link.rs` module
/// doc): begin -> scan -> accept -> finish, ending with a second, distinct
/// `devices` row, then revocation.
#[tokio::test]
async fn device_linking_round_trip_registers_a_second_device() {
    use_mock_keychain();
    let dir = test_dir("device-linking");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-device-linking");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(json_request("POST", "/devices/link/begin", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let begun = body_json(response).await;
    let session_id = begun["session_id"].as_str().unwrap().to_string();
    let link = begun["link"].as_str().unwrap().to_string();
    assert!(begun["qr_svg"].as_str().unwrap().contains("<svg"));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/devices/link/scan",
            json!({"link": link}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let scanned = body_json(response).await;
    let new_device_session_id = scanned["new_device_session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let provisioning_request_b64 = scanned["provisioning_request_b64"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/devices/link/{session_id}/accept"),
            json!({
                "provisioning_request_b64": provisioning_request_b64,
                "device_name": "New Device",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let accepted = body_json(response).await;
    let response_ciphertext_b64 = accepted["response_ciphertext_b64"]
        .as_str()
        .unwrap()
        .to_string();
    let device_id = accepted["device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(accepted["device"]["name"], json!("New Device"));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/devices/link/{new_device_session_id}/finish"),
            json!({"response_ciphertext_b64": response_ciphertext_b64}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let finished = body_json(response).await;
    assert_eq!(finished["confirmed"], json!(true));
    assert_eq!(
        finished["device_signing_key_hex"].as_str().unwrap(),
        device_id
    );

    let response = app.clone().oneshot(get_request("/devices")).await.unwrap();
    let devices = body_json(response).await;
    let devices = devices.as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["device_id"], json!(device_id));
    assert!(devices[0]["revoked_at"].is_null());

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/devices/{device_id}/revoke"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app.clone().oneshot(get_request("/devices")).await.unwrap();
    let devices = body_json(response).await;
    assert!(devices[0]["revoked_at"].is_number());
}

/// TOTP enrollment (start -> confirm -> verify), wrong-code rejection, and
/// removal. Passkey registration can't be exercised headlessly (no real
/// authenticator — same limitation `bh-crypto`'s own passkey test already
/// accepts), so this only confirms `passkey/register/start` returns a
/// well-formed challenge.
#[tokio::test]
async fn local_auth_totp_enrollment_and_verification() {
    use_mock_keychain();
    let dir = test_dir("local-auth");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-local-auth");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app
        .clone()
        .oneshot(get_request("/local-auth/status"))
        .await
        .unwrap();
    let status = body_json(response).await;
    assert_eq!(status["totp_enrolled"], json!(false));
    assert_eq!(status["passkey_enrolled"], json!(false));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/passkey/register/start",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let started = body_json(response).await;
    assert!(!started["ceremony_id"].as_str().unwrap().is_empty());
    assert_eq!(
        started["challenge_json"]["publicKey"]["rp"]["id"],
        json!("localhost")
    );

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/totp/enroll/start",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let enroll = body_json(response).await;
    let ceremony_id = enroll["ceremony_id"].as_str().unwrap().to_string();
    assert!(!enroll["base32_secret"].as_str().unwrap().is_empty());
    assert!(enroll["provisioning_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));
    assert!(enroll["qr_svg"].as_str().unwrap().contains("<svg"));

    // A wrong code doesn't confirm enrollment.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/totp/enroll/confirm",
            json!({"ceremony_id": ceremony_id, "code": "000000"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Re-start enrollment (the failed confirm above consumed the ceremony)
    // and confirm with the real code this time.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/totp/enroll/start",
            json!({}),
        ))
        .await
        .unwrap();
    let enroll = body_json(response).await;
    let ceremony_id = enroll["ceremony_id"].as_str().unwrap().to_string();
    let base32_secret = enroll["base32_secret"].as_str().unwrap().to_string();
    let secret =
        bh_crypto::auth::TotpSecret::from_base32(&base32_secret, "local", "Blackhole").unwrap();
    let code = secret.generate_current().unwrap();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/totp/enroll/confirm",
            json!({"ceremony_id": ceremony_id, "code": code}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request("/local-auth/status"))
        .await
        .unwrap();
    let status = body_json(response).await;
    assert_eq!(status["totp_enrolled"], json!(true));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/totp/verify",
            json!({"code": "000000"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/local-auth/totp/verify",
            json!({"code": code}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/local-auth/totp")
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request("/local-auth/status"))
        .await
        .unwrap();
    let status = body_json(response).await;
    assert_eq!(status["totp_enrolled"], json!(false));
}

/// Creates a group with two contacts, proves the real MLS crypto path
/// round-trips for both (`mls-self-test`), removes one member, confirms
/// only the remainder still decrypts, then sends/lists a message through
/// the *existing* conversations route on the group's conversation_id to
/// prove group creation didn't regress normal messaging.
#[tokio::test]
async fn groups_round_trip_create_add_remove_and_self_test() {
    use_mock_keychain();
    let dir = test_dir("groups");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-groups");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();

    for contact_id in ["c1", "c2"] {
        let response = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/contacts",
                json!({"contact_id": contact_id, "identity_public_key": "22".repeat(64)}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/groups",
            json!({"name": "Friends", "member_contact_ids": ["c1", "c2"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = body_json(response).await;
    let group_id = created["group"]["group_id"].as_str().unwrap().to_string();
    let conversation_id = created["conversation"]["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(created["members"].as_array().unwrap().len(), 2);

    let response = app
        .clone()
        .oneshot(get_request(&format!("/groups/{group_id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let detail = body_json(response).await;
    assert_eq!(detail["members"].as_array().unwrap().len(), 2);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/groups/{group_id}/mls-self-test"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response).await;
    assert_eq!(result["roundtrip_ok"], json!(true));
    let mut confirmed: Vec<String> = result["confirmed_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    confirmed.sort();
    assert_eq!(confirmed, vec!["c1".to_string(), "c2".to_string()]);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/groups/{group_id}/members/c1"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/groups/{group_id}/mls-self-test"),
            json!({}),
        ))
        .await
        .unwrap();
    let result = body_json(response).await;
    assert_eq!(result["roundtrip_ok"], json!(true));
    assert_eq!(result["confirmed_members"], json!(["c2"]));

    // Normal messaging on the group's conversation still works untouched.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/messages"),
            json!({"body": "hello group"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/messages"
        )))
        .await
        .unwrap();
    let messages = body_json(response).await;
    assert_eq!(messages.as_array().unwrap().len(), 1);
    assert_eq!(messages[0]["body"], json!("hello group"));
}

/// The restart story THREAT_MODEL.md §3.2 used to flag as an open gap:
/// create a group and add a member via the router, then build a **second,
/// independent** `AppState`/router pointed at the same profile's on-disk
/// data dir/keys (a fresh `GroupRegistry` included — no in-memory
/// `Group`/`MlsMember` handles carried over, simulating a real daemon
/// restart, not just a profile switch within one process) and confirm
/// `add_member`/`mls_self_test` no longer 410 and actually perform real
/// MLS operations against the reloaded group/member.
#[tokio::test]
async fn groups_survive_a_daemon_restart_via_the_http_api() {
    use_mock_keychain();
    let dir = test_dir("groups-restart");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-groups-restart");
    let profile = manager.create_profile("A", 0).unwrap();
    let profile_id = profile.id.clone();

    // Captured so the "restart" below can re-seed a second `ProfileManager`
    // instance's mock keystore with the same keys (mirrors
    // `file_attachment_upload_list_and_download_round_trip`'s identical
    // pattern/comment: a real OS keychain wouldn't need this, but the mock
    // backend stores credentials per `Entry` instance, not globally).
    let mut db_key = [0u8; 32];
    getrandom::fill(&mut db_key).unwrap();
    let mut payments_db_key = [0u8; 32];
    getrandom::fill(&mut payments_db_key).unwrap();
    let mut mls_db_key = [0u8; 32];
    getrandom::fill(&mut mls_db_key).unwrap();
    let keystore = manager.keystore_for(&profile_id);
    keystore.store_key(DB_KEY_LABEL, &db_key).unwrap();
    keystore
        .store_key(PAYMENTS_DB_KEY_LABEL, &payments_db_key)
        .unwrap();
    keystore.store_key(MLS_DB_KEY_LABEL, &mls_db_key).unwrap();
    let db = Database::open(manager.profile_db_path(&profile_id), &db_key).unwrap();
    let payments_db =
        PaymentsDatabase::open(manager.payments_db_path(&profile_id), &payments_db_key).unwrap();
    bh_api::cosmetics::seed_default_catalog(&payments_db).unwrap();
    let mls_db_path = manager.mls_db_path(&profile_id);
    PersistentMlsProvider::open(&mls_db_path, &mls_db_key).unwrap();
    let session = ProfileSession {
        profile_id: profile_id.clone(),
        db,
        payments_db,
        keystore,
        data_dir: manager.profile_data_dir(&profile_id),
        mls_db_path,
        mls_db_key,
        groups: Arc::new(GroupRegistry::default()),
        device_sync: Arc::new(DeviceSyncRegistry::default()),
        presence: Arc::new(PresenceRegistry::default()),
    };
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": "22".repeat(64)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/groups",
            json!({"name": "Friends", "member_contact_ids": ["c1"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = body_json(response).await;
    let group_id = created["group"]["group_id"].as_str().unwrap().to_string();

    // Simulate a daemon restart: a brand new `AppState`/router — including
    // a fresh `GroupRegistry`, so nothing from the first `app`'s in-memory
    // `own_members`/`live_groups` carries over — pointed at the same
    // on-disk profile directory and keys.
    let manager2 = ProfileManager::new(&dir, "bh-api-smoke-groups-restart");
    let keystore2 = manager2.keystore_for(&profile_id);
    keystore2.store_key(DB_KEY_LABEL, &db_key).unwrap();
    keystore2
        .store_key(PAYMENTS_DB_KEY_LABEL, &payments_db_key)
        .unwrap();
    keystore2.store_key(MLS_DB_KEY_LABEL, &mls_db_key).unwrap();
    let db2 = Database::open(manager2.profile_db_path(&profile_id), &db_key).unwrap();
    let payments_db2 =
        PaymentsDatabase::open(manager2.payments_db_path(&profile_id), &payments_db_key).unwrap();
    let mls_db_path2 = manager2.mls_db_path(&profile_id);
    let session2 = ProfileSession {
        profile_id: profile_id.clone(),
        db: db2,
        payments_db: payments_db2,
        keystore: keystore2,
        data_dir: manager2.profile_data_dir(&profile_id),
        mls_db_path: mls_db_path2,
        mls_db_key,
        groups: Arc::new(GroupRegistry::default()),
        device_sync: Arc::new(DeviceSyncRegistry::default()),
        presence: Arc::new(PresenceRegistry::default()),
    };
    let state2 = Arc::new(AppState::new(manager2, session2));
    let app2 = ApiServer::router(state2);

    // Before this fix, this would 410 GONE: the fresh `GroupRegistry` has
    // no in-memory entry for `group_id`, and there was no way to
    // reconstruct one from storage. Adding a *new* contact exercises a
    // real MLS commit (`Group::add_member`) against the reloaded group and
    // own member — if the reload had produced inconsistent/stale crypto
    // state, this would fail with a crypto error, not silently succeed.
    let response = app2
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c2", "identity_public_key": "33".repeat(64)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app2
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/groups/{group_id}/members"),
            json!({"contact_id": "c2"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Also no longer 410, and functionally correct: encrypts via the
    // reloaded own member/group and decrypts via c2's shadow member (only
    // one that exists in *this* registry — c1's shadow-join state was
    // process-lifetime scaffolding in the first `app` and deliberately
    // does not survive the restart, same as it wouldn't survive a real
    // daemon's).
    let response = app2
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/groups/{group_id}/mls-self-test"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = body_json(response).await;
    assert_eq!(result["roundtrip_ok"], json!(true));
    assert_eq!(result["confirmed_members"], json!(["c2"]));

    // And remove_member: leaf-index lookup + another real MLS commit
    // against the (now in-memory-cached, but originally reloaded) group.
    let response = app2
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/groups/{group_id}/members/c2"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Upload -> list -> download byte-for-byte, then confirms the attachment
/// (unlike device-link/group live state) survives a "restart" — a second
/// `AppState` opened against the same profile directory.
#[tokio::test]
async fn file_attachment_upload_list_and_download_round_trip() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    use_mock_keychain();
    let dir = test_dir("attachments");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-attachments");
    let profile = manager.create_profile("A", 0).unwrap();
    let profile_id = profile.id.clone();

    // Captured so the "restart" below can re-seed a second `ProfileManager`
    // instance's keystore with the same key: `keyring`'s mock backend
    // (unlike a real OS keychain) stores credentials per `Entry` instance
    // rather than globally by (service, user), so a genuinely
    // independent `ProfileManager` wouldn't otherwise see it — see
    // `bh_storage::profiles::ProfileManager::keystore_for`'s doc comment.
    let mut db_key = [0u8; 32];
    getrandom::fill(&mut db_key).unwrap();
    let mut payments_db_key = [0u8; 32];
    getrandom::fill(&mut payments_db_key).unwrap();
    let mut mls_db_key = [0u8; 32];
    getrandom::fill(&mut mls_db_key).unwrap();
    let keystore = manager.keystore_for(&profile_id);
    keystore.store_key(DB_KEY_LABEL, &db_key).unwrap();
    keystore
        .store_key(PAYMENTS_DB_KEY_LABEL, &payments_db_key)
        .unwrap();
    keystore.store_key(MLS_DB_KEY_LABEL, &mls_db_key).unwrap();
    let db = Database::open(manager.profile_db_path(&profile_id), &db_key).unwrap();
    let payments_db =
        PaymentsDatabase::open(manager.payments_db_path(&profile_id), &payments_db_key).unwrap();
    let mls_db_path = manager.mls_db_path(&profile_id);
    PersistentMlsProvider::open(&mls_db_path, &mls_db_key).unwrap();
    let session = ProfileSession {
        profile_id: profile_id.clone(),
        db,
        payments_db,
        keystore,
        data_dir: manager.profile_data_dir(&profile_id),
        mls_db_path,
        mls_db_key,
        groups: Arc::new(GroupRegistry::default()),
        device_sync: Arc::new(DeviceSyncRegistry::default()),
        presence: Arc::new(PresenceRegistry::default()),
    };
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": "22".repeat(64)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
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

    let content = b"hello attachment world";
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/attachments"),
            json!({
                "file_name": "hello.txt",
                "mime_type": "text/plain",
                "data_base64": BASE64.encode(content),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let uploaded = body_json(response).await;
    assert!(uploaded["file"].get("file_key").is_none());
    let content_hash = uploaded["file"]["content_hash"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(uploaded["file"]["file_name"], json!("hello.txt"));

    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/attachments"
        )))
        .await
        .unwrap();
    let listed = body_json(response).await;
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(listed[0].get("file_key").is_none());

    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/attachments/{content_hash}/download"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = body_json(response).await;
    let data = BASE64
        .decode(downloaded["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(data, content);

    // Simulate a restart: a fresh AppState against the same on-disk
    // profile (re-seeding the mock keystore per the comment above — a real
    // OS keychain wouldn't need this). Unlike device-link/group live
    // ceremony state, attachment metadata + chunk files are DB/disk-backed
    // and survive this.
    let manager2 = ProfileManager::new(&dir, "bh-api-smoke-attachments");
    let keystore2 = manager2.keystore_for(&profile_id);
    keystore2.store_key(DB_KEY_LABEL, &db_key).unwrap();
    keystore2
        .store_key(PAYMENTS_DB_KEY_LABEL, &payments_db_key)
        .unwrap();
    keystore2.store_key(MLS_DB_KEY_LABEL, &mls_db_key).unwrap();
    let db2 = Database::open(manager2.profile_db_path(&profile_id), &db_key).unwrap();
    let payments_db2 =
        PaymentsDatabase::open(manager2.payments_db_path(&profile_id), &payments_db_key).unwrap();
    let mls_db_path2 = manager2.mls_db_path(&profile_id);
    let session2 = ProfileSession {
        profile_id: profile_id.clone(),
        db: db2,
        payments_db: payments_db2,
        keystore: keystore2,
        data_dir: manager2.profile_data_dir(&profile_id),
        mls_db_path: mls_db_path2,
        mls_db_key,
        groups: Arc::new(GroupRegistry::default()),
        device_sync: Arc::new(DeviceSyncRegistry::default()),
        presence: Arc::new(PresenceRegistry::default()),
    };
    let state2 = Arc::new(AppState::new(manager2, session2));
    let app2 = ApiServer::router(state2);

    let response = app2
        .clone()
        .oneshot(get_request(&format!(
            "/attachments/{content_hash}/download"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = body_json(response).await;
    let data = BASE64
        .decode(downloaded["data_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(data, content);

    let response = app2
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/attachments/{content_hash}"))
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app2
        .clone()
        .oneshot(get_request(&format!(
            "/attachments/{content_hash}/download"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Closes THREAT_MODEL.md's "attachments aren't swept by the
/// disappearing-message timer" gap: uploads an attachment into a
/// conversation with a short disappearing-message timer, waits past expiry
/// plus one sweep interval, and confirms the on-disk chunk directory is
/// actually gone — not just the DB row (that half was already covered by
/// `deleting_a_message_scrubs_its_payment_request_and_unshared_attachment`
/// in `bh-storage`'s own test suite).
#[tokio::test]
async fn expired_attachment_is_swept_from_disk() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    use_mock_keychain();
    let dir = test_dir("expiring-attachments");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-expiring-attachments");
    let profile = manager.create_profile("A", 0).unwrap();
    let profile_id = profile.id.clone();
    let session = open_profile_session(&manager, &profile_id, true);
    let data_dir = session.data_dir.clone();
    let state = Arc::new(AppState::with_expiry_sweep_interval(
        manager,
        session,
        Duration::from_millis(20),
    ));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": "22".repeat(64)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
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

    // A 0-second disappearing timer: `expires_at` becomes exactly `sent_at`,
    // so the message is already eligible for the very next sweep tick —
    // avoids the flakiness of racing a real wall-clock second boundary.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/disappearing-timer"),
            json!({"timer_secs": 0}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content = b"this attachment should self destruct";
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/attachments"),
            json!({
                "file_name": "secret.txt",
                "mime_type": "text/plain",
                "data_base64": BASE64.encode(content),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let uploaded = body_json(response).await;
    let content_hash = uploaded["file"]["content_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let chunk_dir = data_dir.join("files").join(&content_hash);
    assert!(
        chunk_dir.is_dir(),
        "chunk dir should exist right after upload"
    );

    // The message is already expired; just wait a couple of 20ms sweep
    // intervals for the sweeper to actually catch up to it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/attachments"
        )))
        .await
        .unwrap();
    let listed = body_json(response).await;
    assert!(
        listed.as_array().unwrap().is_empty(),
        "expired attachment's metadata row should be gone"
    );
    assert!(
        !chunk_dir.exists(),
        "expired attachment's chunk dir should have been swept from disk, found: {chunk_dir:?}"
    );
}

/// Exercises the cosmetic store end to end: browse the (seeded) catalog,
/// record a purchase against a server-created invoice placeholder, confirm
/// it as BTCPay's webhook eventually would, and equip what was granted —
/// checking along
/// the way that equipping something never-purchased is rejected and that
/// re-confirming the same purchase doesn't grant a duplicate inventory row
/// (SPEC.md §12 isolation: nothing here ever queries `db` and `payments_db`
/// in the same call, only the opaque entitlement token crosses).
#[tokio::test]
async fn cosmetics_catalog_purchase_and_equip_round_trip() {
    use_mock_keychain();
    let dir = test_dir("cosmetics");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-cosmetics");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let webhook_secret = bh_api::cosmetics::load_or_create_webhook_secret(&state).unwrap();
    let app = ApiServer::router(state);

    let response = app
        .clone()
        .oneshot(get_request("/cosmetics/catalog"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let catalog = body_json(response).await;
    let catalog = catalog.as_array().unwrap();
    assert!(catalog.len() >= 3);
    let banner_id = catalog
        .iter()
        .find(|item| item["kind"] == json!("banner"))
        .unwrap()["item_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Equipping before owning anything is rejected.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/cosmetics/equip",
            json!({"kind": "banner", "item_id": banner_id}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/cosmetics/purchases",
            json!({"item_id": banner_id, "invoice_id": "client-supplied-id"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/cosmetics/purchases",
            json!({"item_id": banner_id}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let purchase = body_json(response).await;
    assert_eq!(purchase["status"], json!("pending"));
    assert!(purchase["invoice_id"]
        .as_str()
        .unwrap()
        .starts_with("local-btcpay-placeholder-"));
    assert_eq!(purchase["checkout_url"], Value::Null);
    assert_eq!(purchase["provider"], json!("local_placeholder"));
    assert_eq!(purchase["provider_status"], json!("btcpay_not_configured"));
    assert!(purchase["expires_at"].as_i64().unwrap() > purchase["created_at"].as_i64().unwrap());
    let purchase_id = purchase["purchase_id"].as_str().unwrap().to_string();

    // No signature, or the wrong one, is rejected — localhost access alone
    // is no longer enough to grant a cosmetic for free.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/cosmetics/purchases/{purchase_id}/paid"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let wrong_secret = [0xAAu8; 32];
    let response = app
        .clone()
        .oneshot(signed_paid_request(
            &format!("/cosmetics/purchases/{purchase_id}/paid"),
            &wrong_secret,
            &purchase_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(signed_paid_request(
            &format!("/cosmetics/purchases/{purchase_id}/paid"),
            &webhook_secret,
            &purchase_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let confirmed = body_json(response).await;
    let entitlement_token = confirmed["entitlement_token"].as_str().unwrap().to_string();

    // Replaying the "webhook" is safe and returns the same token rather
    // than minting (or granting) a second time.
    let response = app
        .clone()
        .oneshot(signed_paid_request(
            &format!("/cosmetics/purchases/{purchase_id}/paid"),
            &webhook_secret,
            &purchase_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let replayed = body_json(response).await;
    assert_eq!(replayed["entitlement_token"], json!(entitlement_token));

    let response = app
        .clone()
        .oneshot(get_request("/cosmetics/inventory"))
        .await
        .unwrap();
    let inventory = body_json(response).await;
    let inventory = inventory.as_array().unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0]["item_id"], json!(banner_id));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/cosmetics/equip",
            json!({"kind": "banner", "item_id": banner_id}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request("/cosmetics/equipped"))
        .await
        .unwrap();
    let equipped = body_json(response).await;
    let equipped = equipped.as_array().unwrap();
    assert_eq!(equipped.len(), 1);
    assert_eq!(equipped[0]["item_id"], json!(banner_id));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/cosmetics/equipped/banner")
                .header("authorization", auth_header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(get_request("/cosmetics/equipped"))
        .await
        .unwrap();
    let equipped = body_json(response).await;
    assert!(equipped.as_array().unwrap().is_empty());
}

/// The PIN layer in front of the SQLCipher database key
/// (THREAT_MODEL.md §3.7): set a PIN, confirm the wrong PIN can't clear
/// it, confirm the right PIN can, and confirm double-setting/double-
/// clearing are rejected rather than silently accepted.
#[tokio::test]
async fn db_pin_set_clear_round_trip() {
    use_mock_keychain();
    let dir = test_dir("db-pin");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-db-pin");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app
        .clone()
        .oneshot(get_request("/security/db-pin"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, json!({"pin_set": false}));

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/security/db-pin",
            json!({"pin": "4242"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request("/security/db-pin"))
        .await
        .unwrap();
    assert_eq!(body_json(response).await, json!({"pin_set": true}));

    // Setting again while already set is rejected, not silently accepted.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/security/db-pin",
            json!({"pin": "9999"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Wrong PIN can't clear it.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/security/db-pin/clear",
            json!({"pin": "0000"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(get_request("/security/db-pin"))
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        json!({"pin_set": true}),
        "a failed clear must not have disturbed the stored PIN state"
    );

    // Right PIN clears it.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/security/db-pin/clear",
            json!({"pin": "4242"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(get_request("/security/db-pin"))
        .await
        .unwrap();
    assert_eq!(body_json(response).await, json!({"pin_set": false}));

    // Clearing again while already unprotected is rejected.
    let response = app
        .oneshot(json_request(
            "POST",
            "/security/db-pin/clear",
            json!({"pin": "4242"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// A PIN set on one profile must be required to switch back into it —
/// `activate_profile` has to be PIN-aware (`bh_storage::db_key_lock`), not
/// just assume every stored keystore entry is a raw 32-byte key. Missing
/// PIN and wrong PIN both come back `401`, not a `500` from a failed
/// `try_into::<[u8; 32]>()` on a sealed blob.
#[tokio::test]
async fn switching_into_a_pin_protected_profile_requires_the_pin() {
    use_mock_keychain();
    let dir = test_dir("pin-protected-switch");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-pin-switch");
    let default = manager.create_profile("Default", 0).unwrap();
    let default_id = default.id.clone();
    let session = open_profile_session(&manager, &default_id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state.clone());

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/profiles",
            json!({"display_name": "Vault"}),
        ))
        .await
        .unwrap();
    let vault_id = body_json(response).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Switch to it once (unprotected so far) to provision its identity,
    // set a PIN on it, then switch back to Default.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/profiles/{vault_id}/activate"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/security/db-pin",
            json!({"pin": "secret-pin"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
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

    // No PIN supplied: rejected, not a 500.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/profiles/{vault_id}/activate"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Wrong PIN: also rejected.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/profiles/{vault_id}/activate"),
            json!({"db_pin": "not-it"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Still on Default the whole time — a rejected switch must not have
    // partially applied.
    let response = app
        .clone()
        .oneshot(get_request("/profiles/active"))
        .await
        .unwrap();
    assert_eq!(body_json(response).await["profile_id"], json!(default_id));

    // Right PIN: succeeds.
    let response = app
        .oneshot(json_request(
            "POST",
            &format!("/profiles/{vault_id}/activate"),
            json!({"db_pin": "secret-pin"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Every other test in this file constructs `AppState` without attaching a
/// network stack (no need to bind a real TCP listener per test) — confirms
/// `GET /network/status` reports that honestly (`enabled: false`) instead
/// of erroring or lying about a network that isn't actually there.
#[tokio::test]
async fn network_status_reports_disabled_when_no_network_is_attached() {
    use_mock_keychain();
    let dir = test_dir("network-status-disabled");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-network-disabled");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app.oneshot(get_request("/network/status")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status = body_json(response).await;
    assert_eq!(status["enabled"], json!(false));
    assert_eq!(status["alive"], json!(false));
    assert_eq!(status["peer_id"], json!(null));
    assert_eq!(status["listen_addrs"], json!([]));
}

/// With a real `bh_network::supervised::SupervisedNetwork` attached
/// (`AppState::with_network`, what `daemon/src/main.rs` does at startup),
/// `GET /network/status` reports it live: a real peer ID and at least one
/// bound listen address, not placeholders.
#[tokio::test]
async fn network_status_reports_a_live_supervised_node() {
    use_mock_keychain();
    let dir = test_dir("network-status-live");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-network-live");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let network = bh_network::supervised::SupervisedNetwork::spawn(
        "/ip4/127.0.0.1/tcp/0",
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let state = Arc::new(AppState::new(manager, session).with_network(network));
    let app = ApiServer::router(state);

    let response = app.oneshot(get_request("/network/status")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status = body_json(response).await;
    assert_eq!(status["enabled"], json!(true));
    assert_eq!(status["alive"], json!(true));
    assert!(status["peer_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(!status["listen_addrs"].as_array().unwrap().is_empty());
}

/// A linked second device pulls messages sent both before and after it
/// linked, each one really encrypted/decrypted through a Double Ratchet
/// session (`ratchet_roundtrip_ok`), and the delivery cursor advances so
/// neither message is re-served — see `device_sync.rs` module doc.
#[tokio::test]
async fn device_sync_pulls_pending_messages_and_advances_the_cursor() {
    use_mock_keychain();
    let dir = test_dir("device-sync");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-device-sync");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();

    let fake_key = "77".repeat(64);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": fake_key}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
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

    // A message sent before the second device is even linked.
    app.clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/messages"),
            json!({"body": "before linking"}),
        ))
        .await
        .unwrap();

    // Link a second device (same 4-step dance as
    // `device_linking_round_trip_registers_a_second_device`).
    let begun = body_json(
        app.clone()
            .oneshot(json_request("POST", "/devices/link/begin", json!({})))
            .await
            .unwrap(),
    )
    .await;
    let session_id = begun["session_id"].as_str().unwrap().to_string();
    let link = begun["link"].as_str().unwrap().to_string();

    let scanned = body_json(
        app.clone()
            .oneshot(json_request(
                "POST",
                "/devices/link/scan",
                json!({"link": link}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let new_device_session_id = scanned["new_device_session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let provisioning_request_b64 = scanned["provisioning_request_b64"]
        .as_str()
        .unwrap()
        .to_string();

    let accepted = body_json(
        app.clone()
            .oneshot(json_request(
                "POST",
                &format!("/devices/link/{session_id}/accept"),
                json!({
                    "provisioning_request_b64": provisioning_request_b64,
                    "device_name": "Phone",
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
    let response_ciphertext_b64 = accepted["response_ciphertext_b64"]
        .as_str()
        .unwrap()
        .to_string();
    let device_id = accepted["device"]["device_id"]
        .as_str()
        .unwrap()
        .to_string();

    app.clone()
        .oneshot(json_request(
            "POST",
            &format!("/devices/link/{new_device_session_id}/finish"),
            json!({"response_ciphertext_b64": response_ciphertext_b64}),
        ))
        .await
        .unwrap();

    // A second message sent after the link completes.
    app.clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/messages"),
            json!({"body": "after linking"}),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(get_request(&format!("/devices/{device_id}/sync/status")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status = body_json(response).await;
    assert_eq!(status["pending_count"], json!(2));

    let response = app
        .clone()
        .oneshot(get_request(&format!("/devices/{device_id}/sync")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let synced = body_json(response).await;
    let entries = synced["synced"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    // Both messages landed within the same test run, so `sent_at` can tie
    // (unix-second resolution) — the pull is ordered by `(sent_at,
    // message_id)` in that case, not insertion order, so assert on the
    // *set* of bodies rather than a specific position.
    let mut bodies: Vec<&str> = entries
        .iter()
        .map(|entry| entry["body"].as_str().unwrap())
        .collect();
    bodies.sort_unstable();
    assert_eq!(bodies, vec!["after linking", "before linking"]);
    for entry in entries {
        assert_eq!(entry["ratchet_roundtrip_ok"], json!(true));
    }

    // The cursor advanced: neither a status peek nor a second pull sees
    // either message again.
    let response = app
        .clone()
        .oneshot(get_request(&format!("/devices/{device_id}/sync/status")))
        .await
        .unwrap();
    let status = body_json(response).await;
    assert_eq!(status["pending_count"], json!(0));

    let response = app
        .clone()
        .oneshot(get_request(&format!("/devices/{device_id}/sync")))
        .await
        .unwrap();
    let synced = body_json(response).await;
    assert!(synced["synced"].as_array().unwrap().is_empty());

    // Revoked devices are no longer syncable.
    app.clone()
        .oneshot(json_request(
            "POST",
            &format!("/devices/{device_id}/revoke"),
            json!({}),
        ))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(get_request(&format!("/devices/{device_id}/sync")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
}

/// A sticker can only be sent from a pack this profile actually owns
/// (checked server-side against `cosmetic_inventory`, never trusted from
/// the client), and an unknown `sticker_id` is rejected before ownership
/// is even checked. See `crates/bh-api/src/stickers.rs`.
#[tokio::test]
async fn sticker_packs_are_gated_by_ownership_and_send_correctly() {
    use_mock_keychain();
    let dir = test_dir("stickers");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-stickers");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let webhook_secret = bh_api::cosmetics::load_or_create_webhook_secret(&state).unwrap();
    let app = ApiServer::router(state);

    // The sticker-pack contents endpoint is static/public — no purchase or
    // even a catalog lookup needed to see what a pack contains.
    let response = app
        .clone()
        .oneshot(get_request("/cosmetics/sticker-packs"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let packs = body_json(response).await;
    let packs = packs.as_array().unwrap();
    let nebula = packs
        .iter()
        .find(|p| p["pack_item_id"] == json!("sticker-pack-nebula"))
        .unwrap();
    let sticker_id = nebula["stickers"][0]["sticker_id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": "22".repeat(64)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/conversations",
            json!({"contact_id": "c1"}),
        ))
        .await
        .unwrap();
    let conversation_id = body_json(response).await["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Sending a sticker from a pack this profile has never purchased is
    // rejected — ownership, not just client-side UI, gates it.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/stickers"),
            json!({"sticker_id": sticker_id}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // A `sticker_id` that isn't part of any known pack is a 400, not a 403
    // (it never gets far enough to check ownership).
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/stickers"),
            json!({"sticker_id": "not-a-real-sticker"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Purchase and pay for the pack (same catalog/purchase/grant flow as
    // every other cosmetic kind), so it lands in `cosmetic_inventory`.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/cosmetics/purchases",
            json!({"item_id": "sticker-pack-nebula"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let purchase_id = body_json(response).await["purchase_id"]
        .as_str()
        .unwrap()
        .to_string();
    let response = app
        .clone()
        .oneshot(signed_paid_request(
            &format!("/cosmetics/purchases/{purchase_id}/paid"),
            &webhook_secret,
            &purchase_id,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now sending the same sticker succeeds.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/stickers"),
            json!({"sticker_id": sticker_id}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sent = body_json(response).await;
    assert_eq!(
        sent["sticker"]["pack_item_id"],
        json!("sticker-pack-nebula")
    );
    assert_eq!(sent["sticker"]["sticker_id"], json!(sticker_id));
    let message_id = sent["message"]["message_id"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(get_request(&format!("/messages/{message_id}/sticker")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let fetched = body_json(response).await;
    assert_eq!(fetched["sticker_id"], json!(sticker_id));

    // The message itself shows up in the conversation like any other.
    let response = app
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/messages"
        )))
        .await
        .unwrap();
    let messages = body_json(response).await;
    assert_eq!(messages.as_array().unwrap().len(), 1);
}

/// `POST /identity` eagerly creates the singleton "Notes to self"
/// conversation, it stays a singleton across repeat `GET /conversations`
/// calls, and a message can be sent straight into it with no contact
/// and no crypto session ever involved.
#[tokio::test]
async fn self_conversation_is_bootstrapped_singleton_and_needs_no_contact() {
    use_mock_keychain();
    let dir = test_dir("self-conversation");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-self-conversation");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    // Bootstrapping the identity eagerly creates the self-conversation —
    // it should already be in the list before anything else is created.
    let response = app
        .clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(get_request("/conversations"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let conversations = body_json(response).await;
    let conversations = conversations.as_array().unwrap();
    let self_convos: Vec<&Value> = conversations
        .iter()
        .filter(|c| c["kind"] == json!("self"))
        .collect();
    assert_eq!(
        self_convos.len(),
        1,
        "exactly one self-conversation must exist"
    );
    let self_conversation_id = self_convos[0]["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(self_convos[0]["contact_id"].is_null());
    assert!(self_convos[0]["group_id"].is_null());

    // Listing again (as a real client would on every app launch) must not
    // create a second one.
    let response = app
        .clone()
        .oneshot(get_request("/conversations"))
        .await
        .unwrap();
    let conversations = body_json(response).await;
    let self_convos: Vec<&Value> = conversations
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == json!("self"))
        .collect();
    assert_eq!(self_convos.len(), 1);

    // A message can be sent straight into it — no contact, no session,
    // and it must not error.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{self_conversation_id}/messages"),
            json!({"body": "buy milk"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sent = body_json(response).await;
    assert_eq!(sent["message"]["body"], json!("buy milk"));
    assert_eq!(sent["message"]["sender_contact_id"], Value::Null);

    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{self_conversation_id}/messages"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let messages = body_json(response).await;
    assert_eq!(messages.as_array().unwrap().len(), 1);
}

/// A profile that never called `POST /identity` (so never got the eager
/// bootstrap-time creation) still gets exactly one self-conversation the
/// first time `GET /conversations` runs — the lazy fallback path.
#[tokio::test]
async fn self_conversation_is_created_lazily_even_without_identity_bootstrap() {
    use_mock_keychain();
    let dir = test_dir("self-conversation-lazy");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-self-conversation-lazy");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    // No POST /identity here at all — go straight to listing conversations.
    let response = app
        .clone()
        .oneshot(get_request("/conversations"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let conversations = body_json(response).await;
    let self_convos: Vec<&Value> = conversations
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["kind"] == json!("self"))
        .collect();
    assert_eq!(self_convos.len(), 1);
}

/// Sending to a conversation id that doesn't exist at all is a 404, not a
/// silent insert or a 500 — this guards the `get_conversation` lookup
/// `send_message` now does before branching on `ConversationKind`.
#[tokio::test]
async fn send_message_to_unknown_conversation_is_not_found() {
    use_mock_keychain();
    let dir = test_dir("send-unknown-conversation");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-send-unknown");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/conversations/does-not-exist/messages",
            json!({"body": "hello?"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Only the local user's own sent messages can be edited: a contact's
/// message is 403, an already-deleted own message is 404 (nothing
/// sensible to edit once its body is wiped), and an unknown message id is
/// 404. The contact's message body/`edited_at` stay untouched throughout.
#[tokio::test]
async fn editing_someone_elses_message_is_rejected() {
    use_mock_keychain();
    let dir = test_dir("edit-permissions");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-edit-permissions");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));

    state
        .db()
        .upsert_contact(&bh_storage::models::Contact {
            contact_id: "c1".into(),
            identity_public_key: vec![0x77; 32],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
    state
        .db()
        .create_direct_conversation("conv1", "c1", 0)
        .unwrap();

    // A message received from the contact (as if the network layer had
    // already decrypted and stored it) — not something the local user sent.
    state
        .db()
        .insert_message(&bh_storage::models::Message {
            message_id: "their-message".into(),
            conversation_id: "conv1".into(),
            sender_contact_id: Some("c1".into()),
            body: Some("hi from bob".into()),
            sent_at: 0,
            received_at: Some(0),
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();

    // A message the local user sent themselves, then deleted.
    state
        .db()
        .insert_message(&bh_storage::models::Message {
            message_id: "my-deleted-message".into(),
            conversation_id: "conv1".into(),
            sender_contact_id: None,
            body: Some("oops".into()),
            sent_at: 1,
            received_at: None,
            expires_at: None,
            deleted_at: None,
            reply_to_message_id: None,
            edited_at: None,
        })
        .unwrap();
    state
        .db()
        .mark_message_deleted("my-deleted-message", 2)
        .unwrap();

    let app = ApiServer::router(state);

    let response = app
        .clone()
        .oneshot(json_request(
            "PATCH",
            "/conversations/conv1/messages/their-message",
            json!({"body": "rewritten by attacker"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(json_request(
            "PATCH",
            "/conversations/conv1/messages/my-deleted-message",
            json!({"body": "resurrected"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(json_request(
            "PATCH",
            "/conversations/conv1/messages/does-not-exist",
            json!({"body": "x"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Confirm the contact's message really is untouched.
    let response = app
        .clone()
        .oneshot(get_request("/conversations/conv1/messages"))
        .await
        .unwrap();
    let messages = body_json(response).await;
    let their_message = messages
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["message_id"] == json!("their-message"))
        .unwrap();
    assert_eq!(their_message["body"], json!("hi from bob"));
    assert!(their_message["edited_at"].is_null());
}

/// Typing indicators default to off, an opt-out ping is a true no-op (no
/// ciphertext, no state change), opt-in produces a real encrypted
/// round-trip through the shadow Double Ratchet session, never touches
/// `messages`, and turning the setting back off clears state immediately.
#[tokio::test]
async fn typing_indicator_is_opt_in_and_stays_ephemeral() {
    use_mock_keychain();
    let dir = test_dir("typing");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-typing");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();

    let fake_key = "33".repeat(64);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": fake_key}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
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

    // Default is OFF — confirm the setting reads that way with no prior
    // configuration.
    let response = app
        .clone()
        .oneshot(get_request("/settings/typing-indicators"))
        .await
        .unwrap();
    assert_eq!(body_json(response).await, json!({"enabled": false}));

    // Opt-out: posting a typing ping is a no-op. Nothing is "sent" and no
    // ciphertext is produced.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/typing"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        json!({"sent": false, "ciphertext_len": null})
    );

    // ...and the polling read confirms nothing is showing as "typing".
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/typing"
        )))
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        json!({"typing": false, "contact_id": Value::Null})
    );

    // Opt in.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/settings/typing-indicators",
            json!({"enabled": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(get_request("/settings/typing-indicators"))
        .await
        .unwrap();
    assert_eq!(body_json(response).await, json!({"enabled": true}));

    // Opt-in: the same endpoint now actually encrypts a real ephemeral
    // payload and round-trips it through the Double Ratchet session.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/typing"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sent = body_json(response).await;
    assert_eq!(sent["sent"], json!(true));
    let ciphertext_len = sent["ciphertext_len"].as_u64().unwrap();
    assert!(ciphertext_len > 0);

    // The GET side reflects the successful decrypt: "c1 is typing".
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/typing"
        )))
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        json!({"typing": true, "contact_id": "c1"})
    );

    // The signal never touched durable storage: the conversation still
    // has zero real messages.
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/messages"
        )))
        .await
        .unwrap();
    let messages = body_json(response).await;
    assert_eq!(messages, json!([]));

    // Turning the setting back off clears the in-memory typing state
    // immediately, rather than letting a stale "typing" flag linger for
    // up to the TTL.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/settings/typing-indicators",
            json!({"enabled": false}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/typing"
        )))
        .await
        .unwrap();
    assert_eq!(
        body_json(response).await,
        json!({"typing": false, "contact_id": Value::Null})
    );
}

/// A broadcast channel (`kind: "broadcast"` on `POST /groups`) is a real
/// MLS group with posting restricted to its owner: an unrecognized `kind`
/// is rejected outright, the owner can post, a named `sender_contact_id`
/// (simulating a non-owner member, the same way `groups.rs`'s shadow
/// members are exercised elsewhere) is rejected, and the exact same
/// attribution is fine on an ordinary group — the restriction is specific
/// to broadcast channels.
#[tokio::test]
async fn broadcast_channel_rejects_posts_from_non_owner_members() {
    use_mock_keychain();
    let dir = test_dir("broadcast-channel");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-broadcast");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();

    let fake_key = "77".repeat(64);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "subscriber", "identity_public_key": fake_key}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Creating a channel with an unrecognized `kind` is rejected outright.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/groups",
            json!({"name": "bad", "member_contact_ids": [], "kind": "not-a-kind"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/groups",
            json!({
                "name": "Announcements",
                "member_contact_ids": ["subscriber"],
                "kind": "broadcast",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = body_json(response).await;
    assert_eq!(created["group"]["broadcast_only"], json!(true));
    assert_eq!(created["members"].as_array().unwrap().len(), 1);
    let conversation_id = created["conversation"]["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();

    // The owner (local user) can post.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/messages"),
            json!({"body": "welcome to the channel"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A member attempting to post (simulated the same way `groups.rs`
    // simulates a shadow member: by naming a `sender_contact_id`) is
    // rejected — this is the posting restriction, not a crypto check.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/messages"),
            json!({"body": "can I post too?", "sender_contact_id": "subscriber"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Only the owner's message made it into the conversation.
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/conversations/{conversation_id}/messages"
        )))
        .await
        .unwrap();
    let messages = body_json(response).await;
    assert_eq!(messages.as_array().unwrap().len(), 1);

    // The exact same `sender_contact_id` attribution is fine on an
    // ordinary (non-broadcast) group — the restriction is specific to
    // broadcast channels, not attributed sends in general.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/groups",
            json!({"name": "Friends", "member_contact_ids": ["subscriber"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let plain_group = body_json(response).await;
    assert_eq!(plain_group["group"]["broadcast_only"], json!(false));
    let plain_conversation_id = plain_group["conversation"]["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{plain_conversation_id}/messages"),
            json!({"body": "anyone can post here", "sender_contact_id": "subscriber"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// Push registration defaults off, enabling returns a fresh opaque
/// (identity-independent) token that a status check never re-exposes,
/// re-enabling rotates to a different token, and disabling clears the
/// registration entirely.
#[tokio::test]
async fn push_registration_defaults_off_and_rotates_on_enable() {
    use_mock_keychain();
    let dir = test_dir("push-registration");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-push");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    // Off by default — no prior registration exists.
    let response = app
        .clone()
        .oneshot(get_request("/push/register"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status = body_json(response).await;
    assert_eq!(status["enabled"], json!(false));
    assert!(status.get("token").is_none());

    // Enabling returns an opaque token that is not the identity key (no
    // identity exists yet at all in this test, which only underlines that
    // the token can't be derived from one) and is a plausible opaque
    // random hex string, not a short/predictable value.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/push/register",
            json!({"enabled": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let enabled = body_json(response).await;
    assert_eq!(enabled["enabled"], json!(true));
    let first_token = enabled["token"].as_str().unwrap().to_string();
    assert_eq!(first_token.len(), 64); // 32 random bytes, hex-encoded
    assert!(first_token.chars().all(|c| c.is_ascii_hexdigit()));

    // A status check reflects the new state but never re-exposes the
    // token.
    let response = app
        .clone()
        .oneshot(get_request("/push/register"))
        .await
        .unwrap();
    let status = body_json(response).await;
    assert_eq!(status["enabled"], json!(true));
    assert!(status.get("token").is_none());

    // Re-enabling rotates to a different token rather than reusing the
    // old one.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/push/register",
            json!({"enabled": true}),
        ))
        .await
        .unwrap();
    let rotated = body_json(response).await;
    let second_token = rotated["token"].as_str().unwrap().to_string();
    assert_ne!(first_token, second_token);

    // Disabling clears the registration entirely.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/push/register",
            json!({"enabled": false}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let disabled = body_json(response).await;
    assert_eq!(disabled["enabled"], json!(false));
    assert!(disabled.get("token").is_none());

    let response = app.oneshot(get_request("/push/register")).await.unwrap();
    let status = body_json(response).await;
    assert_eq!(status["enabled"], json!(false));
}

/// A voice message reuses the exact same attachment upload endpoint as a
/// regular file, distinguished only by `duration_secs`: it stores with no
/// message body (like a sticker), round-trips byte-for-byte on download,
/// and an out-of-bounds duration is rejected.
#[tokio::test]
async fn voice_message_upload_and_download_round_trip() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    use_mock_keychain();
    let dir = test_dir("voice-messages");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-voice");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    app.clone()
        .oneshot(json_request("POST", "/identity", json!({})))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({"contact_id": "c1", "identity_public_key": "22".repeat(64)}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/conversations",
            json!({"contact_id": "c1"}),
        ))
        .await
        .unwrap();
    let conversation_id = body_json(response).await["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();

    // An out-of-bounds duration is rejected before any chunking/disk work.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/attachments"),
            json!({"data_base64": BASE64.encode(b"noise"), "duration_secs": 0}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let audio = b"pretend-this-is-opus-encoded-audio";
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/attachments"),
            json!({
                "mime_type": "audio/opus",
                "data_base64": BASE64.encode(audio),
                "duration_secs": 7,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let uploaded = body_json(response).await;
    assert_eq!(uploaded["file"]["attachment_kind"], json!("voice"));
    assert_eq!(uploaded["file"]["duration_secs"], json!(7));
    assert!(uploaded["file"].get("file_key").is_none());
    // No body — the client tells a voice message apart from an empty text
    // message by fetching its attachment, same as it does for stickers.
    assert_eq!(uploaded["message"]["body"], Value::Null);
    let content_hash = uploaded["file"]["content_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/attachments/{content_hash}/download"
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let downloaded = body_json(response).await;
    let data_base64 = downloaded["data_base64"].as_str().unwrap();
    assert_eq!(BASE64.decode(data_base64).unwrap(), audio);

    // An ordinary attachment (no `duration_secs`) still defaults to `file`.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{conversation_id}/attachments"),
            json!({"file_name": "notes.txt", "data_base64": BASE64.encode(b"hi")}),
        ))
        .await
        .unwrap();
    let plain = body_json(response).await;
    assert_eq!(plain["file"]["attachment_kind"], json!("file"));
    assert!(plain["file"]["duration_secs"].is_null());
}
/// `GET /search` — local full-text search over the profile's own message
/// history, end to end through the real HTTP route table.
#[tokio::test]
async fn search_finds_own_messages_and_respects_conversation_scope() {
    use_mock_keychain();
    let dir = test_dir("search");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-search");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let fake_key = "33".repeat(64);
    for contact_id in ["c1", "c2"] {
        let response = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/contacts",
                json!({"contact_id": contact_id, "identity_public_key": fake_key}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let mut conversation_ids = Vec::new();
    for contact_id in ["c1", "c2"] {
        let response = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/conversations",
                json!({"contact_id": contact_id}),
            ))
            .await
            .unwrap();
        let conversation = body_json(response).await;
        conversation_ids.push(
            conversation["conversation_id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{}/messages", conversation_ids[0]),
            json!({"body": "let's grab pancakes tomorrow"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/conversations/{}/messages", conversation_ids[1]),
            json!({"body": "totally unrelated topic"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Unscoped search finds the matching message and nothing else.
    let response = app
        .clone()
        .oneshot(get_request("/search?q=pancakes"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let results = body_json(response).await;
    let results = results.as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["conversation_id"], json!(conversation_ids[0]));
    let snippet = results[0]["snippet"].as_str().unwrap();
    assert!(snippet.contains('[') && snippet.contains(']'));

    // Scoped to the *other* conversation, the same query finds nothing.
    let response = app
        .clone()
        .oneshot(get_request(&format!(
            "/search?q=pancakes&conversation_id={}",
            conversation_ids[1]
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let results = body_json(response).await;
    assert!(results.as_array().unwrap().is_empty());

    // A query that isn't valid FTS5 punctuation-wise still comes back
    // clean (200, not a 500) rather than leaking a syntax error.
    let response = app
        .clone()
        .oneshot(get_request("/search?q=%22unterminated"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// End-to-end over real HTTP (in-process, no TCP listener — same as every
/// other test in this file): starting a group call spins up a real local
/// MLS group, derives a real MLS-exporter-based shared call key, and drives
/// a real full-mesh WebRTC/SFrame handshake between the caller and its
/// simulated participants (see `bh_api::calls`'s module doc for why the
/// *other* participants are locally-generated "shadow" MLS members rather
/// than real remote peers — same pattern this workspace uses elsewhere for
/// multi-party flows it can't yet exercise against a live network). Then
/// confirms hangup tears the whole simulated mesh down and a second hangup
/// correctly reports the call is gone.
#[tokio::test]
async fn group_call_start_and_hangup_round_trip() {
    use_mock_keychain();
    let dir = test_dir("group-call");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-group-call");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    // Three participants total: the caller (tag 0) plus 2 shadow members
    // (tags 1, 2) — well under the mesh cap.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/group/start",
            json!({"call_id": "group-call-1", "video": false, "participant_count": 2}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let started = body_json(response).await;
    assert_eq!(started["call_id"], json!("group-call-1"));
    assert_eq!(started["local_tag"], json!(0));
    assert_eq!(started["participant_tags"], json!([1, 2]));

    // Hanging up an unknown call is a 404, not a silent success.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/group/no-such-call/hangup",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Hangup tears down the real call.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/group/group-call-1/hangup",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Hanging up the same call twice is a 404 the second time — it's
    // actually gone from the registry, not still lingering.
    let response = app
        .oneshot(json_request(
            "POST",
            "/calls/group/group-call-1/hangup",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The participant cap (`bh_calls::group::MAX_GROUP_CALL_PARTICIPANTS`) is
/// enforced at the HTTP boundary too, not just inside `bh-calls` — a
/// request asking for more participants than a full mesh can sanely
/// support is rejected outright rather than partially built and left in an
/// inconsistent state.
#[tokio::test]
async fn group_call_over_the_participant_cap_is_rejected() {
    use_mock_keychain();
    let dir = test_dir("group-call-cap");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-group-call-cap");
    let default = manager.create_profile("Default", 0).unwrap();
    let session = open_profile_session(&manager, &default.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let response = app
        .oneshot(json_request(
            "POST",
            "/calls/group/start",
            // 1 caller + 6 shadows = 7 participants, one over the cap of 6.
            json!({"call_id": "group-call-too-big", "video": false, "participant_count": 6}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Exercises the call-signaling endpoints end to end (place -> accept ->
/// complete -> hangup, both "sides" simulated against the same daemon —
/// same one-daemon-simulation caveat as this crate's device-linking/groups
/// tests, there's no second physical peer here), plus the screen-share
/// start/stop endpoints layered on top of a live `CallSession`.
///
/// Screen-share `start` actually opens the platform screen capturer
/// (`bh_calls::screen::ScreenCapture`), so whether it succeeds depends on
/// this environment having a display and having granted screen-recording
/// permission to the test process — neither of which a headless/sandboxed
/// CI runner has. Both outcomes are legitimate here (200 if capture
/// actually started, 500 if the platform/permission gate said no); what
/// this test pins down is that the endpoint always responds instead of
/// hanging/panicking, that unknown call ids 404, and that `stop` is a safe
/// no-op when nothing was shared (a path that never touches capture
/// hardware at all, so it's deterministic in any environment).
#[tokio::test]
async fn calls_start_accept_complete_screen_share_and_hangup_round_trip() {
    use_mock_keychain();
    let dir = test_dir("calls");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-calls");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    // Screen-share endpoints on a call that was never started: 404, not a
    // panic or a hang.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/nonexistent/screen-share/start",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/nonexistent/screen-share/stop",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls",
            json!({"call_id": "call-1", "video": true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let offer = body_json(response).await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/incoming",
            json!({"offer": offer["signal"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let answer = body_json(response).await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/call-1/complete",
            json!({"answer": answer["signal"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Stop with nothing being shared: always a safe, hardware-free no-op.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/call-1/screen-share/stop",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/call-1/screen-share/start",
            json!({"fps": 5}),
        ))
        .await
        .unwrap();
    assert!(
        response.status() == StatusCode::OK
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR,
        "unexpected status starting screen share: {}",
        response.status()
    );

    // Clean up regardless of whether it actually started — stop is
    // idempotent either way, and hangup below should also tear down any
    // still-running share.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/call-1/screen-share/stop",
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(json_request("POST", "/calls/call-1/hangup", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// The capstone test for real `bh-network` wiring (`message_crypto.rs`/
/// `message_receive.rs`): two independent `AppState`s, each with its own
/// real identity and its own real `SupervisedNetwork` (two genuinely
/// separate libp2p nodes, dialed together exactly like two daemon
/// processes on a LAN would be), send a `Direct` message from A to B with
/// no shared process state whatsoever — A's daemon never touches B's
/// database or B's `IdentityKeyPair`. The message travels as real X3DH +
/// Double Ratchet ciphertext through A's `send_message` HTTP call, over a
/// real Kademlia mailbox push/pull between the two nodes, and is only
/// ever plaintext again once B's receive loop decrypts it. If any layer
/// (recipient-key-hash derivation, prekey bundle publish/fetch, sealed
/// sender, the ratchet handshake, associated-data agreement) were wrong,
/// this test would hang until timeout or assert on the wrong body — it
/// does not take the crypto's correctness on faith the way a same-process
/// shadow-session test (`device_sync.rs`'s, `groups.rs`'s) necessarily
/// does.
///
/// Needs a genuine multi-thread runtime (unlike every other test in this
/// file): the default single-threaded `#[tokio::test]` runs this test's
/// many blocking SQLCipher/crypto operations (profile creation, identity
/// bootstrap, X3DH+PQ handshakes) on the *same* thread that has to poll
/// each `Node`'s background swarm event loop, which can starve it long
/// enough for an in-flight Kademlia query to spuriously fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_message_travels_a_real_network_between_two_daemons_and_decrypts() {
    use_mock_keychain();

    let dir_a = test_dir("e2e-network-a");
    let manager_a = ProfileManager::new(&dir_a, "bh-api-smoke-e2e-a");
    let profile_a = manager_a.create_profile("A", 0).unwrap();
    let session_a = open_profile_session(&manager_a, &profile_a.id, true);
    let network_a = bh_network::supervised::SupervisedNetwork::spawn(
        "/ip4/127.0.0.1/tcp/0",
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let state_a = Arc::new(AppState::new(manager_a, session_a).with_network(network_a));
    let app_a = ApiServer::router(state_a.clone());

    let dir_b = test_dir("e2e-network-b");
    let manager_b = ProfileManager::new(&dir_b, "bh-api-smoke-e2e-b");
    let profile_b = manager_b.create_profile("B", 0).unwrap();
    let session_b = open_profile_session(&manager_b, &profile_b.id, true);
    let network_b = bh_network::supervised::SupervisedNetwork::spawn(
        "/ip4/127.0.0.1/tcp/0",
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let state_b = Arc::new(AppState::new(manager_b, session_b).with_network(network_b));
    let app_b = ApiServer::router(state_b.clone());

    // Real daemons need a bootstrap-node list to find each other; this
    // test dials directly, same shortcut `dht.rs`/`mailbox.rs`'s own
    // `connected_pair()` test helpers use. Only one direction — identify
    // reciprocates the routing-table entry on both sides over the same
    // connection; a second, opposite-direction dial on top of an
    // already-connected peer was observed to confuse libp2p's connection
    // bookkeeping enough to make `put_record` fail every time.
    let a_addr = state_a
        .network
        .as_ref()
        .unwrap()
        .listen_addrs()
        .await
        .into_iter()
        .next()
        .unwrap()
        .with_p2p(state_a.network.as_ref().unwrap().peer_id())
        .unwrap();
    state_b
        .network
        .as_ref()
        .unwrap()
        .dial(a_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let identity_a: Value = body_json(
        app_a
            .clone()
            .oneshot(json_request("POST", "/identity", json!({})))
            .await
            .unwrap(),
    )
    .await;
    let identity_b: Value = body_json(
        app_b
            .clone()
            .oneshot(json_request("POST", "/identity", json!({})))
            .await
            .unwrap(),
    )
    .await;

    let signing_a = identity_a["public_signing_key"].as_str().unwrap();
    let agreement_a = identity_a["public_agreement_key"].as_str().unwrap();
    let signing_b = identity_b["public_signing_key"].as_str().unwrap();
    let agreement_b = identity_b["public_agreement_key"].as_str().unwrap();

    // Started *before* A sends anything: B must publish its own prekey
    // bundle (this loop's per-tick side effect, see
    // `message_receive.rs::receive_tick`) before A can establish a
    // session with B at all — nothing else in this test triggers that
    // publish for B, since B never calls `send_message` itself. Also
    // creates B's incoming conversation with A once the message arrives,
    // later in this test.
    bh_api::message_receive::spawn_receive_loop(state_b.clone(), Duration::from_millis(150));
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Each side adds the other as a contact — same convention the desktop
    // client uses (`contact_id` = the other party's signing key hex,
    // `identity_public_key` = signing || agreement hex, concatenated).
    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({
                "contact_id": signing_b,
                "identity_public_key": format!("{signing_b}{agreement_b}"),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app_b
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({
                "contact_id": signing_a,
                "identity_public_key": format!("{signing_a}{agreement_a}"),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let conversation: Value = body_json(
        app_a
            .clone()
            .oneshot(json_request(
                "POST",
                "/conversations",
                json!({"contact_id": signing_b}),
            ))
            .await
            .unwrap(),
    )
    .await;
    let conversation_id = conversation["conversation_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Same shortcut every other real-network test in this workspace takes
    // (`mailbox.rs`'s `publish_with_retry`, `dht.rs`'s own retry loop): a
    // freshly-dialed 2-node Kademlia routing table can take a few round
    // trips to converge enough for a `put_record`/`get_record` to
    // succeed, so B's bundle publish and/or A's fetch of it may
    // transiently fail the first few tries even though nothing is
    // actually broken.
    let mut send_status = StatusCode::SERVICE_UNAVAILABLE;
    for attempt in 0..30 {
        let response = app_a
            .clone()
            .oneshot(json_request(
                "POST",
                &format!("/conversations/{conversation_id}/messages"),
                json!({"body": "hello over the real network"}),
            ))
            .await
            .unwrap();
        send_status = response.status();
        if send_status == StatusCode::OK {
            break;
        }
        assert!(attempt < 29, "send_message never succeeded after retries");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        send_status,
        StatusCode::OK,
        "send_message over a live network must succeed, not just store locally"
    );

    // B has no conversation with A yet at all — the receive loop (already
    // running, started above) must create one
    // (`ensure_direct_conversation`), not just insert a message into a
    // pre-existing one.
    let mut found_body = None;
    for _ in 0..100 {
        let conversations: Value = body_json(
            app_b
                .clone()
                .oneshot(get_request("/conversations"))
                .await
                .unwrap(),
        )
        .await;
        if let Some(conv) = conversations
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["contact_id"] == json!(signing_a))
        {
            let conv_id = conv["conversation_id"].as_str().unwrap();
            let messages: Value = body_json(
                app_b
                    .clone()
                    .oneshot(get_request(&format!("/conversations/{conv_id}/messages")))
                    .await
                    .unwrap(),
            )
            .await;
            if let Some(msg) = messages.as_array().unwrap().first() {
                found_body = msg["body"].as_str().map(str::to_string);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        found_body,
        Some("hello over the real network".to_string()),
        "B's receive loop must have decrypted and stored A's real message within the poll window"
    );
}

/// The capstone test for real network call signaling (`calls.rs`'s
/// `send_call_signal`/`handle_incoming_call_signal`): the same two
/// genuinely independent `SupervisedNetwork`/`AppState` pair the message
/// test above uses, but A places a call to B by passing `contact_id` to
/// `POST /calls` instead of manually ferrying the offer/answer JSON
/// itself. The `Offer` travels as real `Envelope::Call` ciphertext through
/// the same X3DH/Double-Ratchet mailbox path a text message would, B's
/// receive loop decrypts and auto-answers it (a real WebRTC handshake,
/// including real ICE gathering over UDP loopback), the `Answer` travels
/// back the same way, and A's own receive loop completes the handshake
/// from it — neither daemon ever calls `/calls/incoming` or `/calls/:id/
/// complete` directly. `GET /calls/:call_id` (a plain status poll, added
/// alongside this wiring) is used instead of opening the `/ws` stream,
/// since this test only needs "is it active yet," not the event stream
/// itself. Finally, A's hangup is confirmed to reach B over the network
/// too, tearing down B's side without B ever calling `/calls/:id/hangup`
/// itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_signaling_travels_a_real_network_between_two_daemons_and_connects() {
    use_mock_keychain();

    let dir_a = test_dir("e2e-call-network-a");
    let manager_a = ProfileManager::new(&dir_a, "bh-api-smoke-e2e-call-a");
    let profile_a = manager_a.create_profile("A", 0).unwrap();
    let session_a = open_profile_session(&manager_a, &profile_a.id, true);
    let network_a = bh_network::supervised::SupervisedNetwork::spawn(
        "/ip4/127.0.0.1/tcp/0",
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let state_a = Arc::new(AppState::new(manager_a, session_a).with_network(network_a));
    let app_a = ApiServer::router(state_a.clone());

    let dir_b = test_dir("e2e-call-network-b");
    let manager_b = ProfileManager::new(&dir_b, "bh-api-smoke-e2e-call-b");
    let profile_b = manager_b.create_profile("B", 0).unwrap();
    let session_b = open_profile_session(&manager_b, &profile_b.id, true);
    let network_b = bh_network::supervised::SupervisedNetwork::spawn(
        "/ip4/127.0.0.1/tcp/0",
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let state_b = Arc::new(AppState::new(manager_b, session_b).with_network(network_b));
    let app_b = ApiServer::router(state_b.clone());

    let a_addr = state_a
        .network
        .as_ref()
        .unwrap()
        .listen_addrs()
        .await
        .into_iter()
        .next()
        .unwrap()
        .with_p2p(state_a.network.as_ref().unwrap().peer_id())
        .unwrap();
    state_b
        .network
        .as_ref()
        .unwrap()
        .dial(a_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let identity_a: Value = body_json(
        app_a
            .clone()
            .oneshot(json_request("POST", "/identity", json!({})))
            .await
            .unwrap(),
    )
    .await;
    let identity_b: Value = body_json(
        app_b
            .clone()
            .oneshot(json_request("POST", "/identity", json!({})))
            .await
            .unwrap(),
    )
    .await;
    let signing_a = identity_a["public_signing_key"].as_str().unwrap();
    let agreement_a = identity_a["public_agreement_key"].as_str().unwrap();
    let signing_b = identity_b["public_signing_key"].as_str().unwrap();
    let agreement_b = identity_b["public_agreement_key"].as_str().unwrap();

    // Both sides' receive loops must run here (unlike the message test
    // above, which only needs B's): B has to receive A's offer, and A has
    // to receive B's answer back.
    bh_api::message_receive::spawn_receive_loop(state_a.clone(), Duration::from_millis(150));
    bh_api::message_receive::spawn_receive_loop(state_b.clone(), Duration::from_millis(150));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({
                "contact_id": signing_b,
                "identity_public_key": format!("{signing_b}{agreement_b}"),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response = app_b
        .clone()
        .oneshot(json_request(
            "POST",
            "/contacts",
            json!({
                "contact_id": signing_a,
                "identity_public_key": format!("{signing_a}{agreement_a}"),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let call_id = "e2e-call-1";
    // Same DHT-convergence shortcut the message test above takes: a
    // freshly-dialed routing table can take a few round trips to settle.
    let mut start_status = StatusCode::SERVICE_UNAVAILABLE;
    for attempt in 0..30 {
        let response = app_a
            .clone()
            .oneshot(json_request(
                "POST",
                "/calls",
                json!({"call_id": call_id, "video": false, "contact_id": signing_b}),
            ))
            .await
            .unwrap();
        start_status = response.status();
        if start_status == StatusCode::OK {
            break;
        }
        assert!(attempt < 29, "start_call never succeeded after retries");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        start_status,
        StatusCode::OK,
        "starting a call over a live network must succeed"
    );

    let mut b_active = false;
    for _ in 0..150 {
        let status: Value = body_json(
            app_b
                .clone()
                .oneshot(get_request(&format!("/calls/{call_id}")))
                .await
                .unwrap(),
        )
        .await;
        if status["status"] == json!("active") {
            b_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        b_active,
        "B must have received and auto-answered A's real network call offer"
    );

    let mut a_active = false;
    for _ in 0..150 {
        let status: Value = body_json(
            app_a
                .clone()
                .oneshot(get_request(&format!("/calls/{call_id}")))
                .await
                .unwrap(),
        )
        .await;
        if status["status"] == json!("active") {
            a_active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        a_active,
        "A must have completed the WebRTC handshake from B's real network answer"
    );

    let response = app_a
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/calls/{call_id}/hangup"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut b_gone = false;
    for _ in 0..150 {
        let status: Value = body_json(
            app_b
                .clone()
                .oneshot(get_request(&format!("/calls/{call_id}")))
                .await
                .unwrap(),
        )
        .await;
        if status["status"] == json!("unknown") {
            b_gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        b_gone,
        "B's call must be torn down once A's hangup signal arrives over the real network, \
         without B ever calling /calls/:id/hangup itself"
    );
}

/// Verifies the "first event is otherwise always missed" fix
/// (`CallRegistry::record_event`/`subscribe_with_current_state`,
/// `call_stream.rs`'s `handle_socket`): a real WebSocket client that opens
/// `GET /calls/:call_id/ws` *after* `complete_call` already published
/// `Connected` still receives that event as its very first message,
/// instead of waiting forever for an event that already happened —
/// `tokio::sync::broadcast::Sender::send` only reaches receivers that
/// already exist at send time, and no real client could possibly have
/// subscribed before the HTTP response that triggered the event even
/// returned.
///
/// Needs a real TCP listener (unlike every other test in this file, which
/// drives the router in-process via `tower::ServiceExt::oneshot`) — a
/// WebSocket upgrade needs an actual bidirectional IO stream to hand off
/// to, which the mocked `oneshot` request/response cycle can't provide.
/// The signaling calls (`/calls`, `/calls/incoming`, `/calls/:id/complete`)
/// still go through `oneshot` against the same router — its `AppState` is
/// the same `Arc` the real listener serves, so both views see the same
/// call registry.
#[tokio::test]
async fn call_ws_replays_the_last_known_state_to_a_late_subscriber() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    use_mock_keychain();
    let dir = test_dir("call-ws");
    let manager = ProfileManager::new(&dir, "bh-api-smoke-call-ws");
    let profile = manager.create_profile("A", 0).unwrap();
    let session = open_profile_session(&manager, &profile.id, true);
    let state = Arc::new(AppState::new(manager, session));
    let app = ApiServer::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_app = app.clone();
    tokio::spawn(async move {
        axum::serve(listener, serve_app).await.unwrap();
    });

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls",
            json!({"call_id": "ws-call-1", "video": false}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let offer = body_json(response).await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/calls/incoming",
            json!({"offer": offer["signal"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let answer = body_json(response).await;

    // `complete_call` records `Connected` synchronously, strictly before
    // this test ever attempts to open the WebSocket below — exactly the
    // race `subscribe_with_current_state` exists to close.
    let response = app
        .oneshot(json_request(
            "POST",
            "/calls/ws-call-1/complete",
            json!({"answer": answer["signal"]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Same `require_bearer_token` gate as every other route (server.rs) —
    // a plain URL has no way to carry it, so build the handshake request
    // by hand and attach it, same as `call_stream_bridge.rs`'s real client
    // does.
    let url = format!("ws://{addr}/calls/ws-call-1/ws");
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Authorization", auth_header().parse().unwrap());
    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();

    let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timed out waiting for the replayed Connected event")
        .expect("stream ended before any message arrived")
        .unwrap();
    let text = match first {
        WsMessage::Text(text) => text,
        other => panic!("expected a text frame carrying the Connected event, got {other:?}"),
    };
    let event: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event, json!({"type": "connected"}));

    ws.close(None).await.unwrap();
}
