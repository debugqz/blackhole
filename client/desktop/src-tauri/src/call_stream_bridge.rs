//! Bridges a call's `GET /calls/:call_id/ws` daemon stream (state events
//! plus VP8 video/screen frames — see `bh-api::call_stream`'s module doc)
//! into the webview via Tauri's event system.
//!
//! The webview can't open that WebSocket directly: browsers (and Tauri's
//! webview) always attach an `Origin` header to a WebSocket handshake,
//! and `server.rs`'s `reject_browser_origin` middleware rejects any
//! request carrying one — unlike `daemon_call`'s raw-`TcpStream` HTTP
//! bridge, which never sets `Origin`. This follows the same precedent
//! `link_preview.rs` set for "networking that must happen on the Tauri
//! Rust side, not the webview's own fetch/WebSocket stack": this module
//! dials the daemon itself with `tokio-tungstenite` and relays what it
//! receives as Tauri events (`call-event` for JSON state, `call-frame`
//! for binary video/screen frames, base64-encoded in the event payload —
//! raw bytes in a JSON array would bloat several-KB VP8 frames ~3-12x on
//! the wire, the same lesson `message_crypto.rs`'s sealed-sender fix
//! learned on the daemon side).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use futures_util::StreamExt;
use serde::Serialize;
use tauri::Emitter;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const DAEMON_PORT: u16 = 47_853;

/// Live call-stream bridges, keyed by `call_id`. Holding the stop sender
/// keeps each bridge's background task discoverable (and stoppable via
/// [`unsubscribe_call_stream`]) without needing to await a `JoinHandle` —
/// nothing here waits on the task's completion, only signals it to end.
#[derive(Default)]
pub struct CallStreamBridges(Mutex<HashMap<String, oneshot::Sender<()>>>);

#[derive(Serialize, Clone)]
struct CallEventPayload {
    call_id: String,
    event: serde_json::Value,
}

#[derive(Serialize, Clone)]
struct CallFramePayload {
    call_id: String,
    kind: u8,
    bytes_b64: String,
}

/// Opens (or re-opens) the bridge for `call_id`, emitting `call-event`
/// (JSON body: `{call_id, event}`, `event` shaped like
/// `bh_api::call_stream::CallEvent`'s serde form) and `call-frame`
/// (`{call_id, kind, bytes_b64}`, `kind` matching
/// `bh_api::call_stream::FrameKind`'s `u8` tag) to the webview as they
/// arrive. Idempotent: subscribing twice for the same call id tears down
/// the previous connection first, rather than leaking a second task that
/// would double-emit every event.
#[tauri::command]
pub async fn subscribe_call_stream(
    app: tauri::AppHandle,
    state: tauri::State<'_, CallStreamBridges>,
    call_id: String,
) -> Result<(), String> {
    {
        let mut guard = state
            .0
            .lock()
            .map_err(|_| "call stream bridge lock poisoned".to_string())?;
        if let Some(old_stop_tx) = guard.remove(&call_id) {
            let _ = old_stop_tx.send(());
        }
    }

    // Like `daemon_call`'s HTTP bridge, this needs `server.rs`'s
    // `require_bearer_token` header — unlike a browser `WebSocket()`
    // (which can't set arbitrary headers on the handshake, the reason
    // this module exists in the first place per its own doc comment),
    // `tokio-tungstenite` can, so this gets the same token every other
    // daemon call uses rather than needing a different auth mechanism.
    let url = format!("ws://127.0.0.1:{DAEMON_PORT}/calls/{call_id}/ws");
    let token = crate::read_api_token()
        .ok_or_else(|| "daemon unreachable: no API token on disk yet".to_string())?;
    let mut request = url
        .into_client_request()
        .map_err(|e| format!("invalid call stream URL: {e}"))?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token}")
            .parse()
            .map_err(|e| format!("invalid API token: {e}"))?,
    );
    let (mut ws, _response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| format!("failed to connect to call stream: {e}"))?;

    let (stop_tx, mut stop_rx) = oneshot::channel();
    state
        .0
        .lock()
        .map_err(|_| "call stream bridge lock poisoned".to_string())?
        .insert(call_id.clone(), stop_tx);

    tauri::async_runtime::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                message = ws.next() => {
                    let Some(Ok(message)) = message else { break };
                    match message {
                        WsMessage::Text(text) => {
                            if let Ok(event) = serde_json::from_str(&text) {
                                let _ = app.emit(
                                    "call-event",
                                    CallEventPayload { call_id: call_id.clone(), event },
                                );
                            }
                        }
                        WsMessage::Binary(bytes) => {
                            if let Some((&kind, payload)) = bytes.split_first() {
                                let _ = app.emit(
                                    "call-frame",
                                    CallFramePayload {
                                        call_id: call_id.clone(),
                                        kind,
                                        bytes_b64: BASE64.encode(payload),
                                    },
                                );
                            }
                        }
                        WsMessage::Close(_) => break,
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(())
}

/// Ends `call_id`'s bridge, if one is open — a no-op otherwise (hanging up
/// a call whose stream was never subscribed to, or unsubscribing twice,
/// are both fine).
#[tauri::command]
pub fn unsubscribe_call_stream(state: tauri::State<'_, CallStreamBridges>, call_id: String) {
    if let Ok(mut guard) = state.0.lock() {
        if let Some(stop_tx) = guard.remove(&call_id) {
            let _ = stop_tx.send(());
        }
    }
}
