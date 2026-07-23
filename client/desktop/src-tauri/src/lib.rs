//! The UI talks only to the local daemon over localhost, never directly to
//! the P2P network (docs/SPEC.md §6). `daemon_call` is a single generic
//! command that proxies an HTTP request over a raw `TcpStream` — the API
//! surface grew past "a handful of calls" (see git history for the old
//! one-Tauri-command-per-route version), so the typed surface now lives on
//! the TypeScript side (`src/api.ts`) instead of being duplicated here.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::Serialize;

mod call_stream_bridge;
mod daemon_lifecycle;
mod link_preview;
mod network_config;
mod prf_unlock;

const DEFAULT_DAEMON_PORT: u16 = 47_853;

/// Matches `daemon/src/main.rs`'s own `data_dir()` exactly — both sides
/// need to agree on where the daemon's per-process bearer token
/// (`api_token`, `server.rs`'s `require_bearer_token`) gets written and
/// read from.
pub(crate) fn data_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("BLACKHOLE_DATA_DIR") {
        return dir.into();
    }
    dirs::data_dir()
        .expect("no platform data directory available")
        .join("blackhole")
}

/// Reads the daemon's current bearer token from disk. `None` if the file
/// doesn't exist yet (daemon hasn't started, or hasn't gotten far enough
/// to write it) — callers should surface the existing "daemon
/// unreachable"-style error in that case, same as any other
/// daemon-not-up scenario.
pub(crate) fn read_api_token() -> Option<String> {
    std::fs::read_to_string(data_dir().join("api_token"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[derive(Serialize)]
pub struct DaemonResponse {
    status: u16,
    body: String,
}

/// HTTP verbs the daemon's route table actually uses (`server.rs`) — an
/// allowlist, not a general HTTP client, since `method` ends up spliced
/// directly into the request line below.
const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH"];

/// `method` and `path` are spliced directly into the request line, and
/// this webview-callable command has no other gate in front of it — a
/// future XSS bug in the webview (e.g. a contact-controlled string
/// reaching `innerHTML`) would otherwise get an unvalidated bridge into
/// raw request-line/header injection against whatever is listening on
/// this port. Reject anything that isn't a plain, single-line HTTP
/// request against the daemon's own route table.
fn validate_method_and_path(method: &str, path: &str) -> Result<(), String> {
    if !ALLOWED_METHODS.contains(&method) {
        return Err(format!("unsupported method: {method}"));
    }
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err("invalid path".to_string());
    }
    Ok(())
}

fn daemon_request(
    method: &str,
    path: &str,
    body: Option<String>,
) -> Result<DaemonResponse, String> {
    validate_method_and_path(method, path)?;

    let mut stream = TcpStream::connect(("127.0.0.1", DEFAULT_DAEMON_PORT))
        .map_err(|e| format!("daemon unreachable: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let token = read_api_token().ok_or_else(|| {
        "daemon unreachable: no API token on disk yet (has the daemon started?)".to_string()
    })?;
    let payload = body.unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| e.to_string())?;

    let mut parts = response.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default().to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "malformed daemon response".to_string())?;

    Ok(DaemonResponse { status, body })
}

#[tauri::command]
fn daemon_call(
    method: String,
    path: String,
    body: Option<String>,
) -> Result<DaemonResponse, String> {
    daemon_request(&method, &path, body)
}

/// Fetches a URL directly (never through the daemon) for a client-side
/// link preview — see `link_preview.rs` module doc for the privacy
/// tradeoff and SSRF guard this enforces.
#[tauri::command]
fn fetch_link_preview(url: String) -> Result<link_preview::LinkPreviewResponse, String> {
    link_preview::fetch(&url)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(daemon_lifecycle::DaemonProcess::default())
        .manage(call_stream_bridge::CallStreamBridges::default())
        .invoke_handler(tauri::generate_handler![
            daemon_call,
            fetch_link_preview,
            daemon_lifecycle::ensure_daemon_running,
            daemon_lifecycle::stop_daemon,
            prf_unlock::get_prf_unlock_config,
            prf_unlock::save_prf_unlock_config,
            prf_unlock::clear_prf_unlock_config,
            network_config::get_network_config,
            network_config::save_network_config,
            call_stream_bridge::subscribe_call_stream,
            call_stream_bridge::unsubscribe_call_stream,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_method_outside_the_allowlist() {
        assert!(validate_method_and_path("TRACE", "/health").is_err());
        assert!(
            validate_method_and_path("get", "/health").is_err(),
            "case-sensitive"
        );
    }

    #[test]
    fn accepts_every_allowlisted_method() {
        for method in ALLOWED_METHODS {
            assert!(validate_method_and_path(method, "/health").is_ok());
        }
    }

    #[test]
    fn rejects_a_path_that_does_not_start_with_a_slash() {
        assert!(validate_method_and_path("GET", "health").is_err());
    }

    /// Regression test: a path containing CR/LF could otherwise splice
    /// extra header lines (or a second request) into the request this
    /// bridge sends to the daemon.
    #[test]
    fn rejects_a_path_containing_crlf() {
        assert!(validate_method_and_path("GET", "/health\r\nX-Injected: 1").is_err());
        assert!(validate_method_and_path("GET", "/health\nX-Injected: 1").is_err());
    }

    #[test]
    fn accepts_a_well_formed_path() {
        assert!(validate_method_and_path("POST", "/conversations/abc-123/messages").is_ok());
    }
}
