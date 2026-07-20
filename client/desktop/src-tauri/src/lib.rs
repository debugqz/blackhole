//! The UI talks only to the local daemon over localhost, never directly to
//! the P2P network (docs/SPEC.md §6). These commands are raw HTTP over a
//! `TcpStream` — fine while the API surface is this small; once it grows
//! past a handful of calls this should move to a typed HTTP client.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_DAEMON_PORT: u16 = 47_853;

fn daemon_request(port: Option<u16>, method: &str, path: &str) -> Result<String, String> {
    let port = port.unwrap_or(DEFAULT_DAEMON_PORT);
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("daemon unreachable: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| e.to_string())?;
    response
        .split("\r\n\r\n")
        .nth(1)
        .map(str::to_string)
        .ok_or_else(|| "malformed daemon response".to_string())
}

#[tauri::command]
fn daemon_health(port: Option<u16>) -> Result<String, String> {
    daemon_request(port, "GET", "/health")
}

/// Irreversible. Wipes the daemon's local key material and database, then
/// the daemon process exits (SPEC.md §7) — this is meant to be gated
/// behind a real confirmation in the UI, not a stray click.
#[tauri::command]
fn panic_wipe_daemon(port: Option<u16>) -> Result<String, String> {
    daemon_request(port, "POST", "/panic-wipe")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![daemon_health, panic_wipe_daemon])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
