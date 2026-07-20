//! The UI talks only to the local daemon over localhost, never directly to
//! the P2P network (docs/SPEC.md §6). This command is a minimal
//! demonstration of that boundary: it makes a plain HTTP request to the
//! daemon's `/health` endpoint and returns the response to the webview.
//! Real daemon communication (once the API surface grows past a health
//! check) should move to a typed client, not raw sockets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_DAEMON_PORT: u16 = 47_853;

#[tauri::command]
fn daemon_health(port: Option<u16>) -> Result<String, String> {
    let port = port.unwrap_or(DEFAULT_DAEMON_PORT);
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("daemon unreachable: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![daemon_health])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
