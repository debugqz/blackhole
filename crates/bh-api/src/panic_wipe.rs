//! Emergency panic wipe (SPEC.md §7): irreversibly destroys local key
//! material and the encrypted database, then exits the daemon process —
//! there is no safe way to keep serving requests against a database that
//! was just deleted out from under an open connection pool, so the client
//! should expect the daemon to disappear and need restarting.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;

use crate::AppState;

pub async fn panic_wipe(State(state): State<Arc<AppState>>) -> StatusCode {
    match state.keystore.panic_wipe() {
        Ok(()) => {
            tracing::warn!("panic wipe executed — daemon exiting");
            tokio::spawn(async {
                // Give the HTTP response a moment to actually flush before
                // the process disappears.
                tokio::time::sleep(Duration::from_millis(200)).await;
                std::process::exit(0);
            });
            StatusCode::OK
        }
        Err(err) => {
            tracing::error!(%err, "panic wipe failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
