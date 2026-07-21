//! Background sweeper for self-destructing messages (SPEC.md §7): messages
//! with an `expires_at` in the past get purged on a timer, not just
//! lazily on next read, so a conversation that's never reopened still
//! gets cleaned up.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::Database;

/// Spawns a background task that calls `purge_expired_messages` every
/// `interval`. `now` is injected (rather than reading the system clock
/// directly) so callers can test this deterministically.
pub fn spawn_expiry_sweeper(
    db: Database,
    interval: Duration,
    now: impl Fn() -> i64 + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate first tick, same as cover traffic
        loop {
            ticker.tick().await;
            match db.purge_expired_messages(now()) {
                Ok(purged) if !purged.is_empty() => {
                    tracing::debug!(
                        count = purged.len(),
                        "purged expired self-destruct messages"
                    );
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(%err, "expiry sweep failed"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Contact, Message};
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn sweeper_purges_messages_once_they_expire() {
        let db = Database::open_in_memory(&[1u8; 32]).unwrap();
        db.upsert_contact(&Contact {
            contact_id: "c1".into(),
            identity_public_key: vec![1],
            display_name: None,
            verified: false,
            blocked: false,
            added_at: 0,
        })
        .unwrap();
        db.create_direct_conversation("conv1", "c1", 0).unwrap();
        db.insert_message(&Message {
            message_id: "m1".into(),
            conversation_id: "conv1".into(),
            sender_contact_id: None,
            body: Some("self destructs at t=10".into()),
            sent_at: 0,
            received_at: None,
            expires_at: Some(10),
            deleted_at: None,
            reply_to_message_id: None,
        })
        .unwrap();

        let clock = Arc::new(AtomicI64::new(0));
        let clock_clone = clock.clone();
        let handle = spawn_expiry_sweeper(db.clone(), Duration::from_millis(15), move || {
            clock_clone.load(Ordering::SeqCst)
        });

        // Still before expiry: message survives the first couple of sweeps.
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 1);

        // Advance the injected clock past expiry and let another sweep run.
        clock.store(20, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(db.list_messages("conv1", 10).unwrap().len(), 0);

        handle.abort();
    }
}
