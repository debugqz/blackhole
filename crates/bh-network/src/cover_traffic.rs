//! Constant-interval dummy traffic between client and entry node, so
//! sending a real message is indistinguishable from being idle. Configurable
//! given the battery/data cost (SPEC.md §5.2) — callers decide whether it's
//! on at all via [`CoverTrafficConfig::enabled`].

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    pub enabled: bool,
    pub interval: Duration,
    /// Dummy packets are padded to a fixed size so they're indistinguishable
    /// from real (padded) traffic by length alone.
    pub packet_size: usize,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: Duration::from_secs(30),
            packet_size: 512,
        }
    }
}

fn dummy_packet(size: usize) -> Vec<u8> {
    let mut packet = vec![0u8; size];
    // Random content, not just zeros — a passive observer who somehow
    // decrypts an entry-node-bound packet shouldn't see an obvious
    // all-zero tell. Content otherwise carries no meaning; only the
    // outer onion layer needs to look like real traffic.
    let _ = getrandom::fill(&mut packet);
    packet
}

/// A running cover-traffic scheduler. Dropping or calling [`stop`](Self::stop)
/// ends it.
pub struct CoverTrafficHandle {
    task: JoinHandle<()>,
}

impl CoverTrafficHandle {
    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for CoverTrafficHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Spawns a background task that calls `send` with a fresh dummy packet
/// every `config.interval`, for as long as `config.enabled`. Returns
/// `None` if cover traffic is disabled — nothing is spawned.
pub fn spawn<F, Fut>(config: CoverTrafficConfig, send: F) -> Option<CoverTrafficHandle>
where
    F: Fn(Vec<u8>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    if !config.enabled {
        return None;
    }

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(config.interval);
        // Default `MissedTickBehavior::Burst` fires every missed tick
        // back-to-back the moment `send` is briefly slow, which is exactly
        // the opposite of this module's entire purpose — a burst is a
        // real, observable timing tell. `Delay` just resumes the constant
        // cadence from whenever the late tick actually completed.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; skip it so cover traffic
        // starts on the same cadence it'll keep, not with a burst at t=0.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            send(dummy_packet(config.packet_size)).await;
        }
    });

    Some(CoverTrafficHandle { task })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn disabled_config_spawns_nothing() {
        let handle = spawn(
            CoverTrafficConfig {
                enabled: false,
                ..Default::default()
            },
            |_packet| async {},
        );
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn sends_packets_of_the_configured_size_at_the_configured_interval() {
        let count = Arc::new(AtomicUsize::new(0));
        let last_len = Arc::new(AtomicUsize::new(0));

        let count_clone = count.clone();
        let last_len_clone = last_len.clone();
        let handle = spawn(
            CoverTrafficConfig {
                enabled: true,
                interval: Duration::from_millis(20),
                packet_size: 128,
            },
            move |packet| {
                let count = count_clone.clone();
                let last_len = last_len_clone.clone();
                async move {
                    last_len.store(packet.len(), Ordering::SeqCst);
                    count.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .expect("cover traffic should spawn when enabled");

        tokio::time::sleep(Duration::from_millis(110)).await;
        let sent = count.load(Ordering::SeqCst);
        assert!(
            sent >= 3,
            "expected several ticks in 110ms at a 20ms interval, got {sent}"
        );
        assert_eq!(last_len.load(Ordering::SeqCst), 128);

        handle.stop();
    }

    #[tokio::test]
    async fn stop_halts_further_sends() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let handle = spawn(
            CoverTrafficConfig {
                enabled: true,
                interval: Duration::from_millis(15),
                packet_size: 32,
            },
            move |_packet| {
                let count = count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.stop();
        let after_stop = count.load(Ordering::SeqCst);

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            after_stop,
            "no further sends should happen after stop()"
        );
    }
}
