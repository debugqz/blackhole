//! Keeps a [`Node`] (and the [`Dht`]/[`Mailbox`] built on top of it) alive
//! across the failure this codebase can't fix directly: the `yamux`
//! remote-panic CVE documented in `docs/THREAT_MODEL.md` §3.10 (ranked
//! #2). A crafted inbound frame can panic `libp2p-yamux`'s internal state
//! machine; the fix is blocked on an upstream `rust-libp2p` release, not
//! anything changeable in this repo. `Node::spawn`'s event loop already
//! runs as its own `tokio::spawn`ed task, so that panic doesn't crash the
//! daemon process — but without this module, it silently and permanently
//! kills *that node's* networking: every `Node`/`Dht`/`Mailbox` clone
//! sharing its channel starts returning `NetworkError::NodeShutDown`
//! forever, until someone notices and restarts the whole daemon.
//!
//! [`SupervisedNetwork`] instead periodically checks [`Node::is_alive`]
//! and, if the event loop has died, spawns a fresh `Node` (new identity —
//! see the caveat on [`SupervisedNetwork::spawn`]) and atomically swaps it
//! in. Callers must fetch [`SupervisedNetwork::dht`]/
//! [`SupervisedNetwork::mailbox`] per use rather than caching the result
//! long-term — a cached clone from before a respawn still points at the
//! dead node's channel, same as holding onto a `Node` clone directly
//! would.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use libp2p::PeerId;

use crate::dht::Dht;
use crate::mailbox::Mailbox;
use crate::transport::Node;
use crate::NetworkError;

const LOCK_POISON_MSG: &str = "supervised network stack lock poisoned";

struct Stack {
    node: Node,
    dht: Dht,
    mailbox: Mailbox,
}

impl Stack {
    fn from_node(node: Node) -> Self {
        let dht = Dht::new(node.clone());
        let mailbox = Mailbox::new(dht.clone());
        Self { node, dht, mailbox }
    }
}

/// A `Node`/`Dht`/`Mailbox` bundle that respawns itself if the underlying
/// swarm event loop dies. Cheap to clone (an `Arc` around the current
/// stack); every clone sees the same live-or-respawned state.
#[derive(Clone)]
pub struct SupervisedNetwork {
    stack: Arc<RwLock<Stack>>,
    listen_addr: String,
}

impl SupervisedNetwork {
    /// Spawns a `Node` listening on `listen_addr` and a background task
    /// that checks its health every `health_check_interval` and respawns
    /// on death.
    ///
    /// **Identity caveat**: `Node::spawn` (`SwarmBuilder::with_new_identity`)
    /// generates a fresh random libp2p keypair every call — this repo does
    /// not yet persist a stable libp2p peer identity across restarts (of
    /// the daemon, or of a respawn triggered by this supervisor). A
    /// respawned node is therefore a *new* peer from the rest of the
    /// network's point of view, not a reconnection as the same one. Making
    /// that identity durable (load/store the keypair the same way
    /// `keystore.rs` handles the SQLCipher key) is a real follow-up, not
    /// done here — this module's job is containing the yamux blast radius,
    /// not node identity persistence.
    pub async fn spawn(
        listen_addr: impl Into<String>,
        health_check_interval: Duration,
    ) -> Result<Self, NetworkError> {
        let listen_addr = listen_addr.into();
        let node = Node::spawn(&listen_addr).await?;
        let stack = Arc::new(RwLock::new(Stack::from_node(node)));

        let supervised = Self {
            stack: stack.clone(),
            listen_addr: listen_addr.clone(),
        };
        tokio::spawn(supervise(stack, listen_addr, health_check_interval));
        Ok(supervised)
    }

    pub fn peer_id(&self) -> PeerId {
        self.stack.read().expect(LOCK_POISON_MSG).node.peer_id()
    }

    /// The multiaddr new/respawned nodes listen on — not necessarily where
    /// the *current* node ended up bound if `listen_addr` used `tcp/0`
    /// (OS-assigned port); see [`SupervisedNetwork::listen_addrs`] for
    /// that.
    pub fn configured_listen_addr(&self) -> &str {
        &self.listen_addr
    }

    pub fn is_alive(&self) -> bool {
        self.stack.read().expect(LOCK_POISON_MSG).node.is_alive()
    }

    pub async fn listen_addrs(&self) -> Vec<libp2p::Multiaddr> {
        let node = self.stack.read().expect(LOCK_POISON_MSG).node.clone();
        node.listen_addrs().await
    }

    /// Fetch fresh before each use — see the module doc for why a
    /// long-held clone can go stale across a respawn.
    pub fn dht(&self) -> Dht {
        self.stack.read().expect(LOCK_POISON_MSG).dht.clone()
    }

    /// Fetch fresh before each use — see the module doc for why a
    /// long-held clone can go stale across a respawn.
    pub fn mailbox(&self) -> Mailbox {
        self.stack.read().expect(LOCK_POISON_MSG).mailbox.clone()
    }
}

async fn supervise(stack: Arc<RwLock<Stack>>, listen_addr: String, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip the immediate first tick, node just started

    loop {
        ticker.tick().await;

        let alive = stack.read().expect(LOCK_POISON_MSG).node.is_alive();
        if alive {
            continue;
        }

        tracing::warn!("network event loop died (see docs/THREAT_MODEL.md §3.10) — respawning");
        match Node::spawn(&listen_addr).await {
            Ok(node) => {
                *stack.write().expect(LOCK_POISON_MSG) = Stack::from_node(node);
                tracing::info!("network node respawned after failure");
            }
            Err(err) => {
                tracing::error!(%err, "failed to respawn network node — will retry next tick");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_freshly_spawned_network_is_alive_and_functional() {
        let net = SupervisedNetwork::spawn("/ip4/127.0.0.1/tcp/0", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(net.is_alive());
        // A real bound socket, not just a flag — proves the event loop
        // actually processed a `NewListenAddr` swarm event, same signal
        // `transport::tests::node_reports_a_listen_address` relies on.
        assert!(!net.listen_addrs().await.is_empty());
        // dht()/mailbox() must return live, usable handles wired to the
        // same underlying node, not disconnected stand-ins.
        let ok = tokio::time::timeout(Duration::from_secs(5), net.dht().lookup(b"nothing-here"))
            .await
            .expect("lookup should not hang")
            .unwrap();
        assert_eq!(ok, None);
    }

    #[tokio::test]
    async fn supervisor_detects_a_dead_node_and_respawns_a_working_one() {
        let dead = Node::dead_handle_for_test();
        assert!(!dead.is_alive());
        let stack = Arc::new(RwLock::new(Stack::from_node(dead)));
        let net = SupervisedNetwork {
            stack: stack.clone(),
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
        };
        assert!(!net.is_alive(), "sanity check: starts dead");

        tokio::spawn(supervise(
            stack,
            "/ip4/127.0.0.1/tcp/0".to_string(),
            Duration::from_millis(20),
        ));

        // Give the supervisor a couple of ticks to notice and respawn.
        let mut respawned = false;
        for _ in 0..50 {
            if net.is_alive() {
                respawned = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(respawned, "supervisor never respawned a dead node");

        // Not just "alive" — a real bound listener and a working dht()
        // handle, proving the swap produced a genuinely functional stack
        // rather than just flipping a flag.
        assert!(!net.listen_addrs().await.is_empty());
        let ok = tokio::time::timeout(Duration::from_secs(5), net.dht().lookup(b"nothing-here"))
            .await
            .expect("lookup should not hang")
            .unwrap();
        assert_eq!(ok, None);
    }
}
