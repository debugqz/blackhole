//! Keeps a [`Node`] (and the [`Dht`]/[`Mailbox`] built on top of it) alive
//! across any panic in the swarm event loop. This module was originally
//! written to contain a specific yamux remote-panic CVE
//! (`docs/THREAT_MODEL.md` §3.10) — verification since then found that
//! CVE isn't actually reachable through the yamux core this node runs
//! (`transport.rs`'s `yamux::Config::default()` resolves to the fixed
//! core, not the vulnerable one), so this module's value today is general
//! defense-in-depth against *any* future event-loop panic, not a
//! mitigation for that one bug specifically. `Node::spawn`'s event loop
//! already runs as its own `tokio::spawn`ed task, so a panic there
//! doesn't crash the daemon process — but without this module, it would
//! silently and permanently kill *that node's* networking: every
//! `Node`/`Dht`/`Mailbox` clone sharing its channel would start returning
//! `NetworkError::NodeShutDown` forever, until someone noticed and
//! restarted the whole daemon.
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

use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};

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
    bootstrap_peers: Arc<Vec<Multiaddr>>,
    keypair: Keypair,
}

impl SupervisedNetwork {
    /// Spawns a `Node` listening on `listen_addr` and a background task
    /// that checks its health every `health_check_interval` and respawns
    /// on death. Equivalent to [`SupervisedNetwork::spawn_with_bootstrap`]
    /// with an empty peer list — nobody is dialed proactively, matching
    /// this method's original behavior for every existing caller/test.
    ///
    /// Uses a fresh random libp2p identity, same as plain [`Node::spawn`] —
    /// see [`SupervisedNetwork::spawn_with_bootstrap_and_keypair`] for the
    /// stable-identity alternative a DHT bootstrap node needs.
    pub async fn spawn(
        listen_addr: impl Into<String>,
        health_check_interval: Duration,
    ) -> Result<Self, NetworkError> {
        Self::spawn_with_bootstrap(listen_addr, health_check_interval, Vec::new()).await
    }

    /// Same as [`SupervisedNetwork::spawn`], but also dials every address
    /// in `bootstrap_peers` right after the node comes up (best-effort —
    /// a dial failure is logged, not fatal, same posture as the daemon's
    /// own "network is best-effort" spawn-failure handling) and again
    /// after any future respawn. This is what closes the gap `dial`'s own
    /// doc comment describes: "real deployments need a bootstrap-node
    /// list." Uses a fresh random identity every call — see
    /// [`SupervisedNetwork::spawn_with_bootstrap_and_keypair`] if the
    /// caller needs that identity to survive a restart.
    pub async fn spawn_with_bootstrap(
        listen_addr: impl Into<String>,
        health_check_interval: Duration,
        bootstrap_peers: Vec<Multiaddr>,
    ) -> Result<Self, NetworkError> {
        Self::spawn_with_bootstrap_and_keypair(
            listen_addr,
            health_check_interval,
            bootstrap_peers,
            Keypair::generate_ed25519(),
        )
        .await
    }

    /// Same as [`SupervisedNetwork::spawn_with_bootstrap`], but with a
    /// caller-supplied libp2p identity instead of a fresh random one — the
    /// same identity is reused across every future respawn this
    /// supervisor performs, unlike the plain `spawn*` constructors above.
    /// This is the fix `spawn`'s previous doc comment flagged as a real
    /// follow-up ("making [network] identity durable... is a real
    /// follow-up, not done here"): a respawned or restarted node using
    /// this constructor keeps the same [`PeerId`], so every other node's
    /// `BLACKHOLE_BOOTSTRAP_PEERS` entry pointing at it (`/p2p/<PeerId>`)
    /// stays valid instead of silently going stale. Intended for
    /// deliberately public, stable-address nodes (a DHT bootstrap node);
    /// see `daemon/src/main.rs`'s `BLACKHOLE_PERSISTENT_NETWORK_IDENTITY`
    /// for the opt-in gate — an ordinary end-user daemon has no reason to
    /// use this (see [`Node::spawn_with_keypair`]'s doc comment for why).
    pub async fn spawn_with_bootstrap_and_keypair(
        listen_addr: impl Into<String>,
        health_check_interval: Duration,
        bootstrap_peers: Vec<Multiaddr>,
        keypair: Keypair,
    ) -> Result<Self, NetworkError> {
        let listen_addr = listen_addr.into();
        let node = Node::spawn_with_keypair(&listen_addr, keypair.clone()).await?;
        let stack = Arc::new(RwLock::new(Stack::from_node(node)));
        let bootstrap_peers = Arc::new(bootstrap_peers);

        let supervised = Self {
            stack: stack.clone(),
            listen_addr: listen_addr.clone(),
            bootstrap_peers: bootstrap_peers.clone(),
            keypair: keypair.clone(),
        };
        supervised.dial_bootstrap_peers().await;
        tokio::spawn(supervise(
            stack,
            listen_addr,
            health_check_interval,
            bootstrap_peers,
            keypair,
        ));
        Ok(supervised)
    }

    /// Dials every configured bootstrap peer, logging (not failing on)
    /// each individual dial error — one unreachable bootstrap entry
    /// shouldn't stop the others from being tried.
    async fn dial_bootstrap_peers(&self) {
        for addr in self.bootstrap_peers.iter() {
            if let Err(err) = self.dial(addr.clone()).await {
                tracing::warn!(%addr, %err, "failed to dial bootstrap peer");
            }
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.stack.read().expect(LOCK_POISON_MSG).node.peer_id()
    }

    /// The identity every current and future respawn of this node uses —
    /// random per call unless the caller went through
    /// [`SupervisedNetwork::spawn_with_bootstrap_and_keypair`]. Exposed so
    /// a caller that generated its own keypair (e.g. `daemon`'s
    /// `load_or_create_network_identity`) can confirm what's actually live
    /// without re-deriving `peer_id()` by hand.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
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

    /// Dials another peer so this node's DHT/mailbox actually reaches
    /// them — two `SupervisedNetwork`s spawned independently (as two
    /// separate daemon processes are) start out with empty Kademlia
    /// routing tables and never see each other's records until at least
    /// one side dials the other. Real deployments need a bootstrap-node
    /// list for this; tests dial directly using a peer's own
    /// `listen_addrs()`/`peer_id()`.
    pub async fn dial(&self, addr: libp2p::Multiaddr) -> Result<(), NetworkError> {
        let node = self.stack.read().expect(LOCK_POISON_MSG).node.clone();
        node.dial(addr).await
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

async fn supervise(
    stack: Arc<RwLock<Stack>>,
    listen_addr: String,
    interval: Duration,
    bootstrap_peers: Arc<Vec<Multiaddr>>,
    keypair: Keypair,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip the immediate first tick, node just started

    loop {
        ticker.tick().await;

        let alive = stack.read().expect(LOCK_POISON_MSG).node.is_alive();
        if alive {
            continue;
        }

        tracing::warn!("network event loop died (see docs/THREAT_MODEL.md §3.10) — respawning");
        match Node::spawn_with_keypair(&listen_addr, keypair.clone()).await {
            Ok(node) => {
                *stack.write().expect(LOCK_POISON_MSG) = Stack::from_node(node);
                tracing::info!("network node respawned after failure");
                // A respawned node keeps the same identity (see
                // `spawn_with_bootstrap_and_keypair`'s doc comment) but
                // always starts with an empty Kademlia routing table —
                // without this, a respawn would silently strand the node
                // with no path back to the peers it's configured to know
                // about.
                for addr in bootstrap_peers.iter() {
                    let node = stack.read().expect(LOCK_POISON_MSG).node.clone();
                    if let Err(err) = node.dial(addr.clone()).await {
                        tracing::warn!(
                            %addr,
                            %err,
                            "failed to re-dial bootstrap peer after respawn"
                        );
                    }
                }
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
    async fn two_independently_spawned_networks_can_dial_and_see_each_others_records() {
        let a = SupervisedNetwork::spawn("/ip4/127.0.0.1/tcp/0", Duration::from_secs(60))
            .await
            .unwrap();
        let b = SupervisedNetwork::spawn("/ip4/127.0.0.1/tcp/0", Duration::from_secs(60))
            .await
            .unwrap();

        let a_addr = a
            .listen_addrs()
            .await
            .into_iter()
            .next()
            .unwrap()
            .with_p2p(a.peer_id())
            .unwrap();
        b.dial(a_addr).await.unwrap();

        for attempt in 0..20 {
            match a
                .dht()
                .publish(b"dial-test-key", b"dial-test-value".to_vec())
                .await
            {
                Ok(()) => break,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("publish failed after retries: {e}"),
            }
        }
        let seen = b.dht().lookup(b"dial-test-key").await.unwrap();
        assert_eq!(seen, Some(b"dial-test-value".to_vec()));
    }

    #[tokio::test]
    async fn spawn_with_bootstrap_dials_configured_peers_without_a_manual_dial_call() {
        let a = SupervisedNetwork::spawn("/ip4/127.0.0.1/tcp/0", Duration::from_secs(60))
            .await
            .unwrap();
        let a_addr = a
            .listen_addrs()
            .await
            .into_iter()
            .next()
            .unwrap()
            .with_p2p(a.peer_id())
            .unwrap();

        // Unlike `two_independently_spawned_networks_can_dial_and_see_each_
        // others_records`, this test never calls `b.dial(...)` itself — the
        // bootstrap list passed to `spawn_with_bootstrap` is what's
        // responsible for the connection existing at all.
        let b = SupervisedNetwork::spawn_with_bootstrap(
            "/ip4/127.0.0.1/tcp/0",
            Duration::from_secs(60),
            vec![a_addr],
        )
        .await
        .unwrap();

        for attempt in 0..20 {
            match a
                .dht()
                .publish(b"bootstrap-test-key", b"bootstrap-test-value".to_vec())
                .await
            {
                Ok(()) => break,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("publish failed after retries: {e}"),
            }
        }
        let seen = b.dht().lookup(b"bootstrap-test-key").await.unwrap();
        assert_eq!(seen, Some(b"bootstrap-test-value".to_vec()));
    }

    #[tokio::test]
    async fn supervisor_detects_a_dead_node_and_respawns_a_working_one() {
        let dead = Node::dead_handle_for_test();
        assert!(!dead.is_alive());
        let stack = Arc::new(RwLock::new(Stack::from_node(dead)));
        let keypair = Keypair::generate_ed25519();
        let net = SupervisedNetwork {
            stack: stack.clone(),
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            bootstrap_peers: Arc::new(Vec::new()),
            keypair: keypair.clone(),
        };
        assert!(!net.is_alive(), "sanity check: starts dead");

        tokio::spawn(supervise(
            stack,
            "/ip4/127.0.0.1/tcp/0".to_string(),
            Duration::from_millis(20),
            Arc::new(Vec::new()),
            keypair.clone(),
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

        // The whole point of supplying a keypair: a respawn must not
        // silently mint a new PeerId out from under every peer that
        // dialed this node's old one.
        assert_eq!(net.peer_id(), PeerId::from(keypair.public()));
    }

    #[tokio::test]
    async fn spawn_with_bootstrap_and_keypair_uses_the_supplied_identity() {
        let keypair = Keypair::generate_ed25519();
        let expected = PeerId::from(keypair.public());
        let net = SupervisedNetwork::spawn_with_bootstrap_and_keypair(
            "/ip4/127.0.0.1/tcp/0",
            Duration::from_secs(60),
            Vec::new(),
            keypair,
        )
        .await
        .unwrap();
        assert_eq!(net.peer_id(), expected);
    }
}
