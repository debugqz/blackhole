//! libp2p transport + swarm plumbing: TCP with Noise encryption and Yamux
//! multiplexing, Kademlia DHT, and Identify (used to populate Kademlia's
//! routing table with addresses learned from peers we connect to). See
//! `docs/SPEC.md` §5.1-5.2.
//!
//! STUN/TURN proper (§5.1) aren't wired in — libp2p's `relay`/`dcutr`
//! behaviours cover the same hole-punching role and are a natural
//! follow-up once real NAT traversal is being tested against a public
//! relay, which isn't feasible in this environment.
//!
//! [`Node`] runs the swarm as a background task and exposes an async
//! command interface, which is the standard shape for a rust-libp2p
//! application (the `Swarm` itself is not `Send`-friendly to share
//! directly across the daemon's request handlers).

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad;
use libp2p::kad::store::{MemoryStore, MemoryStoreConfig};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identify, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
use tokio::sync::{mpsc, oneshot};

use crate::routing_admission::RoutingAdmission;
use crate::NetworkError;

const PROTOCOL_VERSION: &str = "/blackhole/0.1.0";

/// Ceiling for a single DHT record's wire size (both `kad::Config`'s
/// packet-size limit and `MemoryStoreConfig`'s value-size limit are set to
/// this). `libp2p-kad`'s own default packet-size cap
/// (`protocol::DEFAULT_MAX_PACKET_SIZE`) is only 16KiB — far below its
/// *store's* own default 64KiB value cap, so the packet limit was the one
/// that actually bound in practice. A real call-signal `Offer`'s SDP (many
/// ICE host candidates) plus a first-contact X3DH `InitialMessage`
/// comfortably clears 16KiB but stays well under this; `envelope.rs`'s own
/// largest size bucket (64KiB) plus sealed-sender/ratchet framing overhead
/// is the actual worst case this needs to fit, hence the headroom above a
/// plain 64KiB round number.
const MAX_DHT_RECORD_BYTES: usize = 128 * 1024;

#[derive(NetworkBehaviour)]
struct Behaviour {
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
}

type PendingGetRecord =
    HashMap<kad::QueryId, oneshot::Sender<Result<Option<Vec<u8>>, NetworkError>>>;
type PendingPutRecord = HashMap<kad::QueryId, oneshot::Sender<Result<(), NetworkError>>>;

enum Command {
    Dial {
        addr: Multiaddr,
        resp: oneshot::Sender<Result<(), NetworkError>>,
    },
    ListenAddrs {
        resp: oneshot::Sender<Vec<Multiaddr>>,
    },
    PutRecord {
        key: Vec<u8>,
        value: Vec<u8>,
        resp: oneshot::Sender<Result<(), NetworkError>>,
    },
    GetRecord {
        key: Vec<u8>,
        resp: oneshot::Sender<Result<Option<Vec<u8>>, NetworkError>>,
    },
}

/// A running libp2p node. Cheap to clone — clones share the same
/// underlying swarm task via a channel.
#[derive(Clone)]
pub struct Node {
    local_peer_id: PeerId,
    command_tx: mpsc::Sender<Command>,
}

impl Node {
    /// Starts a node listening on `listen_addr` (e.g.
    /// `/ip4/127.0.0.1/tcp/0` to let the OS pick a free port).
    pub async fn spawn(listen_addr: &str) -> Result<Self, NetworkError> {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                // `libp2p_yamux::Config::default()` resolves to the fixed
                // 0.13.10 yamux core, not the vulnerable 0.12.1 one
                // `libp2p-yamux` also bundles for legacy API compatibility
                // — see docs/THREAT_MODEL.md §3.10 for the verified
                // finding. Do not add any `yamux::WindowUpdateMode`-based
                // config here; that's the only API surface that switches
                // to the vulnerable core, and it's `#[deprecated]`
                // upstream so CI's `-D warnings` would already catch it.
                yamux::Config::default,
            )
            .map_err(|e| NetworkError::Setup(e.to_string()))?
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();
                let store = MemoryStore::with_config(
                    peer_id,
                    MemoryStoreConfig {
                        max_value_bytes: MAX_DHT_RECORD_BYTES,
                        ..MemoryStoreConfig::default()
                    },
                );
                let mut kad_config = kad::Config::default();
                kad_config.set_max_packet_size(MAX_DHT_RECORD_BYTES);
                let mut kad = kad::Behaviour::with_config(peer_id, store, kad_config);
                // Kademlia starts in Client mode and only auto-promotes to
                // Server once it has a *confirmed external* address, which
                // never happens on loopback. Every Blackhole node should
                // participate in routing/storage for others by default —
                // this is a P2P mailbox network, not a client/server app —
                // so force Server mode rather than rely on that heuristic.
                kad.set_mode(Some(kad::Mode::Server));
                let identify = identify::Behaviour::new(identify::Config::new(
                    PROTOCOL_VERSION.to_string(),
                    key.public(),
                ));
                Behaviour { kad, identify }
            })
            .map_err(|e| NetworkError::Setup(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let local_peer_id = *swarm.local_peer_id();

        let addr: Multiaddr = listen_addr
            .parse()
            .map_err(|_| NetworkError::Setup(format!("invalid listen address: {listen_addr}")))?;
        swarm
            .listen_on(addr)
            .map_err(|e| NetworkError::Setup(e.to_string()))?;

        let (command_tx, command_rx) = mpsc::channel(32);
        tokio::spawn(run_event_loop(swarm, command_rx));

        Ok(Self {
            local_peer_id,
            command_tx,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// `false` once the background swarm event loop has stopped running —
    /// e.g. after an unrecoverable panic inside `libp2p` itself (this
    /// used to cite the yamux CVE, docs/THREAT_MODEL.md §3.10, as the
    /// motivating example — corrected: that specific bug isn't reachable
    /// through the yamux core this node actually runs, see the comment on
    /// `yamux::Config::default` above; this check guards against any
    /// future panic in the event loop, not that one specifically).
    /// A `tokio::spawn`ed task panicking doesn't crash the process, but it
    /// does drop everything the task owned — including `command_rx` here
    /// — which is exactly what this checks: `mpsc::Sender::is_closed` is
    /// `true` once its paired receiver is gone, no round-trip needed. Once
    /// this is `false`, every other method on this `Node` will return
    /// `NetworkError::NodeShutDown` forever; see [`crate::supervised`] for
    /// a wrapper that respawns a fresh `Node` when that happens.
    pub fn is_alive(&self) -> bool {
        !self.command_tx.is_closed()
    }

    /// Test-only: builds a `Node` handle around an already-dead channel
    /// (its receiver dropped), to exercise supervisor failure-detection
    /// without needing to reproduce a real libp2p panic.
    #[cfg(test)]
    pub(crate) fn dead_handle_for_test() -> Self {
        let (command_tx, command_rx) = mpsc::channel(1);
        drop(command_rx);
        Self {
            local_peer_id: PeerId::random(),
            command_tx,
        }
    }

    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        let (resp, rx) = oneshot::channel();
        if self
            .command_tx
            .send(Command::ListenAddrs { resp })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NetworkError> {
        let (resp, rx) = oneshot::channel();
        self.command_tx
            .send(Command::Dial { addr, resp })
            .await
            .map_err(|_| NetworkError::NodeShutDown)?;
        rx.await.map_err(|_| NetworkError::NodeShutDown)?
    }

    pub async fn put_record(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), NetworkError> {
        let (resp, rx) = oneshot::channel();
        self.command_tx
            .send(Command::PutRecord { key, value, resp })
            .await
            .map_err(|_| NetworkError::NodeShutDown)?;
        rx.await.map_err(|_| NetworkError::NodeShutDown)?
    }

    pub async fn get_record(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, NetworkError> {
        let (resp, rx) = oneshot::channel();
        self.command_tx
            .send(Command::GetRecord { key, resp })
            .await
            .map_err(|_| NetworkError::NodeShutDown)?;
        rx.await.map_err(|_| NetworkError::NodeShutDown)?
    }
}

async fn run_event_loop(mut swarm: Swarm<Behaviour>, mut command_rx: mpsc::Receiver<Command>) {
    let mut listen_addrs: Vec<Multiaddr> = Vec::new();
    let mut listen_addr_waiters: Vec<oneshot::Sender<Vec<Multiaddr>>> = Vec::new();
    let mut pending_get: PendingGetRecord = HashMap::new();
    let mut pending_put: PendingPutRecord = HashMap::new();
    let mut routing_admission = RoutingAdmission::new();

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &mut listen_addrs,
                    &mut listen_addr_waiters,
                    &mut pending_get,
                    &mut pending_put,
                    &mut routing_admission,
                );
            }
            command = command_rx.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Dial { addr, resp } => {
                        let result = swarm
                            .dial(addr)
                            .map_err(|e| NetworkError::Dial(e.to_string()));
                        let _ = resp.send(result);
                    }
                    Command::ListenAddrs { resp } => {
                        if listen_addrs.is_empty() {
                            listen_addr_waiters.push(resp);
                        } else {
                            let _ = resp.send(listen_addrs.clone());
                        }
                    }
                    Command::PutRecord { key, value, resp } => {
                        let record = kad::Record::new(key, value);
                        match swarm.behaviour_mut().kad.put_record(record, kad::Quorum::One) {
                            Ok(id) => {
                                pending_put.insert(id, resp);
                            }
                            Err(e) => {
                                let _ = resp.send(Err(NetworkError::Setup(e.to_string())));
                            }
                        }
                    }
                    Command::GetRecord { key, resp } => {
                        let id = swarm.behaviour_mut().kad.get_record(key.into());
                        pending_get.insert(id, resp);
                    }
                }
            }
        }
    }
}

fn handle_swarm_event(
    event: SwarmEvent<BehaviourEvent>,
    swarm: &mut Swarm<Behaviour>,
    listen_addrs: &mut Vec<Multiaddr>,
    listen_addr_waiters: &mut Vec<oneshot::Sender<Vec<Multiaddr>>>,
    pending_get: &mut PendingGetRecord,
    pending_put: &mut PendingPutRecord,
    routing_admission: &mut RoutingAdmission,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            listen_addrs.push(address);
            for waiter in listen_addr_waiters.drain(..) {
                let _ = waiter.send(listen_addrs.clone());
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            // Routing-table admission control (docs/THREAT_MODEL.md §3.5):
            // don't let one address block flood the table with Sybil peer
            // ids. This is the only place peers get into Kademlia's
            // routing table at all, so it's the right — and only —
            // interception point, rather than wrapping the whole
            // `NetworkBehaviour`.
            for addr in info.listen_addrs {
                if routing_admission.try_admit(peer_id, &addr) {
                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                }
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
            id,
            result,
            ..
        })) => match result {
            kad::QueryResult::GetRecord(res) => {
                if let Some(sender) = pending_get.remove(&id) {
                    let value = match res {
                        Ok(kad::GetRecordOk::FoundRecord(peer_record)) => {
                            Ok(Some(peer_record.record.value))
                        }
                        Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => Ok(None),
                        Err(kad::GetRecordError::NotFound { .. }) => Ok(None),
                        Err(e) => Err(NetworkError::Query(e.to_string())),
                    };
                    let _ = sender.send(value);
                }
            }
            kad::QueryResult::PutRecord(res) => {
                if let Some(sender) = pending_put.remove(&id) {
                    let result = res
                        .map(|_| ())
                        .map_err(|e| NetworkError::Query(e.to_string()));
                    let _ = sender.send(result);
                }
            }
            _ => {}
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    async fn spawn_pair() -> (Node, Node) {
        let a = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let b = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();

        let a_addr = a.listen_addrs().await.into_iter().next().unwrap();
        let a_addr_with_peer = a_addr.with_p2p(a.peer_id()).unwrap();
        b.dial(a_addr_with_peer).await.unwrap();

        // Give the identify exchange a moment to populate both routing
        // tables before the test issues DHT queries.
        tokio::time::sleep(Duration::from_millis(300)).await;
        (a, b)
    }

    /// `put_record`'s quorum can only be satisfied once identify has
    /// finished populating both sides' Kademlia routing tables with each
    /// other's address, which races with the fixed sleep in
    /// `spawn_pair` — so retry a few times rather than assume one sleep is
    /// always enough.
    async fn put_record_with_retry(node: &Node, key: Vec<u8>, value: Vec<u8>) {
        for attempt in 0..20 {
            match node.put_record(key.clone(), value.clone()).await {
                Ok(()) => return,
                Err(_) if attempt < 19 => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(e) => panic!("put_record failed after retries: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn two_nodes_dial_and_exchange_a_dht_record() {
        let (a, b) = spawn_pair().await;

        put_record_with_retry(&a, b"greeting".to_vec(), b"hello from node a".to_vec()).await;

        let value = timeout(Duration::from_secs(5), b.get_record(b"greeting".to_vec()))
            .await
            .expect("query timed out")
            .unwrap();

        assert_eq!(value, Some(b"hello from node a".to_vec()));
    }

    #[tokio::test]
    async fn get_record_on_an_unknown_key_returns_none() {
        let (_a, b) = spawn_pair().await;
        let value = timeout(
            Duration::from_secs(5),
            b.get_record(b"never-published".to_vec()),
        )
        .await
        .expect("query timed out")
        .unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn node_reports_a_listen_address() {
        let node = Node::spawn("/ip4/127.0.0.1/tcp/0").await.unwrap();
        let addrs = node.listen_addrs().await;
        assert!(!addrs.is_empty());
    }
}
