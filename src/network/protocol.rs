//! P2P network protocol implementation

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub::{self, Behaviour as Gossipsub, IdentTopic, MessageAuthenticity},
    identity,
    kad::{store::MemoryStore, Behaviour as Kademlia, Event as KadEvent, Mode as KadMode},
    noise,
    ping::{self, Behaviour as Ping, Event as PingEvent},
    quic,
    request_response::{
        Behaviour as RequestResponse, Event as RequestResponseEvent,
        Message as RequestResponseMessage,
    },
    swarm::{NetworkBehaviour, Swarm},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use log::{debug, info};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::config::Settings;
use crate::types::NodeId;

use super::discovery::PeerRegistry;
use super::heartbeat::{
    create_heartbeat_protocol, HeartbeatCodec, HeartbeatRequest, HeartbeatResponse,
};
use super::message::Message;
use super::req_resp::{create_result_protocol, ResultCodec, ResultRequest, ResultResponse};

// Global topic for all paraloom messages
const PARALOOM_TOPIC: &str = "paraloom/v1";

/// Extract the trailing `/p2p/<peer_id>` component from a
/// multiaddr if present. Used by bootstrap registration to learn
/// the PeerId without dialling first; if the operator gives us a
/// bare network multiaddr (no /p2p/ suffix) we fall back to dial
/// only.
fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            Some(peer_id)
        } else {
            None
        }
    })
}

#[derive(NetworkBehaviour)]
pub struct ParaloomBehaviour {
    pub gossipsub: Gossipsub,
    pub request_response: RequestResponse<ResultCodec>,
    pub heartbeat: RequestResponse<HeartbeatCodec>,
    /// Kademlia DHT for peer discovery (#65). Routing table is
    /// empty at construction; bootstrap registration and periodic
    /// refresh land in subsequent PRs.
    pub kad: Kademlia<MemoryStore>,
    /// libp2p ping for connection-level liveness probes (#65).
    /// Distinct from the application-level heartbeat protocol
    /// used for coordinator HA in #66; this one runs on every
    /// open connection and surfaces RTTs / disconnects to the
    /// swarm event loop. PeerRegistry (#69) integration of these
    /// signals is a follow-up.
    pub ping: Ping,
}

/// Network event handler
#[async_trait]
pub trait NetworkEventHandler: Send + Sync {
    /// Handle a message from the network
    async fn handle_message(&self, source: NodeId, message: Message) -> Result<()>;

    async fn handle_result_request(
        &self,
        _source: NodeId,
        _request: ResultRequest,
    ) -> Result<ResultResponse> {
        log::warn!("Received result request but handler not implemented");
        Ok(ResultResponse {
            success: false,
            message: "Handler not implemented".to_string(),
        })
    }

    /// Handle an inbound coordinator-HA heartbeat. The default
    /// rejects the heartbeat so a node that has not opted into
    /// standby mode does not silently accept primary state.
    async fn handle_heartbeat_request(
        &self,
        _source: NodeId,
        _request: HeartbeatRequest,
    ) -> Result<HeartbeatResponse> {
        log::warn!("Received heartbeat request but handler not implemented");
        Ok(HeartbeatResponse {
            accepted: false,
            last_applied_sequence: 0,
        })
    }
}

/// Network manager
pub struct NetworkManager {
    peer_id: PeerId,
    swarm: Arc<Mutex<Swarm<ParaloomBehaviour>>>,
    message_sender: mpsc::Sender<(NodeId, Message)>,
    message_receiver: Arc<Mutex<mpsc::Receiver<(NodeId, Message)>>>,
    handler: Arc<Mutex<Option<Arc<dyn NetworkEventHandler>>>>,
    connected_peers: Arc<Mutex<Vec<PeerId>>>,
    /// Peer state machine introduced in #69. The swarm event loop
    /// feeds connection establish / close into mark_connected /
    /// mark_disconnected, and ping ok-rtt into record_response.
    /// The slow / offline distinction in #65's acceptance criteria
    /// is enforced here.
    peer_registry: Arc<Mutex<PeerRegistry>>,
}

/// Load a libp2p ed25519 identity from `path` (protobuf-encoded, the format
/// produced by [`identity::Keypair::to_protobuf_encoding`]). If `path` is
/// `None` an ephemeral keypair is returned. If `path` is set but the file does
/// not exist, a fresh keypair is generated and written to the path with mode
/// 0600 (Unix) so subsequent restarts reuse the same PeerId.
///
/// Errors propagate filesystem and protobuf-decode failures rather than
/// silently falling back to a fresh key — a corrupted or unreadable identity
/// file is operator-actionable; silently regenerating would mean published
/// `/p2p/<peerid>` multiaddrs stop resolving without explanation.
fn load_or_create_identity(path: Option<&str>) -> Result<identity::Keypair> {
    use std::fs;
    use std::path::Path;

    let path = match path {
        Some(p) => Path::new(p),
        None => return Ok(identity::Keypair::generate_ed25519()),
    };

    if path.exists() {
        let bytes = fs::read(path)
            .with_context(|| format!("reading libp2p identity from {}", path.display()))?;
        let keypair = identity::Keypair::from_protobuf_encoding(&bytes).with_context(|| {
            format!(
                "decoding libp2p identity at {} (expected protobuf-encoded Keypair; \
                 delete the file to regenerate)",
                path.display()
            )
        })?;
        info!("Loaded persisted libp2p identity from {}", path.display());
        return Ok(keypair);
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating parent directory {}", parent.display()))?;
        }
    }
    let keypair = identity::Keypair::generate_ed25519();
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| anyhow!("encoding libp2p identity to protobuf: {}", e))?;
    fs::write(path, &bytes)
        .with_context(|| format!("writing libp2p identity to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 permissions on {}", path.display()))?;
    }
    info!(
        "Generated new libp2p identity, persisted to {} (PeerId stable across restarts)",
        path.display()
    );
    Ok(keypair)
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(settings: &Settings) -> Result<Self> {
        // Load a persisted libp2p identity if `network.identity_path` is set,
        // otherwise generate a fresh one (and persist it back to the path when
        // configured, so the next restart keeps the same PeerId). Without this,
        // every restart rotates the PeerId — fatal for any node whose
        // `/p2p/<peerid>` multiaddr is published as a bootstrap anchor.
        let local_key = load_or_create_identity(settings.network.identity_path.as_deref())?;
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer ID: {}", local_peer_id);

        // Create TCP transport
        let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(
                noise::Config::new(&local_key).map_err(|e| anyhow!("Noise error: {}", e))?,
            )
            .multiplex(yamux::Config::default())
            .boxed();

        // Create QUIC transport (has built-in encryption)
        let quic_transport = quic::tokio::Transport::new(quic::Config::new(&local_key));

        // Combine TCP and QUIC transports using or_transport
        let transport = tcp_transport
            .or_transport(quic_transport)
            .map(|either, _| match either {
                futures::future::Either::Left((peer_id, muxer)) => {
                    (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer))
                }
                futures::future::Either::Right((peer_id, muxer)) => {
                    (peer_id, libp2p::core::muxing::StreamMuxerBox::new(muxer))
                }
            })
            .boxed();

        // Gossipsub `max_transmit_size` (#69, follow-up to audit #10).
        // The previous value of 10 MiB allowed any peer to flood the
        // network with messages larger than any legitimate paraloom
        // payload — the only realistic gossiped objects are validator
        // status pings, leader announcements, and small
        // verification-request notifications, all well under 1 MiB.
        // A tighter cap shrinks the DoS surface; revisit only if real
        // measurements show a legitimate use case bumping the ceiling.
        const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 1024 * 1024;
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .build()
            .map_err(|e| anyhow!("Failed to build gossipsub config: {}", e))?;

        // Build the Gossipsub behavior
        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow!("Gossipsub error: {}", e))?;

        let request_response = create_result_protocol();
        let heartbeat = create_heartbeat_protocol();

        // Kademlia DHT in Server mode so this node accepts queries
        // from other peers and contributes its routing-table view.
        // Routing table is empty at construction; PRs that follow
        // this one register the bootstrap list and run periodic
        // refresh. The MemoryStore is suitable for v0.5.0; a
        // disk-backed store can be considered for very large
        // validator sets later.
        let kad_store = MemoryStore::new(local_peer_id);
        let mut kad = Kademlia::new(local_peer_id, kad_store);
        kad.set_mode(Some(KadMode::Server));

        // Connection-level ping. interval=15s, timeout=20s — both
        // shorter than libp2p's defaults so a stalled peer is
        // disconnected from the swarm within a window the
        // PeerRegistry's slow/offline distinction (#69) can react
        // to without piling up retries. Tunable later when
        // operational data shows what real deployments need.
        let ping = Ping::new(
            ping::Config::new()
                .with_interval(std::time::Duration::from_secs(15))
                .with_timeout(std::time::Duration::from_secs(20)),
        );

        let behaviour = ParaloomBehaviour {
            gossipsub,
            request_response,
            heartbeat,
            kad,
            ping,
        };

        // Set up message channel
        let (tx, rx) = mpsc::channel(100);

        // Build the Swarm with combined behavior
        let swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );

        Ok(NetworkManager {
            peer_id: local_peer_id,
            swarm: Arc::new(Mutex::new(swarm)),
            message_sender: tx,
            message_receiver: Arc::new(Mutex::new(rx)),
            handler: Arc::new(Mutex::new(None)),
            connected_peers: Arc::new(Mutex::new(Vec::new())),
            peer_registry: Arc::new(Mutex::new(PeerRegistry::new())),
        })
    }

    /// Borrow the peer registry. Public so operational tooling
    /// (the /metrics endpoint, future CLI status commands) can
    /// observe peer state without going through the swarm.
    pub fn peer_registry(&self) -> Arc<Mutex<PeerRegistry>> {
        self.peer_registry.clone()
    }

    /// Set the event handler
    pub async fn set_handler(&self, handler: Arc<dyn NetworkEventHandler>) {
        let mut h = self.handler.lock().await;
        *h = Some(handler);
    }

    /// Connect to bootstrap nodes
    pub async fn connect_to_bootstrap(&self, bootstrap_nodes: Vec<String>) -> Result<()> {
        if bootstrap_nodes.is_empty() {
            info!("No bootstrap nodes configured");
            return Ok(());
        }

        let mut swarm = self.swarm.lock().await;

        for addr_str in bootstrap_nodes {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => {
                    // Extract /p2p/<peer_id> if present so the
                    // address can also be registered in Kademlia's
                    // routing table. Without the suffix the dial
                    // still works, but the DHT cannot use the
                    // bootstrap as a query target. Operators are
                    // expected to publish full multiaddrs
                    // including /p2p/<peer_id>; an address without
                    // the suffix gets a warn log and is dialled
                    // but not added to kad.
                    let peer_id = peer_id_from_multiaddr(&addr);
                    if let Some(pid) = peer_id {
                        swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                        info!("Registered bootstrap {} in Kademlia routing table", pid);
                    } else {
                        log::warn!(
                            "Bootstrap address {} has no /p2p/<peer_id>; dialled but not in kad",
                            addr
                        );
                    }
                    info!("Dialing bootstrap node: {}", addr);
                    if let Err(e) = swarm.dial(addr.clone()) {
                        log::warn!("Failed to dial {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    log::warn!("Invalid bootstrap address {}: {}", addr_str, e);
                }
            }
        }

        Ok(())
    }

    /// Start the network manager
    pub async fn start(&self, listen_address: Multiaddr) -> Result<()> {
        let mut swarm = self.swarm.lock().await;

        // Subscribe to the paraloom topic
        let topic = IdentTopic::new(PARALOOM_TOPIC);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| anyhow!("Failed to subscribe to topic: {}", e))?;
        info!("Subscribed to topic: {}", PARALOOM_TOPIC);

        // Listen on the given address
        swarm.listen_on(listen_address.clone())?;
        info!("Listening on {}", listen_address);

        // Clone values for the task
        let swarm_clone = self.swarm.clone();
        let receiver_clone = self.message_receiver.clone();
        let handler_clone = self.handler.clone();
        let connected_peers_clone = self.connected_peers.clone();
        let peer_registry_clone = self.peer_registry.clone();

        // Spawn task to handle events
        tokio::spawn(async move {
            Self::run_event_loop(
                swarm_clone,
                receiver_clone,
                handler_clone,
                connected_peers_clone,
                peer_registry_clone,
            )
            .await;
        });

        Ok(())
    }

    /// Run the event loop
    async fn run_event_loop(
        swarm: Arc<Mutex<Swarm<ParaloomBehaviour>>>,
        receiver: Arc<Mutex<mpsc::Receiver<(NodeId, Message)>>>,
        handler: Arc<Mutex<Option<Arc<dyn NetworkEventHandler>>>>,
        connected_peers: Arc<Mutex<Vec<PeerId>>>,
        peer_registry: Arc<Mutex<PeerRegistry>>,
    ) {
        info!("Starting network event loop");

        loop {
            tokio::select! {
                // Handle Swarm events
                event = async {
                    let mut swarm_lock = swarm.lock().await;
                    swarm_lock.next().await
                } => {
                    match event {
                        Some(event) => {
                            // Log important events at info level
                            match event {
                                libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                    info!("Connection established with peer: {}", peer_id);

                                    // Add to connected peers list
                                    let mut peers = connected_peers.lock().await;
                                    if !peers.contains(&peer_id) {
                                        peers.push(peer_id);
                                    }
                                    drop(peers);

                                    // Mirror into the PeerRegistry state
                                    // machine so the slow / offline
                                    // distinction has live data.
                                    let mut registry = peer_registry.lock().await;
                                    registry.mark_connected(NodeId(peer_id.to_bytes()));
                                }
                                libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                    info!("Connection closed with peer: {} (cause: {:?})", peer_id, cause);

                                    // Remove from connected peers list
                                    let mut peers = connected_peers.lock().await;
                                    peers.retain(|p| p != &peer_id);
                                    drop(peers);

                                    let mut registry = peer_registry.lock().await;
                                    registry.mark_disconnected(NodeId(peer_id.to_bytes()));
                                }
                                libp2p::swarm::SwarmEvent::IncomingConnection { .. } => {
                                    info!("Incoming connection");
                                }
                                libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                    log::warn!("Outgoing connection error to {:?}: {}", peer_id, error);
                                }
                                libp2p::swarm::SwarmEvent::Dialing { peer_id, connection_id: _ } => {
                                    info!("Dialing peer: {:?}", peer_id);
                                }
                                libp2p::swarm::SwarmEvent::Behaviour(behaviour_event) => {
                                    match behaviour_event {
                                        ParaloomBehaviourEvent::Gossipsub(gossip_event) => {
                                            if let gossipsub::Event::Message {
                                                propagation_source: peer_id,
                                                message,
                                                ..
                                            } = gossip_event {
                                                info!("Received gossipsub message from peer: {}", peer_id);

                                                // Deserialize the message
                                                match bincode::deserialize::<Message>(&message.data) {
                                                    Ok(msg) => {
                                                        let source = NodeId(peer_id.to_bytes());
                                                        let handler_lock = handler.lock().await;
                                                        if let Some(h) = handler_lock.as_ref() {
                                                            if let Err(e) = h.handle_message(source, msg).await {
                                                                log::error!("Error handling message: {}", e);
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        log::error!("Failed to deserialize message: {}", e);
                                                    }
                                                }
                                            } else {
                                                debug!("Gossipsub event: {:?}", gossip_event);
                                            }
                                        }

                                        ParaloomBehaviourEvent::RequestResponse(req_resp_event) => {
                                            match req_resp_event {
                                                RequestResponseEvent::Message { peer, message, connection_id: _ } => {
                                                    match message {
                                                        RequestResponseMessage::Request { request, channel, .. } => {
                                                            info!("=== RECEIVED RESULT REQUEST ===");
                                                            info!("From validator: {}", peer);
                                                            info!("Task ID: {}", request.result.task_id);

                                                            let source = NodeId(peer.to_bytes());
                                                            let handler_lock = handler.lock().await;

                                                            let response = if let Some(h) = handler_lock.as_ref() {
                                                                match h.handle_result_request(source, request).await {
                                                                    Ok(resp) => {
                                                                        info!("Handler processed result successfully");
                                                                        resp
                                                                    }
                                                                    Err(e) => {
                                                                        log::error!("Error handling result request: {}", e);
                                                                        ResultResponse {
                                                                            success: false,
                                                                            message: format!("Error: {}", e),
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                log::warn!("No handler registered");
                                                                ResultResponse {
                                                                    success: false,
                                                                    message: "No handler registered".to_string(),
                                                                }
                                                            };

                                                            info!("Sending response: success={}", response.success);
                                                            let mut swarm_lock = swarm.lock().await;
                                                            if let Err(e) = swarm_lock.behaviour_mut().request_response.send_response(channel, response) {
                                                                log::error!("Failed to send response: {:?}", e);
                                                            } else {
                                                                info!("=== RESPONSE SENT ===");
                                                            }
                                                        }

                                                        RequestResponseMessage::Response { response, .. } => {
                                                            info!("=== RECEIVED RESPONSE FROM COORDINATOR ===");
                                                            info!("Success: {}, Message: {}", response.success, response.message);
                                                        }
                                                    }
                                                }
                                                RequestResponseEvent::OutboundFailure { peer, request_id, error, connection_id: _ } => {
                                                    log::error!("=== REQUEST-RESPONSE OUTBOUND FAILURE ===");
                                                    log::error!("Peer: {:?}", peer);
                                                    log::error!("Request ID: {:?}", request_id);
                                                    log::error!("Error: {:?}", error);
                                                }
                                                RequestResponseEvent::InboundFailure { peer, request_id, error, connection_id: _ } => {
                                                    log::error!("=== REQUEST-RESPONSE INBOUND FAILURE ===");
                                                    log::error!("Peer: {:?}", peer);
                                                    log::error!("Request ID: {:?}", request_id);
                                                    log::error!("Error: {:?}", error);
                                                }
                                                RequestResponseEvent::ResponseSent { peer, request_id, connection_id: _ } => {
                                                    info!("=== RESPONSE SENT SUCCESSFULLY ===");
                                                    info!("To peer: {}", peer);
                                                    info!("Request ID: {:?}", request_id);
                                                }
                                            }
                                        }

                                        ParaloomBehaviourEvent::Heartbeat(hb_event) => {
                                            match hb_event {
                                                RequestResponseEvent::Message { peer, message, connection_id: _ } => {
                                                    match message {
                                                        RequestResponseMessage::Request { request, channel, .. } => {
                                                            let source = NodeId(peer.to_bytes());
                                                            let handler_lock = handler.lock().await;
                                                            let response = if let Some(h) = handler_lock.as_ref() {
                                                                match h.handle_heartbeat_request(source, request).await {
                                                                    Ok(resp) => resp,
                                                                    Err(e) => {
                                                                        log::error!("heartbeat handler error: {}", e);
                                                                        HeartbeatResponse {
                                                                            accepted: false,
                                                                            last_applied_sequence: 0,
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                HeartbeatResponse {
                                                                    accepted: false,
                                                                    last_applied_sequence: 0,
                                                                }
                                                            };
                                                            drop(handler_lock);
                                                            let mut swarm_lock = swarm.lock().await;
                                                            if let Err(e) = swarm_lock.behaviour_mut().heartbeat.send_response(channel, response) {
                                                                log::error!("Failed to send heartbeat response: {:?}", e);
                                                            }
                                                        }
                                                        RequestResponseMessage::Response { response, .. } => {
                                                            debug!(
                                                                "heartbeat response: accepted={}, last_applied={}",
                                                                response.accepted, response.last_applied_sequence
                                                            );
                                                        }
                                                    }
                                                }
                                                RequestResponseEvent::OutboundFailure { peer, error, .. } => {
                                                    log::warn!(
                                                        "heartbeat outbound failure to {:?}: {:?}",
                                                        peer, error
                                                    );
                                                }
                                                RequestResponseEvent::InboundFailure { peer, error, .. } => {
                                                    log::warn!(
                                                        "heartbeat inbound failure from {:?}: {:?}",
                                                        peer, error
                                                    );
                                                }
                                                RequestResponseEvent::ResponseSent { peer, .. } => {
                                                    debug!("heartbeat response sent to {}", peer);
                                                }
                                            }
                                        }

                                        ParaloomBehaviourEvent::Kad(kad_event) => {
                                            match kad_event {
                                                KadEvent::RoutingUpdated { peer, .. } => {
                                                    debug!("kad routing table updated with peer {}", peer);
                                                }
                                                KadEvent::OutboundQueryProgressed { id, result, .. } => {
                                                    debug!("kad query {:?} progressed: {:?}", id, result);
                                                }
                                                other => {
                                                    debug!("kad event: {:?}", other);
                                                }
                                            }
                                        }

                                        ParaloomBehaviourEvent::Ping(ping_event) => {
                                            match ping_event {
                                                PingEvent { peer, result: Ok(rtt), .. } => {
                                                    debug!("ping ok: peer {} rtt {:?}", peer, rtt);
                                                    // Feed the rtt into the
                                                    // PeerRegistry so the
                                                    // slow-vs-offline
                                                    // distinction has data.
                                                    let mut registry = peer_registry.lock().await;
                                                    registry.record_response(
                                                        &NodeId(peer.to_bytes()),
                                                        rtt,
                                                    );
                                                }
                                                PingEvent { peer, result: Err(e), .. } => {
                                                    log::warn!("ping failed: peer {} error {:?}", peer, e);
                                                    // libp2p will close the
                                                    // connection on repeated
                                                    // ping failures, which
                                                    // surfaces as a
                                                    // ConnectionClosed event
                                                    // and triggers the
                                                    // mark_disconnected path
                                                    // above. No direct call
                                                    // here to avoid double-
                                                    // counting transient
                                                    // failures.
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    debug!("Swarm event: {:?}", event);
                                }
                            }
                        }
                        None => break,
                    }
                },

                // Handle outgoing messages - publish to gossipsub
                message = async {
                    let mut receiver = receiver.lock().await;
                    receiver.recv().await
                } => {
                    match message {
                        Some((_target, message)) => {
                            // Serialize the message
                            match bincode::serialize(&message) {
                                Ok(data) => {
                                    let topic = IdentTopic::new(PARALOOM_TOPIC);
                                    let mut swarm_lock = swarm.lock().await;
                                    if let Err(e) = swarm_lock.behaviour_mut().gossipsub.publish(topic, data) {
                                        log::error!("Failed to publish message: {}", e);
                                    } else {
                                        info!("Published message to gossipsub");
                                    }
                                }
                                Err(e) => {
                                    log::error!("Failed to serialize message: {}", e);
                                }
                            }
                        },
                        None => break,
                    }
                }
            }
        }

        info!("Network event loop terminated");
    }

    /// Send a message to a peer (broadcasts via gossipsub)
    pub async fn send_message(&self, _peer: NodeId, message: Message) -> Result<()> {
        self.message_sender
            .send((NodeId(vec![]), message))
            .await
            .map_err(|e| anyhow!("Failed to send message: {}", e))
    }

    pub async fn send_result_request(&self, peer: NodeId, request: ResultRequest) -> Result<()> {
        let peer_id = PeerId::from_bytes(&peer.0).map_err(|e| anyhow!("Invalid peer ID: {}", e))?;

        info!("=== SENDING RESULT REQUEST ===");
        info!("Target peer: {}", peer_id);
        info!("Task ID: {}", request.result.task_id);

        let mut swarm = self.swarm.lock().await;

        // Check if peer is connected
        let is_connected = swarm.is_connected(&peer_id);
        info!("Is peer connected? {}", is_connected);

        let request_id = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, request);

        info!("Request ID: {:?}", request_id);
        info!("=== REQUEST SENT ===");
        Ok(())
    }

    /// Send a coordinator-HA heartbeat to a standby. Fire-and-forget
    /// at the request level: the response (an ack with the standby's
    /// last applied sequence) is observed via the swarm event loop
    /// rather than awaited synchronously here, so a slow standby
    /// cannot back-pressure the primary's broadcast cadence.
    pub async fn send_heartbeat_request(
        &self,
        peer: NodeId,
        request: HeartbeatRequest,
    ) -> Result<()> {
        let peer_id = PeerId::from_bytes(&peer.0).map_err(|e| anyhow!("Invalid peer ID: {}", e))?;
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .heartbeat
            .send_request(&peer_id, request);
        Ok(())
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> NodeId {
        NodeId(self.peer_id.to_bytes())
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<NodeId> {
        let peers = self.connected_peers.lock().await;
        peers.iter().map(|p| NodeId(p.to_bytes())).collect()
    }

    /// Spawn a tokio task that periodically asks Kademlia to
    /// refresh its routing table.
    ///
    /// Bootstrap walks the local routing table by issuing a query
    /// for the local peer's own id, which finds the closest peers
    /// in the DHT and refreshes their entries. Without periodic
    /// refresh, a routing-table entry whose underlying connection
    /// silently died would linger and queries through it would
    /// time out instead of hopping to a healthier neighbour.
    ///
    /// `interval` should be on the order of minutes; libp2p's own
    /// guidance suggests 5 minutes for healthy networks. The
    /// returned JoinHandle lets the caller `abort()` on shutdown.
    pub fn start_kad_bootstrap_refresh(
        self: Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Skip the immediate first tick so the very first
            // bootstrap attempt happens after `interval`, by which
            // time the swarm event loop is up and the routing
            // table has at least the bootstrap entries from
            // connect_to_bootstrap.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let mut swarm = self.swarm.lock().await;
                match swarm.behaviour_mut().kad.bootstrap() {
                    Ok(query_id) => {
                        debug!("kad bootstrap refresh kicked off ({:?})", query_id);
                    }
                    Err(e) => {
                        log::warn!("kad bootstrap refresh failed to start: {}", e);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_extracted_from_multiaddr_with_p2p_suffix() {
        let key = identity::Keypair::generate_ed25519();
        let expected = PeerId::from(key.public());
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/9000/p2p/{}", expected)
            .parse()
            .expect("multiaddr parses");
        assert_eq!(peer_id_from_multiaddr(&addr), Some(expected));
    }

    #[test]
    fn peer_id_returns_none_for_bare_multiaddr() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().expect("multiaddr parses");
        assert_eq!(peer_id_from_multiaddr(&addr), None);
    }

    #[tokio::test]
    async fn fresh_network_manager_has_empty_peer_registry() {
        let mgr = NetworkManager::new(&Settings::development()).expect("network manager");
        let registry = mgr.peer_registry();
        let registry = registry.lock().await;
        assert_eq!(registry.len(), 0, "fresh registry holds no peers");
        assert!(
            registry.peers_due_for_reconnect().is_empty(),
            "no pending reconnects in a fresh registry"
        );
    }

    #[tokio::test]
    async fn empty_bootstrap_list_succeeds_without_warning() {
        let mgr = NetworkManager::new(&Settings::development()).expect("network manager");
        mgr.connect_to_bootstrap(Vec::new())
            .await
            .expect("empty bootstrap is a no-op");
    }

    #[tokio::test]
    async fn malformed_bootstrap_address_does_not_error() {
        let mgr = NetworkManager::new(&Settings::development()).expect("network manager");
        // The function logs a warn and skips the bad address; the
        // overall call must still succeed so a single typo in the
        // operator's bootstrap list does not prevent node startup.
        mgr.connect_to_bootstrap(vec!["not-a-multiaddr".to_string()])
            .await
            .expect("malformed addresses surface as warn, not Err");
    }

    #[test]
    fn identity_persists_across_calls_when_path_set() {
        // Pins the anchor-onboarding contract: a node configured with a
        // persistent identity_path must surface the SAME PeerId on every
        // start-up. A regression here would silently invalidate every
        // published `/p2p/<peerid>` multiaddr the moment the anchor restarts.
        let tmp = std::env::temp_dir().join(format!(
            "paraloom-identity-test-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_str = tmp.to_string_lossy().to_string();

        // First call: file does not exist → generate + persist.
        let key1 = load_or_create_identity(Some(&path_str)).expect("first generate");
        let peer1 = PeerId::from(key1.public());
        assert!(tmp.exists(), "identity file must be created on first call");

        // Second call: file exists → load back the same keypair.
        let key2 = load_or_create_identity(Some(&path_str)).expect("second load");
        let peer2 = PeerId::from(key2.public());
        assert_eq!(peer1, peer2, "PeerId must be stable across restarts");

        // Cleanup.
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn identity_is_ephemeral_when_path_unset() {
        // Without an identity_path the old behaviour is preserved: every
        // call yields a fresh ephemeral keypair. Pins the opt-in nature of
        // the feature so existing test/demo configs are not silently
        // re-routed to write key material into the cwd.
        let key1 = load_or_create_identity(None).expect("ephemeral 1");
        let key2 = load_or_create_identity(None).expect("ephemeral 2");
        assert_ne!(
            PeerId::from(key1.public()),
            PeerId::from(key2.public()),
            "ephemeral identities must differ between calls"
        );
    }

    #[test]
    fn corrupted_identity_file_returns_error() {
        // A garbled identity file is operator-actionable; silently
        // regenerating would mean published `/p2p/<peerid>` multiaddrs
        // stop resolving without explanation. Pins the "fail loud" contract.
        let tmp = std::env::temp_dir().join(format!(
            "paraloom-identity-corrupt-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&tmp, b"this is not a protobuf-encoded libp2p keypair")
            .expect("write corrupted file");
        let result = load_or_create_identity(Some(&tmp.to_string_lossy()));
        assert!(
            result.is_err(),
            "corrupted identity must error, not regenerate"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
