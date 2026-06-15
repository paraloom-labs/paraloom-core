//! P2P network protocol implementation

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::{
    autonat, dcutr,
    gossipsub::{self, Behaviour as Gossipsub, IdentTopic, MessageAuthenticity},
    identify, identity,
    kad::{store::MemoryStore, Behaviour as Kademlia, Event as KadEvent, Mode as KadMode},
    noise,
    ping::{self, Behaviour as Ping, Event as PingEvent},
    relay,
    request_response::{
        Behaviour as RequestResponse, Event as RequestResponseEvent,
        Message as RequestResponseMessage, OutboundRequestId,
    },
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, Swarm},
    tcp, yamux, Multiaddr, PeerId,
};
use log::{debug, info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::config::Settings;
use crate::types::NodeId;

use super::cosign::{create_cosign_protocol, CoSignCodec, CoSignRequest, CoSignResponse};
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
    /// Settlement co-signing protocol (#260). The round leader sends each
    /// approving validator a `CoSignRequest` carrying the unsigned settlement
    /// transaction message and collects their signatures to satisfy the
    /// on-chain validator quorum.
    pub cosign: RequestResponse<CoSignCodec>,
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
    /// AutoNAT v1 (#226). Always present: every node probes peers to
    /// learn whether its own listen addresses are publicly reachable
    /// (`NatStatus::Public`) or it sits behind a NAT
    /// (`NatStatus::Private`). The status drives the relay-client
    /// decision in PR-B; here in PR-A it confirms external addresses
    /// so other peers learn how to dial this node.
    pub autonat: autonat::Behaviour,
    /// Circuit-relay v2 *server* (#226), gated on
    /// `network.enable_relay_server`. A `Toggle` so a node that does
    /// not opt in carries no relay-server state machine at all —
    /// only public, dialable anchors should accept reservations and
    /// forward circuits on behalf of NATed peers.
    pub relay: Toggle<relay::Behaviour>,
    /// Circuit-relay v2 *client* (#226). Always present: when this
    /// node sits behind a NAT it reserves a slot on a relay server
    /// and listens on the resulting `/<relay>/p2p-circuit` address so
    /// peers can reach it through the relay. The behaviour is injected
    /// by `SwarmBuilder::with_relay_client`, which also weaves the
    /// matching relay transport into the swarm.
    pub relay_client: relay::client::Behaviour,
    /// Direct Connection Upgrade through Relay (#226). Once a relayed
    /// circuit is established, DCUtR coordinates a simultaneous-open
    /// hole punch to upgrade it to a direct connection, dropping the
    /// relay from the hot path when the NAT allows it.
    pub dcutr: dcutr::Behaviour,
    /// libp2p identify (#226). Required for DCUtR and AutoNAT to work:
    /// it tells each peer the address the *other* side observes it on,
    /// which the swarm records as an external-address candidate. DCUtR
    /// needs that observed address to coordinate the hole punch — without
    /// identify the hole-punch attempt fails immediately with
    /// `NoAddresses`. Also lets peers learn each other's protocol set.
    pub identify: identify::Behaviour,
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

    /// Handle an inbound settlement co-sign request (#260). The default
    /// declines (`signature: None`) so a node that has not opted into
    /// validator co-signing never signs a settlement it cannot vouch for; the
    /// verify-then-sign implementation lives on the node.
    async fn handle_cosign_request(
        &self,
        _source: NodeId,
        request: CoSignRequest,
    ) -> Result<CoSignResponse> {
        log::warn!("Received cosign request but handler not implemented");
        Ok(CoSignResponse {
            request_id: request.request_id,
            wallet_pubkey: String::new(),
            signature: None,
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
    /// Outstanding co-sign requests this node sent as round leader (#260),
    /// keyed by the libp2p outbound request id. `send_cosign_request` inserts a
    /// oneshot here and awaits it; the event loop completes it when the matching
    /// response arrives, or drops it on outbound failure / timeout so the
    /// awaiter errors instead of hanging.
    cosign_waiters: Arc<Mutex<HashMap<OutboundRequestId, oneshot::Sender<CoSignResponse>>>>,
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
        let cosign = create_cosign_protocol();

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

        // AutoNAT (#226): probe peers to discover our own reachability.
        // Always on — the status it produces is what lets PR-B decide
        // whether this node needs to listen via a relay, and in the
        // meantime it confirms external addresses so peers can dial us.
        let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

        // Circuit-relay v2 server (#226), opt-in. Only a public anchor
        // should forward traffic for NATed peers; everyone else carries
        // a disabled `Toggle` and accepts no reservations.
        let relay = if settings.network.enable_relay_server {
            info!("Relay server enabled — forwarding circuits for NATed peers");
            Toggle::from(Some(relay::Behaviour::new(
                local_peer_id,
                relay::Config::default(),
            )))
        } else {
            Toggle::from(None)
        };

        // identify (#226): exchange each peer's observed address so the
        // swarm learns its external-address candidates. DCUtR and AutoNAT
        // both depend on this — without it DCUtR's hole punch fails with
        // `NoAddresses`. The protocol string is the libp2p identify
        // protocol id; the agent version carries our crate version.
        let identify = identify::Behaviour::new(
            identify::Config::new("/paraloom/1.0.0".to_string(), local_key.public())
                .with_agent_version(format!("paraloom/{}", env!("CARGO_PKG_VERSION"))),
        );

        // Set up message channel
        let (tx, rx) = mpsc::channel(100);

        // Build the swarm via SwarmBuilder rather than Swarm::new so
        // the relay *client* transport can be woven into the stack
        // (#226). `with_relay_client` returns the client behaviour and
        // injects a `/p2p-circuit` transport, letting a NATed node dial
        // and listen through a relay; assembling that transport by hand
        // alongside TCP+QUIC is exactly the error-prone composition the
        // builder exists to handle. Transport set is otherwise
        // unchanged: TCP (noise + yamux) or QUIC, same as before.
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| anyhow!("building TCP transport: {}", e))?
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|e| anyhow!("building relay-client transport: {}", e))?
            .with_behaviour(|_key, relay_client| ParaloomBehaviour {
                gossipsub,
                request_response,
                heartbeat,
                cosign,
                kad,
                ping,
                autonat,
                relay,
                relay_client,
                dcutr: dcutr::Behaviour::new(local_peer_id),
                identify,
            })
            .map_err(|e| anyhow!("building swarm behaviour: {}", e))?
            .build();

        Ok(NetworkManager {
            peer_id: local_peer_id,
            swarm: Arc::new(Mutex::new(swarm)),
            message_sender: tx,
            message_receiver: Arc::new(Mutex::new(rx)),
            handler: Arc::new(Mutex::new(None)),
            connected_peers: Arc::new(Mutex::new(Vec::new())),
            peer_registry: Arc::new(Mutex::new(PeerRegistry::new())),
            cosign_waiters: Arc::new(Mutex::new(HashMap::new())),
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

    /// Declare a publicly-reachable address for this node (#226).
    ///
    /// Calls `Swarm::add_external_address`, which marks the address
    /// confirmed and propagates it to every behaviour. This matters
    /// for a relay *server*: the reservation it grants a NATed peer
    /// only carries the relay's own external addresses, so without one
    /// the client gets `NoAddressesInReservation` and cannot build a
    /// usable `/p2p-circuit` listen address. A public anchor therefore
    /// declares its routable multiaddr here. AutoNAT also confirms
    /// addresses automatically, but a bootstrap anchor may have no
    /// other AutoNAT server to probe it, so an explicit declaration is
    /// the reliable path.
    pub async fn add_external_address(&self, addr: &str) -> Result<()> {
        let addr: Multiaddr = addr
            .parse()
            .with_context(|| format!("parsing external address {}", addr))?;
        let mut swarm = self.swarm.lock().await;
        swarm.add_external_address(addr.clone());
        info!("Declared external address {}", addr);
        Ok(())
    }

    /// Reserve a slot on a circuit-relay v2 server and listen on the
    /// resulting `/<relay>/p2p-circuit` address (#226).
    ///
    /// A node behind a NAT calls this so peers can reach it *through*
    /// the relay: the relay client transport (woven in by
    /// `SwarmBuilder::with_relay_client`) dials the relay, requests a
    /// reservation, and the swarm starts accepting inbound circuits on
    /// the relayed address. DCUtR then opportunistically upgrades each
    /// relayed circuit to a direct connection.
    ///
    /// `relay_addr` must include the relay's `/p2p/<peer_id>` suffix —
    /// without it the relay client cannot identify the reservation
    /// target, so we reject the address rather than silently no-op.
    pub async fn listen_via_relay(&self, relay_addr: &str) -> Result<()> {
        let relay_addr: Multiaddr = relay_addr
            .parse()
            .with_context(|| format!("parsing relay address {}", relay_addr))?;

        let relay_peer = peer_id_from_multiaddr(&relay_addr).ok_or_else(|| {
            anyhow!(
                "relay address {} has no /p2p/<peer_id> suffix; cannot reserve a circuit",
                relay_addr
            )
        })?;

        let mut swarm = self.swarm.lock().await;

        // Register the relay in Kademlia so the relay-client behaviour
        // can resolve the relay's address when it dials (it builds its
        // reservation dial with `extend_addresses_through_behaviour`).
        // We deliberately do NOT dial the relay ourselves: listening on
        // the circuit triggers the relay-client behaviour to open its
        // own dial and pin the pending reservation to that connection.
        // A second, explicit dial to the same peer races with it and
        // gets coalesced, dropping the reservation's listener channel —
        // the listener then closes cleanly before any reservation is
        // made. Letting the behaviour own the dial is the supported path.
        swarm
            .behaviour_mut()
            .kad
            .add_address(&relay_peer, relay_addr.clone());

        // Listening on `<relay>/p2p-circuit` is what actually requests
        // the reservation and starts accepting relayed inbound
        // connections.
        let circuit_addr = relay_addr
            .clone()
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        swarm
            .listen_on(circuit_addr.clone())
            .with_context(|| format!("listening on relay circuit {}", circuit_addr))?;

        info!(
            "Reserving relay slot on {} and listening via circuit {}",
            relay_addr, circuit_addr
        );
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
        let cosign_waiters_clone = self.cosign_waiters.clone();

        // Spawn task to handle events
        tokio::spawn(async move {
            Self::run_event_loop(
                swarm_clone,
                receiver_clone,
                handler_clone,
                connected_peers_clone,
                peer_registry_clone,
                cosign_waiters_clone,
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
        cosign_waiters: Arc<Mutex<HashMap<OutboundRequestId, oneshot::Sender<CoSignResponse>>>>,
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
                                libp2p::swarm::SwarmEvent::NewExternalAddrCandidate { address } => {
                                    // AutoNAT will probe this candidate; promotion to
                                    // a confirmed external address surfaces below.
                                    debug!("New external address candidate: {}", address);
                                }
                                libp2p::swarm::SwarmEvent::ExternalAddrConfirmed { address } => {
                                    info!("External address confirmed: {}", address);
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
                                                        // Gossipsub runs in Signed mode, so `message.source`
                                                        // is the authenticated original publisher. Prefer it
                                                        // over `propagation_source` (the last forwarding hop)
                                                        // so a relayed message is attributed to its real
                                                        // author — this is what lets the consensus layer
                                                        // reject a vote whose self-declared validator does not
                                                        // match the authenticated sender (audit).
                                                        let source = match message.source {
                                                            Some(author) => NodeId(author.to_bytes()),
                                                            None => NodeId(peer_id.to_bytes()),
                                                        };
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

                                        ParaloomBehaviourEvent::Cosign(cosign_event) => {
                                            match cosign_event {
                                                RequestResponseEvent::Message { peer, message, connection_id: _ } => {
                                                    match message {
                                                        RequestResponseMessage::Request { request, channel, .. } => {
                                                            let source = NodeId(peer.to_bytes());
                                                            let request_id = request.request_id.clone();
                                                            let handler_lock = handler.lock().await;
                                                            let response = if let Some(h) = handler_lock.as_ref() {
                                                                match h.handle_cosign_request(source, request).await {
                                                                    Ok(resp) => resp,
                                                                    Err(e) => {
                                                                        log::error!("cosign handler error: {}", e);
                                                                        CoSignResponse {
                                                                            request_id,
                                                                            wallet_pubkey: String::new(),
                                                                            signature: None,
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                CoSignResponse {
                                                                    request_id,
                                                                    wallet_pubkey: String::new(),
                                                                    signature: None,
                                                                }
                                                            };
                                                            drop(handler_lock);
                                                            let mut swarm_lock = swarm.lock().await;
                                                            if let Err(e) = swarm_lock.behaviour_mut().cosign.send_response(channel, response) {
                                                                log::error!("Failed to send cosign response: {:?}", e);
                                                            }
                                                        }
                                                        RequestResponseMessage::Response { request_id, response, .. } => {
                                                            // Complete the leader-side waiter registered by
                                                            // send_cosign_request (#260).
                                                            if let Some(tx) = cosign_waiters.lock().await.remove(&request_id) {
                                                                let _ = tx.send(response);
                                                            } else {
                                                                debug!("cosign response with no waiter: {:?}", request_id);
                                                            }
                                                        }
                                                    }
                                                }
                                                RequestResponseEvent::OutboundFailure { peer, request_id, error, .. } => {
                                                    log::warn!(
                                                        "cosign outbound failure to {:?}: {:?}",
                                                        peer, error
                                                    );
                                                    // Drop the waiter so the awaiting leader errors
                                                    // out instead of hanging past the timeout.
                                                    cosign_waiters.lock().await.remove(&request_id);
                                                }
                                                RequestResponseEvent::InboundFailure { peer, error, .. } => {
                                                    log::warn!(
                                                        "cosign inbound failure from {:?}: {:?}",
                                                        peer, error
                                                    );
                                                }
                                                RequestResponseEvent::ResponseSent { peer, .. } => {
                                                    debug!("cosign response sent to {}", peer);
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

                                        ParaloomBehaviourEvent::Autonat(autonat_event) => {
                                            match autonat_event {
                                                autonat::Event::StatusChanged { old, new } => {
                                                    info!(
                                                        "AutoNAT reachability changed: {:?} -> {:?}",
                                                        old, new
                                                    );
                                                    // When a probe confirms we are
                                                    // publicly reachable, register the
                                                    // address as external so the swarm
                                                    // advertises it to peers (and PR-B
                                                    // can prefer a direct dial over a
                                                    // relay circuit).
                                                    if let autonat::NatStatus::Public(addr) = &new {
                                                        let mut swarm_lock = swarm.lock().await;
                                                        swarm_lock.add_external_address(addr.clone());
                                                        info!("Confirmed publicly reachable at {}", addr);
                                                    }
                                                }
                                                other => {
                                                    debug!("autonat event: {:?}", other);
                                                }
                                            }
                                        }

                                        ParaloomBehaviourEvent::Relay(relay_event) => {
                                            // Relay-server activity (reservations,
                                            // circuit open/close) is low-volume, so
                                            // log at info: it makes the anchor's relay
                                            // role observable without a debug build.
                                            // Only emitted when enable_relay_server is
                                            // on; the Toggle is silent otherwise.
                                            info!("relay server event: {:?}", relay_event);
                                        }

                                        ParaloomBehaviourEvent::RelayClient(relay_client_event) => {
                                            // Client side of #226: reservations we hold
                                            // on a relay and circuits opened through it.
                                            // Low-volume; info-level so a NATed node's
                                            // path to reachability is observable.
                                            info!("relay client event: {:?}", relay_client_event);
                                        }

                                        ParaloomBehaviourEvent::Dcutr(dcutr_event) => {
                                            // Hole-punch attempt to upgrade a relayed
                                            // circuit to a direct connection. The event
                                            // carries the peer and a Result; log the
                                            // whole event so both success and the
                                            // failure cause are visible.
                                            info!("dcutr hole-punch event: {:?}", dcutr_event);
                                        }

                                        ParaloomBehaviourEvent::Identify(identify_event) => {
                                            // The behaviour reports observed addresses
                                            // to the swarm on its own (as external-addr
                                            // candidates that AutoNAT confirms and DCUtR
                                            // consumes); we just log at debug for
                                            // visibility into the peer handshake.
                                            debug!("identify event: {:?}", identify_event);
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

    /// Send a settlement co-sign request to a validator and await its response
    /// (#260). Unlike the heartbeat and result protocols, the round leader needs
    /// the reply, so this registers a oneshot keyed by the outbound request id
    /// and awaits it. The event loop completes the oneshot when the response
    /// arrives, or drops it on outbound failure / the protocol's request
    /// timeout — in which case this returns an error rather than blocking the
    /// round on an unresponsive validator.
    pub async fn send_cosign_request(
        &self,
        peer: NodeId,
        request: CoSignRequest,
    ) -> Result<CoSignResponse> {
        let peer_id = PeerId::from_bytes(&peer.0).map_err(|e| anyhow!("Invalid peer ID: {}", e))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut swarm = self.swarm.lock().await;
            let request_id = swarm.behaviour_mut().cosign.send_request(&peer_id, request);
            self.cosign_waiters.lock().await.insert(request_id, tx);
        }
        rx.await
            .map_err(|_| anyhow!("cosign request to {} failed or timed out", peer_id))
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> NodeId {
        NodeId(self.peer_id.to_bytes())
    }

    /// The local PeerId in libp2p's base58 string form (the value
    /// that appears in a `/p2p/<peer_id>` multiaddr). Distinct from
    /// [`Self::local_peer_id`], which returns the raw-byte `NodeId`;
    /// this is what operators and tests need to construct a dialable
    /// multiaddr for this node.
    pub fn peer_id_base58(&self) -> String {
        self.peer_id.to_string()
    }

    /// Multiaddrs the swarm is currently listening on, stringified.
    /// After a successful relay reservation (#226) this includes the
    /// `/<relay>/p2p-circuit` address; before that it is just the
    /// local transport addresses. Exposed for operational tooling and
    /// for tests that assert a relay circuit came up.
    pub async fn listen_addresses(&self) -> Vec<String> {
        let swarm = self.swarm.lock().await;
        swarm.listeners().map(|a| a.to_string()).collect()
    }

    /// Whether this node is running a circuit-relay v2 server (#226).
    /// Mirrors `network.enable_relay_server`; exposed so operational
    /// tooling (the /metrics endpoint, status CLIs) can report the
    /// node's relay role without reaching into the swarm.
    pub async fn relay_server_enabled(&self) -> bool {
        let swarm = self.swarm.lock().await;
        swarm.behaviour().relay.is_enabled()
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
    async fn relay_server_toggle_follows_config() {
        // The relay-server behaviour is a Toggle gated on
        // network.enable_relay_server: off by default (a NATed
        // validator carries no relay state) and on only when an
        // operator opts the node in (the public anchor). #226.
        let mut off = Settings::development();
        off.network.enable_relay_server = false;
        let mgr_off = NetworkManager::new(&off).expect("network manager");
        assert!(
            !mgr_off.relay_server_enabled().await,
            "relay server must be disabled when the flag is off"
        );

        let mut on = Settings::development();
        on.network.enable_relay_server = true;
        let mgr_on = NetworkManager::new(&on).expect("network manager");
        assert!(
            mgr_on.relay_server_enabled().await,
            "relay server must be enabled when the flag is on"
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
