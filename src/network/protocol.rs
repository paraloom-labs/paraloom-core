//! P2P network protocol implementation

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub::{self, Behaviour as Gossipsub, IdentTopic, MessageAuthenticity},
    identity, noise, quic,
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

use super::message::Message;
use super::req_resp::{create_result_protocol, ResultCodec, ResultRequest, ResultResponse};

// Global topic for all paraloom messages
const PARALOOM_TOPIC: &str = "paraloom/v1";

#[derive(NetworkBehaviour)]
pub struct ParaloomBehaviour {
    pub gossipsub: Gossipsub,
    pub request_response: RequestResponse<ResultCodec>,
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
}

/// Network manager
pub struct NetworkManager {
    peer_id: PeerId,
    swarm: Arc<Mutex<Swarm<ParaloomBehaviour>>>,
    message_sender: mpsc::Sender<(NodeId, Message)>,
    message_receiver: Arc<Mutex<mpsc::Receiver<(NodeId, Message)>>>,
    handler: Arc<Mutex<Option<Arc<dyn NetworkEventHandler>>>>,
    connected_peers: Arc<Mutex<Vec<PeerId>>>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(_settings: &Settings) -> Result<Self> {
        // Create a random PeerId
        let local_key = identity::Keypair::generate_ed25519();
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

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(10 * 1024 * 1024)
            .build()
            .map_err(|e| anyhow!("Failed to build gossipsub config: {}", e))?;

        // Build the Gossipsub behavior
        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow!("Gossipsub error: {}", e))?;

        let request_response = create_result_protocol();

        let behaviour = ParaloomBehaviour {
            gossipsub,
            request_response,
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
        })
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

        // Spawn task to handle events
        tokio::spawn(async move {
            Self::run_event_loop(
                swarm_clone,
                receiver_clone,
                handler_clone,
                connected_peers_clone,
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
                                }
                                libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                    info!("Connection closed with peer: {} (cause: {:?})", peer_id, cause);

                                    // Remove from connected peers list
                                    let mut peers = connected_peers.lock().await;
                                    peers.retain(|p| p != &peer_id);
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

    /// Get local peer ID
    pub fn local_peer_id(&self) -> NodeId {
        NodeId(self.peer_id.to_bytes())
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<NodeId> {
        let peers = self.connected_peers.lock().await;
        peers.iter().map(|p| NodeId(p.to_bytes())).collect()
    }
}
