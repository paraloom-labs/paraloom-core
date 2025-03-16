//! P2P network protocol implementation

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub::{self, Gossipsub, MessageAuthenticity},
    identity, mplex, noise,
    swarm::SwarmBuilder,
    tcp, Multiaddr, PeerId, Swarm, Transport,
};
use log::{debug, info};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use crate::config::Settings;
use crate::types::NodeId;

use super::message::Message;

/// Network event handler
#[async_trait]
pub trait NetworkEventHandler: Send + Sync {
    /// Handle a message from the network
    async fn handle_message(&self, source: NodeId, message: Message) -> Result<()>;
}

/// Network manager
pub struct NetworkManager {
    peer_id: PeerId,
    swarm: Arc<Mutex<Swarm<Gossipsub>>>,
    message_sender: mpsc::Sender<(NodeId, Message)>,
    message_receiver: Arc<Mutex<mpsc::Receiver<(NodeId, Message)>>>,
    handler: Option<Arc<dyn NetworkEventHandler>>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new(_settings: &Settings) -> Result<Self> {
        // Create a random PeerId
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        info!("Local peer ID: {}", local_peer_id);

        // Create a transport
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(
                noise::NoiseAuthenticated::xx(&local_key)
                    .map_err(|e| anyhow!("Noise error: {}", e))?,
            )
            .multiplex(mplex::MplexConfig::new())
            .boxed();

        // Create a Gossipsub behavior
        let gossipsub_config = gossipsub::GossipsubConfig::default();

        // Build the Gossipsub behavior
        let gossipsub = Gossipsub::new(MessageAuthenticity::Signed(local_key), gossipsub_config)
            .map_err(|e| anyhow!("Gossipsub error: {}", e))?;

        // Set up message channel
        let (tx, rx) = mpsc::channel(100);

        // Build the Swarm
        let swarm =
            SwarmBuilder::with_tokio_executor(transport, gossipsub, local_peer_id.clone()).build();

        Ok(NetworkManager {
            peer_id: local_peer_id,
            swarm: Arc::new(Mutex::new(swarm)),
            message_sender: tx,
            message_receiver: Arc::new(Mutex::new(rx)),
            handler: None,
        })
    }

    /// Set the event handler
    pub fn set_handler(&mut self, handler: Arc<dyn NetworkEventHandler>) {
        self.handler = Some(handler);
    }

    /// Start the network manager
    pub async fn start(&self, listen_address: Multiaddr) -> Result<()> {
        let mut swarm = self.swarm.lock().await;

        // Listen on the given address
        swarm.listen_on(listen_address.clone())?;
        info!("Listening on {}", listen_address);

        // Clone values for the task
        let swarm_clone = self.swarm.clone();
        let receiver_clone = self.message_receiver.clone();
        let handler_clone = self.handler.clone();

        // Spawn task to handle events
        tokio::spawn(async move {
            Self::run_event_loop(swarm_clone, receiver_clone, handler_clone).await;
        });

        Ok(())
    }

    /// Run the event loop
    async fn run_event_loop(
        swarm: Arc<Mutex<Swarm<Gossipsub>>>,
        receiver: Arc<Mutex<mpsc::Receiver<(NodeId, Message)>>>,
        handler: Option<Arc<dyn NetworkEventHandler>>,
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
                        Some(event) => debug!("Swarm event: {:?}", event),
                        None => break,
                    }
                },

                // Handle incoming messages
                message = async {
                    let mut receiver = receiver.lock().await;
                    receiver.recv().await
                } => {
                    match message {
                        Some((source, message)) => {
                            if let Some(handler) = &handler {
                                if let Err(e) = handler.handle_message(source, message).await {
                                    log::error!("Error handling message: {}", e);
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

    /// Send a message to a peer
    pub async fn send_message(&self, peer: NodeId, message: Message) -> Result<()> {
        self.message_sender
            .send((peer, message))
            .await
            .map_err(|e| anyhow!("Failed to send message: {}", e))
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> NodeId {
        NodeId(self.peer_id.to_bytes())
    }
}
