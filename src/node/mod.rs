//! Node implementation

use anyhow::Result;
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Settings;
use crate::network::{Message, NetworkManager};
use crate::resource::ResourceMonitor;
use crate::types::{NodeId, NodeInfo, NodeStatus, NodeType, ResourceContribution};

/// Node implementation
pub struct Node {
    settings: Settings,
    network: Arc<NetworkManager>,
    status: Arc<Mutex<NodeStatus>>,
    node_info: NodeInfo,
    resource_monitor: ResourceMonitor,
}

#[async_trait]
impl crate::network::protocol::NetworkEventHandler for Node {
    // Previous implementation...
    async fn handle_message(&self, source: NodeId, message: Message) -> Result<()> {
        info!("Received message from {}: {:?}", source, message);
        match message {
            Message::Ping => {
                // Respond with Pong
                self.network.send_message(source, Message::Pong).await?;
            }
            Message::Pong => {
                // Update node status
                info!("Received Pong from {}", source);
            }
            Message::Discovery { node_info } => {
                // Store node information
                info!("Discovered node {}: {:?}", source, node_info);
            }
            Message::ResourceUpdate { resources } => {
                // Update resource information
                info!("Resource update from {}: {:?}", source, resources);
            }
        }
        Ok(())
    }
}

impl Node {
    /// Create a new node
    pub fn new(settings: Settings) -> Result<Self> {
        let network = NetworkManager::new(&settings)?;

        let node_type = match settings.node.node_type.as_str() {
            "ResourceProvider" => NodeType::ResourceProvider,
            "Coordinator" => NodeType::Coordinator,
            "Bridge" => NodeType::Bridge,
            _ => NodeType::ResourceProvider,
        };

        let node_id = network.local_peer_id();

        // Create resource monitor
        let resource_monitor = ResourceMonitor::new(
            settings.node.max_cpu_usage,
            settings.node.max_memory_usage,
            settings.node.max_storage_usage,
        );

        // Initial empty resource contribution
        let resources = resource_monitor.get_contribution();

        let node_info = NodeInfo {
            id: node_id.clone(),
            node_type,
            resources,
            address: settings.network.listen_address.clone(),
        };

        let node = Node {
            settings,
            network: Arc::new(network),
            status: Arc::new(Mutex::new(NodeStatus::Starting)),
            node_info,
            resource_monitor,
        };

        Ok(node)
    }

    /// Run the node
    pub async fn run(&self) -> Result<()> {
        info!("Starting node: {:?}", self.node_info);

        // Start resource monitor
        self.resource_monitor.start().await?;

        // Check for GPU information
        if let Some(gpu_info) = self.resource_monitor.check_gpu() {
            info!("Detected GPU: {}", gpu_info);
        }

        // Set event handler
        let mut network = NetworkManager::new(&self.settings)?;
        network.set_handler(Arc::new(self.clone()));

        // Parse the listen address
        let listen_address = self.settings.network.listen_address.parse()?;

        // Start network
        network.start(listen_address).await?;

        // Update status
        {
            let mut status = self.status.lock().await;
            *status = NodeStatus::Running;
        }

        // Periodically update resource information
        let status = self.status.clone();
        loop {
            let current_status = status.lock().await.clone();
            match current_status {
                NodeStatus::Running => {
                    // Periodically update resource contribution
                    let updated_resources = self.resource_monitor.get_contribution();
                    {
                        let mut info = self.node_info.clone();
                        info.resources = updated_resources;
                        // You can broadcast this information to the network if needed
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                }
                _ => {
                    info!("Node status changed to {:?}, shutting down", current_status);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Stop the node
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping node");
        let mut status = self.status.lock().await;
        *status = NodeStatus::ShuttingDown;
        Ok(())
    }
}

// Clone is needed for the async_trait implementation
impl Clone for Node {
    fn clone(&self) -> Self {
        Node {
            settings: self.settings.clone(),
            network: self.network.clone(),
            status: self.status.clone(),
            node_info: self.node_info.clone(),
            resource_monitor: ResourceMonitor::new(
                self.settings.node.max_cpu_usage,
                self.settings.node.max_memory_usage,
                self.settings.node.max_storage_usage,
            ),
        }
    }
}
