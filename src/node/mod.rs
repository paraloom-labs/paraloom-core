//! Node implementation

use anyhow::Result;
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::Settings;
use crate::coordinator::Coordinator;
use crate::network::{Message, NetworkManager, ResultRequest, ResultResponse};
use crate::privacy::pool::ShieldedPool;
use crate::privacy::verification::VerificationCoordinator;
use crate::resource::ResourceMonitor;
use crate::storage::PrivacyStorage;
use crate::types::{NodeId, NodeInfo, NodeStatus, NodeType};
use crate::validator::Validator;

/// Node implementation
pub struct Node {
    settings: Settings,
    network: Arc<NetworkManager>,
    status: Arc<Mutex<NodeStatus>>,
    node_info: NodeInfo,
    resource_monitor: Arc<ResourceMonitor>,
    coordinator: Option<Arc<Coordinator>>,
    validator: Option<Arc<Mutex<Validator>>>,
    // Privacy layer
    privacy_storage: Option<Arc<PrivacyStorage>>,
    shielded_pool: Option<Arc<ShieldedPool>>,
    verification_coordinator: Option<Arc<VerificationCoordinator>>,
}

#[async_trait]
impl crate::network::protocol::NetworkEventHandler for Node {
    // Previous implementation...
    async fn handle_message(&self, source: NodeId, message: Message) -> Result<()> {
        match message {
            Message::Ping => {
                self.network.send_message(source, Message::Pong).await?;
            }
            Message::Pong => {
                info!("Received Pong from {}", source);
            }
            Message::Discovery { node_info } => {
                info!("Discovered node {}: {:?}", source, node_info);

                // If we're a coordinator, register this validator
                if let Some(coordinator) = &self.coordinator {
                    info!("This is a coordinator node, checking if validator...");
                    if node_info.node_type == NodeType::ResourceProvider {
                        info!("Node is a ResourceProvider, registering...");
                        coordinator.register_validator(source.clone()).await;
                    } else {
                        info!("Node type is {:?}, not registering", node_info.node_type);
                    }
                } else {
                    info!("This is not a coordinator node");
                }
            }
            Message::ResourceUpdate { resources } => {
                info!("Resource update from {}: {:?}", source, resources);
            }

            // Task-related messages
            Message::TaskRequest {
                task,
                coordinator_id,
            } => {
                if let Some(validator) = &self.validator {
                    let validator = validator.lock().await;
                    validator.handle_task_request(task, coordinator_id).await?;
                }
            }
            Message::TaskResponse { result } => {
                if let Some(coordinator) = &self.coordinator {
                    coordinator.handle_task_result(result).await?;
                }
            }
            Message::TaskError { task_id, error } => {
                if let Some(coordinator) = &self.coordinator {
                    coordinator.handle_task_error(task_id, error).await?;
                }
            }

            // Privacy-related messages
            Message::ShieldedTransaction { transaction } => {
                info!("Received shielded transaction: {}", transaction.id());

                // Process transaction if privacy is enabled
                if let Some(pool) = &self.shielded_pool {
                    match transaction {
                        crate::privacy::transaction::ShieldedTransaction::Deposit(tx) => {
                            match pool.deposit(tx.output_note.clone(), tx.amount - tx.fee).await {
                                Ok(commitment) => {
                                    info!("Deposit successful: commitment={}", commitment.to_hex());
                                }
                                Err(e) => {
                                    info!("Deposit failed: {}", e);
                                }
                            }
                        }
                        crate::privacy::transaction::ShieldedTransaction::Transfer(tx) => {
                            match pool
                                .transfer(tx.input_nullifiers.clone(), tx.output_notes.clone())
                                .await
                            {
                                Ok(commitments) => {
                                    info!("Transfer successful: {} outputs", commitments.len());
                                }
                                Err(e) => {
                                    info!("Transfer failed: {}", e);
                                }
                            }
                        }
                        crate::privacy::transaction::ShieldedTransaction::Withdraw(tx) => {
                            match pool.withdraw(tx.input_nullifier.clone(), tx.amount, &tx.to_public).await {
                                Ok(()) => {
                                    info!("Withdrawal successful: {} lamports", tx.amount);
                                }
                                Err(e) => {
                                    info!("Withdrawal failed: {}", e);
                                }
                            }
                        }
                    }
                } else {
                    info!("Privacy not enabled, ignoring transaction");
                }
            }
            Message::VerificationRequest {
                task_id,
                transaction_id,
                chunk,
            } => {
                info!(
                    "Received verification request: task={}, tx={}",
                    task_id, transaction_id
                );

                // Verify chunk and send result
                let result = chunk.verify();

                let response = Message::VerificationResult {
                    task_id,
                    validator_id: self.node_info.id.clone(),
                    result,
                };

                // Send result back to source
                if let Err(e) = self.network.send_message(source.clone(), response).await {
                    info!("Failed to send verification result: {}", e);
                }
            }
            Message::VerificationResult {
                task_id,
                validator_id,
                result,
            } => {
                info!(
                    "Received verification result: task={}, validator={:?}",
                    task_id, validator_id
                );

                // Aggregate verification result if coordinator is enabled
                if let Some(coord) = &self.verification_coordinator {
                    let task_result = crate::privacy::verification::VerificationTaskResult {
                        task_id,
                        validator: validator_id,
                        result,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    };

                    if let Err(e) = coord.submit_result(task_result).await {
                        info!("Failed to submit verification result: {}", e);
                    }
                }
            }
            Message::PoolStateQuery => {
                info!("Received pool state query from {}", source);

                if let Some(pool) = &self.shielded_pool {
                    let merkle_root = pool.root().await;
                    let total_supply = pool.total_supply().await;
                    let commitment_count = pool.commitment_count().await;

                    let response = Message::PoolStateResponse {
                        merkle_root,
                        total_supply,
                        commitment_count,
                    };

                    if let Err(e) = self.network.send_message(source.clone(), response).await {
                        info!("Failed to send pool state response: {}", e);
                    }
                } else {
                    info!("Privacy not enabled, cannot respond to pool state query");
                }
            }
            Message::PoolStateResponse {
                merkle_root,
                total_supply,
                commitment_count,
            } => {
                info!(
                    "Received pool state: root={:?}, supply={}, commitments={}",
                    merkle_root, total_supply, commitment_count
                );
            }
            Message::NullifierQuery { nullifier } => {
                info!("Received nullifier query: {:?}", nullifier);

                if let Some(pool) = &self.shielded_pool {
                    let is_spent = pool.is_spent(&nullifier).await;

                    let response = Message::NullifierResponse {
                        nullifier,
                        is_spent,
                    };

                    if let Err(e) = self.network.send_message(source.clone(), response).await {
                        info!("Failed to send nullifier response: {}", e);
                    }
                } else {
                    info!("Privacy not enabled, cannot respond to nullifier query");
                }
            }
            Message::NullifierResponse {
                nullifier,
                is_spent,
            } => {
                info!(
                    "Received nullifier response: {:?}, spent={}",
                    nullifier, is_spent
                );
            }
        }
        Ok(())
    }

    async fn handle_result_request(
        &self,
        source: NodeId,
        request: ResultRequest,
    ) -> Result<ResultResponse> {
        info!("Received result request from {}", source);
        if let Some(coordinator) = &self.coordinator {
            match coordinator.handle_task_result(request.result).await {
                Ok(_) => {
                    info!("Task result processed successfully");
                    Ok(ResultResponse {
                        success: true,
                        message: "Result received and processed".to_string(),
                    })
                }
                Err(e) => {
                    log::error!("Failed to process task result: {}", e);
                    Ok(ResultResponse {
                        success: false,
                        message: format!("Error processing result: {}", e),
                    })
                }
            }
        } else {
            log::warn!("Received result request but this node is not a coordinator");
            Ok(ResultResponse {
                success: false,
                message: "This node is not a coordinator".to_string(),
            })
        }
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
            node_type: node_type.clone(),
            resources,
            address: settings.network.listen_address.clone(),
        };

        let network_arc = Arc::new(network);

        // Initialize coordinator or validator based on node type
        let coordinator = if node_type == NodeType::Coordinator {
            Some(Arc::new(Coordinator::new(network_arc.clone())))
        } else {
            None
        };

        let validator = if node_type == NodeType::ResourceProvider {
            Some(Arc::new(Mutex::new(Validator::new(network_arc.clone()))))
        } else {
            None
        };

        // Privacy layer will be initialized in run() if enabled
        let node = Node {
            settings,
            network: network_arc,
            status: Arc::new(Mutex::new(NodeStatus::Starting)),
            node_info,
            resource_monitor: Arc::new(resource_monitor),
            coordinator,
            validator,
            privacy_storage: None,
            shielded_pool: None,
            verification_coordinator: None,
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
        self.network.set_handler(Arc::new(self.clone())).await;

        // Parse the listen address
        let listen_address = self.settings.network.listen_address.parse()?;

        // Start network
        self.network.start(listen_address).await?;

        // Connect to bootstrap nodes
        if !self.settings.network.bootstrap_nodes.is_empty() {
            info!(
                "Connecting to {} bootstrap nodes",
                self.settings.network.bootstrap_nodes.len()
            );
            self.network
                .connect_to_bootstrap(self.settings.network.bootstrap_nodes.clone())
                .await?;

            // Wait a bit for connection to establish
            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

            // Send discovery message to all connected peers
            let discovery_msg = Message::Discovery {
                node_info: self.node_info.clone(),
            };

            let peers = self.network.connected_peers().await;
            info!(
                "Sending discovery message to {} connected peers",
                peers.len()
            );

            for peer in peers {
                if let Err(e) = self.network.send_message(peer, discovery_msg.clone()).await {
                    log::warn!("Failed to send discovery message to peer: {}", e);
                }
            }

            info!(
                "Discovery broadcast complete for {:?}",
                self.node_info.node_type
            );
        }

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

    /// Submit a task (only for coordinator nodes)
    pub async fn submit_task(&self, task_type: crate::task::TaskType) -> Result<String> {
        if let Some(coordinator) = &self.coordinator {
            coordinator.submit_task(task_type).await
        } else {
            Err(anyhow::anyhow!("This node is not a coordinator"))
        }
    }

    /// Get coordinator reference
    pub fn coordinator(&self) -> Option<Arc<Coordinator>> {
        self.coordinator.clone()
    }

    /// Get node info
    pub fn node_info(&self) -> NodeInfo {
        self.node_info.clone()
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
            resource_monitor: self.resource_monitor.clone(),
            coordinator: self.coordinator.clone(),
            validator: self.validator.clone(),
            privacy_storage: self.privacy_storage.clone(),
            shielded_pool: self.shielded_pool.clone(),
            verification_coordinator: self.verification_coordinator.clone(),
        }
    }
}
