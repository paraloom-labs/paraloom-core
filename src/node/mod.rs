//! Node implementation

use anyhow::Result;
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::compute::{JobCoordinator, JobExecutor, JobManager};
use crate::config::Settings;
use crate::coordinator::Coordinator;
use crate::network::{Message, NetworkManager, ResultRequest, ResultResponse};
use crate::privacy::pool::ShieldedPool;
use crate::privacy::verification::VerificationCoordinator;
use crate::resource::ResourceMonitor;
use crate::storage::{ComputeStorage, PrivacyStorage};
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
    // Compute layer
    compute_executor: Option<Arc<JobExecutor>>,
    compute_manager: Option<Arc<JobManager>>,
    compute_coordinator: Option<Arc<JobCoordinator>>,
    compute_storage: Option<Arc<ComputeStorage>>,
    // Track coordinator nodes for result reporting
    job_coordinators: Arc<Mutex<std::collections::HashMap<crate::compute::JobId, NodeId>>>,
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
                        crate::privacy::transaction::ShieldedTransaction::Deposit(tx) => match pool
                            .deposit(tx.output_note.clone(), tx.amount - tx.fee)
                            .await
                        {
                            Ok(commitment) => {
                                info!("Deposit successful: commitment={}", commitment.to_hex());
                            }
                            Err(e) => {
                                info!("Deposit failed: {}", e);
                            }
                        },
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
                            match pool
                                .withdraw(tx.input_nullifier.clone(), tx.amount, &tx.to_public)
                                .await
                            {
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

            // Consensus messages
            Message::WithdrawalVerificationRequest { request } => {
                info!(
                    "Received withdrawal verification request: {}",
                    request.request_id
                );

                // Verify withdrawal zkSNARK proof if privacy pool is available
                let vote = if let Some(pool) = &self.shielded_pool {
                    match self.verify_withdrawal_proof(&request, pool).await {
                        Ok(true) => {
                            info!(
                                "Withdrawal proof verified successfully: {}",
                                request.request_id
                            );
                            crate::consensus::withdrawal::VerificationVote::Valid
                        }
                        Ok(false) => {
                            log::warn!(
                                "Withdrawal proof verification failed: {}",
                                request.request_id
                            );
                            crate::consensus::withdrawal::VerificationVote::Invalid {
                                reason: "Proof verification failed".to_string(),
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Error verifying withdrawal proof {}: {}",
                                request.request_id,
                                e
                            );
                            crate::consensus::withdrawal::VerificationVote::Invalid {
                                reason: format!("Verification error: {}", e),
                            }
                        }
                    }
                } else {
                    log::warn!("Privacy pool not available, cannot verify proof");
                    crate::consensus::withdrawal::VerificationVote::Invalid {
                        reason: "Privacy pool not available".to_string(),
                    }
                };

                // Send verification result back to source (coordinator)
                let result = crate::consensus::withdrawal::WithdrawalVerificationResult {
                    request_id: request.request_id,
                    validator: self.node_info.id.clone(),
                    vote,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let response = Message::WithdrawalVerificationResult { result };
                if let Err(e) = self.network.send_message(source.clone(), response).await {
                    log::error!("Failed to send verification result: {}", e);
                }
            }
            Message::WithdrawalVerificationResult { result } => {
                info!(
                    "Received withdrawal verification result: {}",
                    result.request_id
                );
            }
            Message::ValidatorRegistration {
                validator_id,
                stake_amount,
                pubkey,
            } => {
                info!(
                    "Validator registered: {:?}, stake: {}, pubkey: {:?}",
                    validator_id, stake_amount, pubkey
                );
            }
            Message::ValidatorUnregistration { validator_id } => {
                info!("Validator unregistered: {:?}", validator_id);
            }
            Message::ValidatorHeartbeat {
                validator_id,
                timestamp,
            } => {
                info!("Validator heartbeat: {:?} at {}", validator_id, timestamp);
            }

            // Compute-related messages
            Message::ComputeJobRequest {
                job_id,
                wasm_code,
                input_data,
                max_memory_bytes,
                max_instructions,
                timeout_secs,
            } => {
                info!(
                    "Received compute job request from {}: job_id={}",
                    source, job_id
                );

                if let Some(executor) = &self.compute_executor {
                    // Create compute job
                    let limits = crate::compute::ResourceLimits {
                        max_memory_bytes,
                        max_instructions,
                        timeout_secs,
                    };
                    let job = crate::compute::ComputeJob::new(wasm_code, input_data, limits);
                    let actual_job_id = job.id.clone();

                    // Store coordinator for result reporting
                    {
                        let mut coordinators = self.job_coordinators.lock().await;
                        coordinators.insert(actual_job_id.clone(), source.clone());
                    }

                    // Store job as pending
                    if let Some(storage) = &self.compute_storage {
                        if let Err(e) = storage.add_pending_job(&job) {
                            log::error!("Failed to store pending job in storage: {}", e);
                        }
                    }

                    // Submit job to executor
                    match executor.submit_job(job.clone()) {
                        Ok(_) => {
                            info!("Compute job {} accepted for execution", actual_job_id);

                            // Move to active jobs in storage
                            if let Some(storage) = &self.compute_storage {
                                if let Err(e) = storage.remove_pending_job(&actual_job_id) {
                                    log::error!("Failed to remove pending job: {}", e);
                                }
                                if let Err(e) = storage.mark_job_active(&job) {
                                    log::error!("Failed to mark job as active: {}", e);
                                }
                            }

                            let response = Message::ComputeJobResponse {
                                job_id: actual_job_id,
                                accepted: true,
                                message: "Job accepted for execution".to_string(),
                            };
                            if let Err(e) = self.network.send_message(source, response).await {
                                log::error!("Failed to send compute job response: {}", e);
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to submit compute job: {}", e);

                            // Remove from pending storage on failure
                            if let Some(storage) = &self.compute_storage {
                                if let Err(e) = storage.remove_pending_job(&actual_job_id) {
                                    log::error!("Failed to remove pending job: {}", e);
                                }
                            }

                            let response = Message::ComputeJobResponse {
                                job_id: actual_job_id,
                                accepted: false,
                                message: format!("Job rejected: {}", e),
                            };
                            if let Err(e) = self.network.send_message(source, response).await {
                                log::error!("Failed to send compute job response: {}", e);
                            }
                        }
                    }
                } else {
                    log::warn!("Received compute job request but this node has no executor");
                    let response = Message::ComputeJobResponse {
                        job_id,
                        accepted: false,
                        message: "This node is not configured for compute execution".to_string(),
                    };
                    if let Err(e) = self.network.send_message(source, response).await {
                        log::error!("Failed to send compute job response: {}", e);
                    }
                }
            }
            Message::ComputeJobResponse {
                job_id,
                accepted,
                message,
            } => {
                info!(
                    "Received compute job response from {}: job_id={}, accepted={}, message={}",
                    source, job_id, accepted, message
                );

                // If we have a manager (coordinator node), notify it
                if let Some(_manager) = &self.compute_manager {
                    if accepted {
                        info!("Job {} was accepted by validator {}", job_id, source);
                        // Assignment tracking is handled by JobCoordinator
                    } else {
                        // Job was rejected, we might need to reassign
                        log::warn!("Job {} was rejected by {}: {}", job_id, source, message);
                        // Could implement retry logic here
                    }
                }
            }
            Message::ComputeJobQuery { job_id } => {
                info!(
                    "Received compute job query from {}: job_id={}",
                    source, job_id
                );

                if let Some(executor) = &self.compute_executor {
                    // Check if job exists and get result
                    if let Some(result) = executor.get_job_result(&job_id) {
                        let response = Message::ComputeJobResult {
                            job_id: result.job_id.clone(),
                            status: result.status.clone(),
                            output_data: result.output_data.clone(),
                            execution_time_ms: result.execution_time_ms,
                            memory_used_bytes: result.memory_used_bytes,
                            instructions_executed: result.instructions_executed,
                        };
                        if let Err(e) = self.network.send_message(source, response).await {
                            log::error!("Failed to send compute job result: {}", e);
                        }
                    } else {
                        log::warn!("Job {} not found in executor", job_id);
                    }
                } else {
                    log::warn!("Received compute job query but this node has no executor");
                }
            }
            Message::ComputeJobResult {
                job_id,
                status,
                output_data,
                execution_time_ms,
                memory_used_bytes,
                instructions_executed,
            } => {
                info!(
                    "Received compute job result from {}: job_id={}, status={:?}",
                    source, job_id, status
                );

                // Store result and update job status
                let result = crate::compute::JobResult {
                    job_id: job_id.clone(),
                    status,
                    output_data,
                    error: None,
                    execution_time_ms,
                    memory_used_bytes,
                    instructions_executed,
                };

                // Store result in storage
                if let Some(storage) = &self.compute_storage {
                    // Remove from active jobs
                    if let Err(e) = storage.remove_active_job(&job_id) {
                        log::error!("Failed to remove active job: {}", e);
                    }
                    // Store completed result
                    if let Err(e) = storage.store_result(&result) {
                        log::error!("Failed to store job result: {}", e);
                    }
                }

                // If we have a manager (coordinator node), update job status
                if let Some(manager) = &self.compute_manager {
                    if let Err(e) = manager.submit_result(result) {
                        log::error!("Failed to submit job result to manager: {}", e);
                    }
                }
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

        // Initialize compute layer based on node type
        let compute_executor = if node_type == NodeType::ResourceProvider {
            match JobExecutor::new() {
                Ok(executor) => Some(Arc::new(executor)),
                Err(e) => {
                    log::warn!("Failed to create JobExecutor: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let compute_coordinator = if node_type == NodeType::Coordinator {
            Some(Arc::new(JobCoordinator::new()))
        } else {
            None
        };

        let compute_manager = if node_type == NodeType::Coordinator {
            Some(Arc::new(JobManager::new()))
        } else {
            None
        };

        // Initialize compute storage if compute layer is enabled
        let compute_storage =
            if node_type == NodeType::ResourceProvider || node_type == NodeType::Coordinator {
                let storage_path = format!("{}/compute", settings.storage.data_dir);
                match ComputeStorage::open(&storage_path) {
                    Ok(storage) => {
                        info!("Compute storage initialized at {}", storage_path);
                        Some(Arc::new(storage))
                    }
                    Err(e) => {
                        log::warn!("Failed to open compute storage: {}", e);
                        None
                    }
                }
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
            compute_executor,
            compute_manager,
            compute_coordinator,
            compute_storage,
            job_coordinators: Arc::new(Mutex::new(std::collections::HashMap::new())),
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

        // Start compute executor if available (ResourceProvider nodes)
        if let Some(executor) = &self.compute_executor {
            executor.start().await?;
            info!("Compute executor started");
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

        // Start timeout monitoring for coordinator nodes
        if let Some(coordinator) = &self.compute_coordinator {
            let coordinator_clone = coordinator.clone();
            let status_clone = self.status.clone();
            tokio::spawn(async move {
                loop {
                    // Check node status
                    let current_status = status_clone.lock().await.clone();
                    if !matches!(current_status, NodeStatus::Running) {
                        info!("Timeout monitor shutting down");
                        break;
                    }

                    // Check for timed out jobs and reassign
                    match coordinator_clone.handle_timeouts().await {
                        Ok(reassigned) => {
                            if !reassigned.is_empty() {
                                info!("Reassigned {} timed out jobs", reassigned.len());
                                for job_id in reassigned {
                                    info!("  - Job {} was reassigned due to timeout", job_id);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Error handling timeouts: {}", e);
                        }
                    }

                    // Check every 60 seconds
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                }
            });
            info!("Timeout monitoring started for coordinator node");
        }

        // Start result reporting for ResourceProvider nodes
        if let Some(executor) = &self.compute_executor {
            let executor_clone = executor.clone();
            let network_clone = self.network.clone();
            let coordinators_clone = self.job_coordinators.clone();
            let status_clone = self.status.clone();

            tokio::spawn(async move {
                // Track which jobs we've already reported
                let mut reported_jobs = std::collections::HashSet::new();

                loop {
                    // Check node status
                    let current_status = status_clone.lock().await.clone();
                    if !matches!(current_status, NodeStatus::Running) {
                        info!("Result reporter shutting down");
                        break;
                    }

                    // Get all job results
                    let _stats = executor_clone.get_stats();

                    // Check for completed jobs
                    let coordinators = coordinators_clone.lock().await;
                    for (job_id, coordinator_id) in coordinators.iter() {
                        // Skip if already reported
                        if reported_jobs.contains(job_id) {
                            continue;
                        }

                        // Check if job has a result
                        if let Some(result) = executor_clone.get_job_result(job_id) {
                            // Job is complete, send result to coordinator
                            info!(
                                "Reporting job {} result to coordinator {}",
                                job_id, coordinator_id
                            );

                            let message = Message::ComputeJobResult {
                                job_id: result.job_id.clone(),
                                status: result.status.clone(),
                                output_data: result.output_data.clone(),
                                execution_time_ms: result.execution_time_ms,
                                memory_used_bytes: result.memory_used_bytes,
                                instructions_executed: result.instructions_executed,
                            };

                            match network_clone
                                .send_message(coordinator_id.clone(), message)
                                .await
                            {
                                Ok(_) => {
                                    info!("Successfully reported job {} result", job_id);
                                    reported_jobs.insert(job_id.clone());
                                }
                                Err(e) => {
                                    log::error!("Failed to send job result: {}", e);
                                }
                            }
                        }
                    }
                    drop(coordinators);

                    // Clean up old reported jobs
                    if reported_jobs.len() > 1000 {
                        reported_jobs.clear();
                    }

                    // Check every 5 seconds for new results
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            });
            info!("Result reporting started for ResourceProvider node");
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

    // Compute layer API methods

    /// Submit a compute job for execution (for ResourceProvider nodes)
    pub fn submit_compute_job(
        &self,
        job: crate::compute::ComputeJob,
    ) -> Result<crate::compute::JobId> {
        if let Some(executor) = &self.compute_executor {
            executor.submit_job(job)
        } else {
            Err(anyhow::anyhow!(
                "This node is not configured for compute execution"
            ))
        }
    }

    /// Get compute job result (for ResourceProvider nodes)
    pub fn get_compute_job_result(
        &self,
        job_id: &crate::compute::JobId,
    ) -> Option<crate::compute::JobResult> {
        self.compute_executor
            .as_ref()
            .and_then(|executor| executor.get_job_result(job_id))
    }

    /// Get compute executor statistics (for ResourceProvider nodes)
    pub fn get_compute_stats(&self) -> Option<crate::compute::ExecutorStats> {
        self.compute_executor
            .as_ref()
            .map(|executor| executor.get_stats())
    }

    /// Register a validator for compute jobs (for Coordinator nodes)
    pub async fn register_compute_validator(
        &self,
        capacity: crate::compute::ValidatorCapacity,
    ) -> Result<()> {
        if let Some(manager) = &self.compute_manager {
            manager.register_validator(capacity.clone())?;

            // Also update the coordinator with capacity info
            if let Some(coordinator) = &self.compute_coordinator {
                let announcement = crate::compute::CapacityAnnouncement {
                    validator_id: capacity.validator_id.clone(),
                    cpu_cores: capacity.cpu_cores,
                    memory_mb: capacity.memory_mb,
                    max_concurrent_jobs: capacity.max_concurrent_jobs,
                    current_load: 0,
                };
                coordinator.update_validator_capacity(announcement).await;
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("This node is not a coordinator"))
        }
    }

    /// Submit a job to the compute network (for Coordinator nodes)
    pub async fn submit_compute_job_to_network(
        &self,
        job: crate::compute::ComputeJob,
    ) -> Result<crate::compute::JobId> {
        if let Some(coordinator) = &self.compute_coordinator {
            let job_id = job.id.clone();

            // Assign job to a validator
            if let Some(assignment) = coordinator.assign_job(job_id.clone()).await? {
                info!(
                    "Job {} assigned to validator {}",
                    job_id, assignment.validator_id
                );

                // Send job request to the assigned validator
                let message = Message::ComputeJobRequest {
                    job_id: job.id.clone(),
                    wasm_code: job.wasm_code.clone(),
                    input_data: job.input_data.clone(),
                    max_memory_bytes: job.max_memory_bytes,
                    max_instructions: job.max_instructions,
                    timeout_secs: job.timeout_secs,
                };

                // Convert ValidatorId (String) to NodeId
                // ValidatorId is expected to be the hex representation of NodeId
                let node_id = self.validator_id_to_node_id(&assignment.validator_id)?;
                self.network.send_message(node_id, message).await?;
                Ok(job_id)
            } else {
                Err(anyhow::anyhow!(
                    "No available validators for job assignment"
                ))
            }
        } else {
            Err(anyhow::anyhow!("This node is not a coordinator"))
        }
    }

    /// Helper to convert ValidatorId (hex string) to NodeId
    fn validator_id_to_node_id(&self, validator_id: &str) -> Result<NodeId> {
        // For now, use ValidatorId as-is since it should be NodeId.to_string() format
        // In a production system, maintain a mapping
        let bytes = hex::decode(validator_id)
            .map_err(|e| anyhow::anyhow!("Invalid validator ID format: {}", e))?;
        Ok(NodeId(bytes))
    }

    /// Get compute manager reference (for Coordinator nodes)
    pub fn compute_manager(&self) -> Option<Arc<JobManager>> {
        self.compute_manager.clone()
    }

    /// Get compute coordinator reference (for Coordinator nodes)
    pub fn compute_coordinator(&self) -> Option<Arc<JobCoordinator>> {
        self.compute_coordinator.clone()
    }

    /// Get compute executor reference (for ResourceProvider nodes)
    pub fn compute_executor(&self) -> Option<Arc<JobExecutor>> {
        self.compute_executor.clone()
    }

    /// Verify withdrawal zkSNARK proof
    async fn verify_withdrawal_proof(
        &self,
        request: &crate::consensus::withdrawal::WithdrawalVerificationRequest,
        pool: &Arc<crate::privacy::pool::ShieldedPool>,
    ) -> Result<bool> {
        use crate::privacy::{bytes_to_field, deserialize_proof, Groth16ProofSystem};
        use ark_bls12_381::Fr;

        // Deserialize proof
        let proof = match deserialize_proof(&request.proof) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to deserialize proof: {}", e);
                return Ok(false);
            }
        };

        // Get current Merkle root from pool
        let merkle_root = pool.root().await;
        let merkle_root_field = match bytes_to_field(&merkle_root) {
            Ok(f) => f,
            Err(e) => {
                log::error!("Invalid Merkle root: {}", e);
                return Ok(false);
            }
        };

        // Convert nullifier to field element
        let nullifier_field = match bytes_to_field(&request.nullifier) {
            Ok(f) => f,
            Err(e) => {
                log::error!("Invalid nullifier: {}", e);
                return Ok(false);
            }
        };

        // Convert amount to field element
        let amount_field = Fr::from(request.amount);

        // Public inputs for verification
        let public_inputs = vec![merkle_root_field, nullifier_field, amount_field];

        // Load verifying key (for MVP, generate on-the-fly)
        let vk = match self.load_withdraw_verifying_key() {
            Ok(k) => k,
            Err(e) => {
                log::error!("Failed to load verifying key: {}", e);
                return Ok(false);
            }
        };

        // Verify proof
        match Groth16ProofSystem::verify(&vk, &public_inputs, &proof) {
            Ok(valid) => {
                log::debug!(
                    "Withdrawal proof verification result for {}: {}",
                    request.request_id,
                    valid
                );
                Ok(valid)
            }
            Err(e) => {
                log::error!("Proof verification error: {}", e);
                Ok(false)
            }
        }
    }

    /// Load withdraw circuit verifying key
    fn load_withdraw_verifying_key(
        &self,
    ) -> Result<ark_groth16::VerifyingKey<ark_bls12_381::Bls12_381>> {
        use crate::privacy::{Groth16ProofSystem, WithdrawCircuit};
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;

        // For MVP, generate keys on-the-fly
        // In production, these should be loaded from trusted setup
        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = WithdrawCircuit {
            merkle_root: Some([0u8; 32]),
            nullifier: Some([0u8; 32]),
            withdraw_amount: Some(0u64),
            input_value: Some(0u64),
            input_randomness: Some([0u8; 32]),
            input_path: None,
            secret: Some([0u8; 32]),
        };

        let (_, vk) = Groth16ProofSystem::setup(circuit, &mut rng)?;
        Ok(vk)
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
            compute_executor: self.compute_executor.clone(),
            compute_manager: self.compute_manager.clone(),
            compute_coordinator: self.compute_coordinator.clone(),
            compute_storage: self.compute_storage.clone(),
            job_coordinators: self.job_coordinators.clone(),
        }
    }
}
