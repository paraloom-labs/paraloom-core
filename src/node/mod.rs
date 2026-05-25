//! Node implementation

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::info;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::bridge::Bridge;
use crate::compute::{JobCoordinator, JobExecutor, JobManager};
use crate::config::Settings;
use crate::consensus::{ApprovedWithdrawal, WithdrawalVerificationCoordinator};
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

    // Coordinator-HA spawn handles (#66). The broadcast handle is
    // populated when the node is configured as a primary with a
    // non-empty standby list; the watchdog handle is populated when
    // the node is configured as a standby. Either may be None when
    // HA is disabled. Held in Arc<Mutex<Option<...>>> so Clone of
    // Node remains cheap and shutdown can abort in place.
    ha_broadcast: Arc<Mutex<Option<JoinHandle<()>>>>,
    ha_watchdog: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Kademlia bootstrap-refresh handle (#65). Spawned in run()
    /// once the swarm is up and bootstrap addresses are
    /// registered; aborted in stop(). Held under the same
    /// Arc<Mutex<Option<...>>> shape as the HA handles so Clone
    /// stays cheap.
    kad_refresh: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Solana bridge manager (#163). Present only on bridge-enabled
    /// validator- or bridge-class nodes. Owns the deposit
    /// `EventListener` that indexes on-chain deposits into
    /// `shielded_pool`, so a withdrawing client can later obtain the
    /// Merkle path for the note it wants to spend. Initialized and
    /// started in run(), stopped in stop(). Held under Arc<Mutex<...>>
    /// so Clone of Node stays cheap and the &mut-taking lifecycle
    /// methods (init/start/stop) remain reachable behind &self.
    bridge: Option<Arc<Mutex<Bridge>>>,

    /// Merkle path-query HTTP server handle (#163). Spawned in run()
    /// when the bridge is enabled and a bind address is configured;
    /// aborted in stop(). Same Arc<Mutex<Option<...>>> shape as the
    /// other spawned-task handles so Clone of Node stays cheap.
    path_server: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Withdrawal consensus coordinator (#164). Present on bridge-enabled
    /// validator/bridge nodes. Incoming `WithdrawalVerificationResult`
    /// votes are routed into it; when a validator quorum approves a
    /// withdrawal it pushes the approval onto the channel drained by the
    /// submitter task.
    withdrawal_coordinator: Option<Arc<WithdrawalVerificationCoordinator>>,

    /// Receiver half of the coordinator's approval channel (#164). Taken
    /// once by run() to drive the submitter task. Wrapped so Clone of
    /// Node stays cheap; the receiver itself is not `Clone`.
    approval_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ApprovedWithdrawal>>>>,

    /// Submitter task handle (#164): drains approvals and settles them
    /// on-chain. Spawned in run(), aborted in stop().
    submitter_task: Arc<Mutex<Option<JoinHandle<()>>>>,
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

                // Mirror the registration into the withdrawal coordinator
                // (#175) so it knows the validator set: start_verification
                // requires a quorum-sized set, and leader selection weighs
                // these members. Independent of the compute coordinator
                // above — a bridge-enabled validator node has the former
                // without being a compute Coordinator.
                if let Some(withdrawal) = &self.withdrawal_coordinator {
                    if node_info.node_type == NodeType::ResourceProvider {
                        withdrawal.register_validator(source.clone()).await;
                    }
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
                // Route the vote into the withdrawal coordinator (#164).
                // On the node that started this verification, a vote that
                // completes the quorum makes the coordinator emit an
                // approval, which the submitter task settles on-chain. A
                // node that never started this request has no pending
                // entry — submit_result errors and we drop the vote.
                if let Some(coordinator) = &self.withdrawal_coordinator {
                    if let Err(e) = coordinator.submit_result(result).await {
                        log::debug!("dropping withdrawal vote: {}", e);
                    }
                }
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

    /// Route an inbound coordinator-HA heartbeat to the local
    /// coordinator instance, if any. A node configured without a
    /// coordinator has no standby state to apply, so it rejects the
    /// heartbeat and the primary will surface this as an outbound
    /// failure — useful operationally to spot a misconfigured peer
    /// list.
    async fn handle_heartbeat_request(
        &self,
        _source: NodeId,
        request: crate::network::HeartbeatRequest,
    ) -> Result<crate::network::HeartbeatResponse> {
        if let Some(coordinator) = &self.coordinator {
            Ok(coordinator.apply_heartbeat(request).await)
        } else {
            log::warn!("heartbeat received but this node has no coordinator");
            Ok(crate::network::HeartbeatResponse {
                accepted: false,
                last_applied_sequence: 0,
            })
        }
    }
}

/// Whether a submit error means the withdrawal was already settled (its
/// nullifier is spent), as opposed to a real failure (#164). A replay is
/// expected — e.g. two nodes reach quorum and both try to submit — so the
/// submitter task skips it quietly instead of logging a warning.
fn is_replay_error(e: &crate::bridge::BridgeError) -> bool {
    matches!(
        e,
        crate::bridge::BridgeError::InvalidTransaction(msg) if msg.contains("already spent")
    )
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

        // Initialize coordinator or validator based on node type.
        // For Coordinator nodes, the HA settings determine the role:
        // a configured `ha.primary` puts this coordinator into the
        // Standby role mirroring that primary; otherwise it starts
        // as a Primary (the existing default, preserved for any
        // operator who has not opted into HA yet).
        let coordinator = if node_type == NodeType::Coordinator {
            let coord = if let Some(primary_hex) = &settings.ha.primary {
                let primary_id = NodeId::from_str(primary_hex)
                    .map_err(|e| anyhow!("invalid ha.primary hex {:?}: {}", primary_hex, e))?;
                let stall = Duration::from_millis(settings.ha.stall_threshold_ms);
                Coordinator::standby_of(network_arc.clone(), primary_id, stall)
            } else {
                Coordinator::new(network_arc.clone())
            };
            Some(Arc::new(coord))
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

        // Privacy layer + Solana bridge (#163). A validator- or
        // bridge-class node with the bridge enabled owns a ShieldedPool
        // that the Bridge manager's deposit EventListener keeps in sync
        // with on-chain deposits (started in run()). Compute-only
        // providers and nodes with the bridge disabled skip it.
        //
        // The pool is in-memory (ShieldedPool::new) rather than
        // storage-backed on purpose: the deposit listener does not yet
        // persist its scan cursor, so a persistent tree would
        // double-index on restart. Rebuilding from chain on each run
        // keeps the cursor and the tree consistent; persistent indexing
        // is a follow-up once the cursor is durable.
        let runs_bridge = settings.bridge.enabled
            && matches!(node_type, NodeType::ResourceProvider | NodeType::Bridge);
        let shielded_pool = if runs_bridge {
            Some(Arc::new(ShieldedPool::new()))
        } else {
            None
        };
        let bridge = if runs_bridge {
            Some(Arc::new(Mutex::new(Bridge::new(settings.bridge.clone()))))
        } else {
            None
        };

        // Withdrawal consensus coordinator + its approval channel (#164).
        // Built only on bridge-enabled validator/bridge nodes; the
        // receiver is held until run() spawns the submitter task.
        let (withdrawal_coordinator, approval_rx) = if runs_bridge {
            let (coord, rx) = WithdrawalVerificationCoordinator::new_with_approvals();
            (Some(Arc::new(coord)), Some(rx))
        } else {
            (None, None)
        };

        let node = Node {
            settings,
            network: network_arc,
            status: Arc::new(Mutex::new(NodeStatus::Starting)),
            node_info,
            resource_monitor: Arc::new(resource_monitor),
            coordinator,
            validator,
            privacy_storage: None,
            shielded_pool,
            verification_coordinator: None,
            bridge,
            compute_executor,
            compute_manager,
            compute_coordinator,
            compute_storage,
            job_coordinators: Arc::new(Mutex::new(std::collections::HashMap::new())),
            ha_broadcast: Arc::new(Mutex::new(None)),
            ha_watchdog: Arc::new(Mutex::new(None)),
            kad_refresh: Arc::new(Mutex::new(None)),
            path_server: Arc::new(Mutex::new(None)),
            withdrawal_coordinator,
            approval_rx: Arc::new(Mutex::new(approval_rx)),
            submitter_task: Arc::new(Mutex::new(None)),
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

        // Spawn the Kademlia bootstrap-refresh task (#65). Cadence
        // is hardcoded at 5 minutes for now; a configurable knob
        // lands when the rest of the discovery surface (liveness
        // probes, integration test) is ready and we know what
        // operators actually want to tune.
        {
            let handle =
                Arc::clone(&self.network).start_kad_bootstrap_refresh(Duration::from_secs(300));
            *self.kad_refresh.lock().await = Some(handle);
            info!("Kademlia bootstrap-refresh task spawned (interval 300s)");
        }

        // Spawn coordinator-HA loops based on the configured role
        // (#66). A standby runs the stall watchdog; a primary with
        // a non-empty standby list runs the heartbeat broadcast.
        // A primary without standbys (or any node configured
        // without HA) skips both, preserving the pre-#66 behavior.
        if let Some(coordinator) = &self.coordinator {
            let ha = &self.settings.ha;
            if ha.primary.is_some() {
                let handle = Arc::clone(coordinator)
                    .start_stall_watchdog(Duration::from_millis(ha.watchdog_interval_ms));
                *self.ha_watchdog.lock().await = Some(handle);
                info!(
                    "HA stall watchdog spawned (interval {}ms, threshold {}ms)",
                    ha.watchdog_interval_ms, ha.stall_threshold_ms
                );
            } else if !ha.standbys.is_empty() {
                let mut standby_ids = Vec::with_capacity(ha.standbys.len());
                for hex in &ha.standbys {
                    let id = NodeId::from_str(hex)
                        .map_err(|e| anyhow!("invalid ha.standbys entry {:?}: {}", hex, e))?;
                    standby_ids.push(id);
                }
                let primary_id = self.network.local_peer_id();
                let handle = Arc::clone(coordinator).start_heartbeat_broadcast(
                    primary_id,
                    standby_ids,
                    Duration::from_millis(ha.heartbeat_interval_ms),
                );
                *self.ha_broadcast.lock().await = Some(handle);
                info!(
                    "HA heartbeat broadcast spawned to {} standbys (interval {}ms)",
                    ha.standbys.len(),
                    ha.heartbeat_interval_ms
                );
            }
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

        // Start the Solana bridge deposit listener (#163). On a
        // bridge-enabled validator/bridge node this spawns the
        // EventListener, which polls Solana and indexes deposit
        // commitments into the shielded pool so a withdrawing client
        // can later obtain a Merkle path for the note it spends.
        if let (Some(bridge), Some(pool)) = (&self.bridge, &self.shielded_pool) {
            let mut bridge = bridge.lock().await;
            bridge.init(pool.clone()).await?;
            bridge.start().await?;
            info!("Solana bridge deposit listener started");
        }

        // Serve Merkle paths over HTTP (#163) so a withdrawing client
        // can fetch the (root, path) for the note it spends. Only runs
        // when the node owns an indexed pool and a bind address is
        // configured; an empty address disables it. An unparseable
        // address is logged and skipped rather than failing start-up.
        if let Some(pool) = &self.shielded_pool {
            let addr_str = self.settings.bridge.merkle_path_query_address.trim();
            if !addr_str.is_empty() {
                match addr_str.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let pool = pool.clone();
                        let handle = tokio::spawn(async move {
                            if let Err(e) = crate::privacy::path_server::serve(pool, addr).await {
                                log::error!(
                                    target: "paraloom::privacy::path_server",
                                    "Merkle path query server exited: {}",
                                    e
                                );
                            }
                        });
                        *self.path_server.lock().await = Some(handle);
                        info!("Merkle path query server started on {}", addr_str);
                    }
                    Err(e) => {
                        log::warn!(
                            "invalid bridge.merkle_path_query_address '{}': {} — path server not started",
                            addr_str,
                            e
                        );
                    }
                }
            }
        }

        // Settle consensus-approved withdrawals (#164). Drains the
        // approval channel the withdrawal coordinator pushes to when a
        // validator quorum approves a withdrawal, and submits each
        // on-chain via the bridge. A per-message failure — including a
        // replay whose nullifier is already spent — is logged and
        // skipped so it cannot kill the task and stall later approvals.
        if let (Some(bridge), Some(coordinator), Some(rx)) = (
            self.bridge.clone(),
            self.withdrawal_coordinator.clone(),
            self.approval_rx.lock().await.take(),
        ) {
            let mut rx = rx;
            let local_id = self.node_info.id.clone();
            let handle = tokio::spawn(async move {
                while let Some(approved) = rx.recv().await {
                    let request_id = approved.request_id.clone();

                    // Leader gate (#175): the gossip mesh floods the
                    // approval to every node, so without this each
                    // validator would submit the same withdrawal — N-1
                    // redundant, replay-rejected transactions. Only the
                    // deterministically-selected leader for this request
                    // settles it; every node derives the same leader from
                    // the request_id seed, so exactly one submits.
                    match coordinator.select_leader(&request_id).await {
                        Ok(leader) if leader != local_id => {
                            log::debug!(
                                "withdrawal {} approved; not leader, leaving submission to {:?}",
                                request_id,
                                leader
                            );
                            continue;
                        }
                        Ok(_) => { /* we are the leader — settle below */ }
                        Err(e) => {
                            // No leader selectable (e.g. empty set): submit
                            // rather than drop the withdrawal. Replay
                            // protection keeps it safe if another node
                            // also submits.
                            log::warn!(
                                "leader selection failed for {}: {} — submitting anyway",
                                request_id,
                                e
                            );
                        }
                    }

                    match bridge.lock().await.submit_approved(approved).await {
                        Ok(sig) => {
                            info!("on-chain withdraw submitted for {}: {}", request_id, sig)
                        }
                        Err(e) if is_replay_error(&e) => {
                            log::debug!(
                                "withdrawal {} already settled (nullifier spent), skipping",
                                request_id
                            )
                        }
                        Err(e) => {
                            log::warn!("withdrawal {} submit failed: {}", request_id, e)
                        }
                    }
                }
            });
            *self.submitter_task.lock().await = Some(handle);
            info!("withdrawal submitter task started");
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
        // Cancel HA loops first so they do not race the status flip
        // (the broadcast loop checks is_primary on each tick; an
        // abort during a tick is safe but waiting one tick of
        // unnecessary heartbeats is also safe).
        if let Some(handle) = self.ha_broadcast.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.ha_watchdog.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.kad_refresh.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.path_server.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.submitter_task.lock().await.take() {
            handle.abort();
        }
        // Stop the bridge deposit listener (#163) so its poll loop
        // winds down on the next tick. A failure here must not block
        // the rest of shutdown, so it is logged rather than propagated.
        if let Some(bridge) = &self.bridge {
            if let Err(e) = bridge.lock().await.stop().await {
                log::warn!("error stopping Solana bridge: {}", e);
            }
        }
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

    /// Get the withdrawal consensus coordinator (#164), if this node runs
    /// one. Exposed so an integration harness can drive verification
    /// (start_verification + submit_result) against the same coordinator
    /// whose approvals the node's submitter task settles on-chain.
    pub fn withdrawal_coordinator(&self) -> Option<Arc<WithdrawalVerificationCoordinator>> {
        self.withdrawal_coordinator.clone()
    }

    /// Initiate distributed verification of a withdrawal (#175).
    ///
    /// Records the request with this node's withdrawal coordinator and
    /// broadcasts it to the validator set over the gossip mesh, so
    /// validators verify and vote without the request having to be driven
    /// into the coordinator by hand. Votes flood back as
    /// `WithdrawalVerificationResult`, route into the coordinator (#164),
    /// and the resulting approval is settled on-chain by the leader's
    /// submitter task. Returns the request id.
    ///
    /// Errors if this node runs no withdrawal coordinator, or if
    /// `start_verification` rejects the request (e.g. the known validator
    /// set is below the consensus quorum).
    pub async fn initiate_withdrawal_verification(
        &self,
        request: crate::consensus::WithdrawalVerificationRequest,
    ) -> Result<String> {
        let coordinator = self.withdrawal_coordinator.as_ref().ok_or_else(|| {
            anyhow!("node has no withdrawal coordinator (bridge disabled or non-validator)")
        })?;
        let request_id = coordinator.start_verification(request.clone()).await?;
        // send_message broadcasts to the whole gossip topic — the peer
        // argument is ignored by the network layer — so every validator
        // receives the request to verify.
        self.network
            .send_message(
                NodeId(vec![]),
                Message::WithdrawalVerificationRequest { request },
            )
            .await?;
        info!("initiated withdrawal verification: {}", request_id);
        Ok(request_id)
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
            input_recipient: Some([0u8; 32]),
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
            ha_broadcast: self.ha_broadcast.clone(),
            ha_watchdog: self.ha_watchdog.clone(),
            kad_refresh: self.kad_refresh.clone(),
            bridge: self.bridge.clone(),
            path_server: self.path_server.clone(),
            withdrawal_coordinator: self.withdrawal_coordinator.clone(),
            approval_rx: self.approval_rx.clone(),
            submitter_task: self.submitter_task.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    // With the bridge disabled (the default), a node owns neither a
    // shielded pool nor a bridge manager — unchanged from pre-#163.
    #[test]
    fn bridge_disabled_node_has_no_pool() {
        let settings = Settings::development();
        assert!(!settings.bridge.enabled);
        let node = Node::new(settings).expect("construct node");
        assert!(node.shielded_pool.is_none());
        assert!(node.bridge.is_none());
        assert!(node.withdrawal_coordinator.is_none());
    }

    // A validator-class node (ResourceProvider) with the bridge enabled
    // owns a shielded pool, a bridge manager, and a withdrawal
    // coordinator, so run() can start the deposit listener (#163) and the
    // consensus→submit pipeline (#164).
    #[test]
    fn bridge_enabled_validator_owns_pool_and_bridge() {
        let mut settings = Settings::development();
        settings.bridge.enabled = true;
        let node = Node::new(settings).expect("construct node");
        assert!(node.shielded_pool.is_some());
        assert!(node.bridge.is_some());
        assert!(node.withdrawal_coordinator.is_some());
    }

    // A coordinator node does not index deposits even with the bridge
    // enabled: the deposit listener is validator/bridge-class only.
    #[test]
    fn bridge_enabled_coordinator_skips_pool() {
        let mut settings = Settings::development();
        settings.node.node_type = "Coordinator".to_string();
        settings.bridge.enabled = true;
        let node = Node::new(settings).expect("construct node");
        assert!(node.shielded_pool.is_none());
        assert!(node.bridge.is_none());
        assert!(node.withdrawal_coordinator.is_none());
    }

    // A node without a withdrawal coordinator (bridge disabled) cannot
    // initiate verification (#175).
    #[tokio::test]
    async fn initiate_withdrawal_errors_without_coordinator() {
        let node = Node::new(Settings::development()).expect("construct node");
        let request = crate::consensus::WithdrawalVerificationRequest {
            request_id: "x".to_string(),
            nullifier: [0u8; 32],
            amount: 1,
            recipient: [0u8; 32],
            proof: vec![0u8; 8],
            fee: 0,
            timestamp: 0,
        };
        assert!(node
            .initiate_withdrawal_verification(request)
            .await
            .is_err());
    }

    // On a bridge-enabled validator with a quorum-sized validator set
    // registered, initiate_withdrawal_verification records the request
    // and returns its id (#175). The broadcast is buffered on the network
    // channel; delivery is exercised by the multi-node integration test.
    #[tokio::test]
    async fn initiate_withdrawal_starts_verification() {
        let mut settings = Settings::development();
        settings.bridge.enabled = true;
        let node = Node::new(settings).expect("construct node");

        let coordinator = node
            .withdrawal_coordinator()
            .expect("validator node has a withdrawal coordinator");
        for i in 0..10u8 {
            coordinator.register_validator(NodeId(vec![i])).await;
        }

        let request = crate::consensus::WithdrawalVerificationRequest {
            request_id: "init-1".to_string(),
            nullifier: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            proof: vec![0u8; 128],
            fee: 10,
            timestamp: 0,
        };
        let request_id = node
            .initiate_withdrawal_verification(request)
            .await
            .expect("initiate succeeds with a quorum-sized validator set");
        assert_eq!(request_id, "init-1");
    }
}
