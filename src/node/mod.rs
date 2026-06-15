//! Node implementation

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::info;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use crate::bridge::solana::{
    build_settlement_message, derive_bridge_vault, CoSignPayload, SettlementParams,
};
use crate::bridge::Bridge;
use crate::compute::{JobCoordinator, JobExecutor, JobManager};
use crate::config::Settings;
use crate::consensus::transfer::TransferVerificationRequest;
use crate::consensus::withdrawal::WithdrawalVerificationRequest;
use crate::consensus::{
    ApprovedTransfer, ApprovedWithdrawal, TransferVerificationCoordinator,
    WithdrawalVerificationCoordinator,
};
use crate::coordinator::Coordinator;
use crate::network::{
    CoSignRequest, CoSignResponse, Message, NetworkManager, ResultRequest, ResultResponse,
    SettlementKind,
};
use crate::privacy::pool::ShieldedPool;
use crate::privacy::verification::VerificationCoordinator;
use crate::resource::ResourceMonitor;
use crate::storage::{ComputeStorage, PrivacyStorage};
use crate::types::{NodeId, NodeInfo, NodeStatus, NodeType};
use crate::validator::Validator;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::{pubkey::Pubkey, transaction::Transaction};

pub mod cosign_round;
pub mod transfer_ingress;
pub mod withdrawal_ingress;

/// Node implementation
/// Withdrawal-proof verifier hook (#181). A closure that decides whether a
/// withdrawal request's proof is valid. Production never sets one — the node
/// uses the real Groth16 path. The multi-node consensus E2E injects one via
/// [`Node::with_proof_verifier`] to exercise the libp2p gossip → vote →
/// quorum wiring independently of the cryptographic proof (which is covered
/// by the privacy circuit tests and the on-chain settlement test).
pub type WithdrawalProofVerifier =
    Arc<dyn Fn(&crate::consensus::withdrawal::WithdrawalVerificationRequest) -> bool + Send + Sync>;

/// Transfer-proof verifier override (#194), the transfer twin of
/// [`WithdrawalProofVerifier`]. `None` in production, so `verify_transfer_proof`
/// runs the real Groth16 path; the multi-node transfer consensus E2E injects a
/// closure to exercise the gossip → vote → quorum wiring without proving.
pub type TransferProofVerifier =
    Arc<dyn Fn(&crate::consensus::transfer::TransferVerificationRequest) -> bool + Send + Sync>;

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

    /// Optional withdrawal-proof verifier override (#181, Layer 2 testing
    /// seam). `None` in production, so `verify_withdrawal_proof` runs the
    /// real Groth16 path. The multi-node consensus E2E injects a closure
    /// here to decouple the network/consensus wiring under test from the
    /// cryptographic proof path. Set via [`Node::with_proof_verifier`].
    proof_verifier_override: Option<WithdrawalProofVerifier>,

    /// Withdrawal-ingress HTTP server handle (#184). Spawned in run() on a
    /// bridge-enabled node when `bridge.withdrawal_ingress_address` is set;
    /// aborted in stop(). Same Arc<Mutex<Option<...>>> shape as the other
    /// spawned-task handles so Clone of Node stays cheap.
    withdrawal_ingress: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Transfer consensus coordinator (#194), the transfer twin of
    /// `withdrawal_coordinator`. Incoming `TransferVerificationResult` votes
    /// route into it; a quorum-approved transfer is pushed onto the channel
    /// drained by the transfer submitter task.
    transfer_coordinator: Option<Arc<TransferVerificationCoordinator>>,

    /// Receiver half of the transfer coordinator's approval channel (#194).
    /// Taken once by run() to drive the transfer submitter task.
    transfer_approval_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ApprovedTransfer>>>>,

    /// Transfer submitter task handle (#194): drains approved transfers and
    /// settles them on-chain. Spawned in run(), aborted in stop().
    transfer_submitter_task: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Optional transfer-proof verifier override (#194 testing seam). `None`
    /// in production.
    transfer_proof_verifier_override: Option<TransferProofVerifier>,

    /// Transfer-ingress HTTP server handle (#194). Spawned in run() when
    /// `bridge.transfer_ingress_address` is set; aborted in stop().
    transfer_ingress: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Encrypted output notes this node has seen (#196), served from
    /// `GET /transfer/scan` for recipients to trial-decrypt. Populated when the
    /// node initiates or receives a transfer verification request. In-memory;
    /// persistence across restart is a follow-up.
    delivered_notes: Arc<Mutex<Vec<transfer_ingress::DeliveredNote>>>,

    /// This validator's Solana settlement keypair (#260), loaded from
    /// `bridge.authority_keypair_path`. Used to co-sign settlement transactions
    /// when another validator (the round leader) requests it. `None` on nodes
    /// without a configured keypair; such a node declines all co-sign requests.
    cosign_keypair: Option<Arc<Keypair>>,

    /// Withdrawal requests this node verified as `Valid` (#260), keyed by
    /// request id. A co-sign request is honoured only if its parameters match
    /// the request cached here — so the round leader cannot get this validator
    /// to sign a withdrawal it never verified, nor one with a substituted
    /// recipient (the recipient is the one every validator saw in the gossiped
    /// request). Bounded by `MAX_VERIFIED_CACHE`; entries are short-lived.
    verified_withdrawals: Arc<Mutex<HashMap<String, WithdrawalVerificationRequest>>>,

    /// Transfer twin of `verified_withdrawals` (#260).
    verified_transfers: Arc<Mutex<HashMap<String, TransferVerificationRequest>>>,
}

/// Upper bound on the per-node verified-settlement caches (#260). Entries are
/// consumed within seconds of the vote (the co-sign round follows immediately),
/// so this is only a safety ceiling against unbounded growth, never a working
/// limit in practice.
const MAX_VERIFIED_CACHE: usize = 1024;

/// Insert a verified settlement request into a bounded per-node cache (#260).
/// The bound is a safety ceiling, not a working limit; if the map is somehow at
/// capacity for a new key, drop one arbitrary existing entry to make room.
async fn cache_verified<V>(cache: &Arc<Mutex<HashMap<String, V>>>, request_id: String, value: V) {
    let mut map = cache.lock().await;
    if map.len() >= MAX_VERIFIED_CACHE && !map.contains_key(&request_id) {
        if let Some(victim) = map.keys().next().cloned() {
            map.remove(&victim);
        }
    }
    map.insert(request_id, value);
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
                        withdrawal
                            .register_validator_with_wallet(
                                source.clone(),
                                node_info.wallet_pubkey.clone(),
                            )
                            .await;
                    }
                }

                // Mirror into the transfer coordinator (#194) for the same
                // reason — its `start_verification` also needs a quorum-sized
                // validator set.
                if let Some(transfer) = &self.transfer_coordinator {
                    if node_info.node_type == NodeType::ResourceProvider {
                        transfer
                            .register_validator_with_wallet(
                                source.clone(),
                                node_info.wallet_pubkey.clone(),
                            )
                            .await;
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

                // Remember a request we verified Valid so we can later co-sign
                // its settlement, but only the exact parameters we saw (#260).
                if matches!(vote, crate::consensus::withdrawal::VerificationVote::Valid) {
                    cache_verified(
                        &self.verified_withdrawals,
                        request.request_id.clone(),
                        request.clone(),
                    )
                    .await;
                }

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
                // A vote must come from the validator it claims to be (audit):
                // `result.validator` is set by the sender, so without this check
                // one peer could submit votes under every validator's identity
                // and fabricate a quorum. `source` is the authenticated gossip
                // publisher, so reject any vote whose claimed validator does not
                // match the sender.
                if result.validator != source {
                    log::warn!(
                        "dropping withdrawal vote for {}: claimed validator {:?} != sender {:?}",
                        result.request_id,
                        result.validator,
                        source
                    );
                    return Ok(());
                }
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
            Message::TransferVerificationRequest { request } => {
                info!(
                    "Received transfer verification request: {}",
                    request.request_id
                );

                // Record the encrypted output notes for recipient scanning
                // (#196); any validator that sees the broadcast can serve scan.
                self.record_delivered_notes(&request.output_commitments, &request.ciphertexts)
                    .await;

                // Verify the transfer zkSNARK proof if a privacy pool is
                // available, mirroring the withdrawal path (#194).
                let vote = if let Some(pool) = &self.shielded_pool {
                    match self.verify_transfer_proof(&request, pool).await {
                        Ok(true) => {
                            info!(
                                "Transfer proof verified successfully: {}",
                                request.request_id
                            );
                            crate::consensus::vote_tally::VerificationVote::Valid
                        }
                        Ok(false) => {
                            log::warn!(
                                "Transfer proof verification failed: {}",
                                request.request_id
                            );
                            crate::consensus::vote_tally::VerificationVote::Invalid {
                                reason: "Proof verification failed".to_string(),
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Error verifying transfer proof {}: {}",
                                request.request_id,
                                e
                            );
                            crate::consensus::vote_tally::VerificationVote::Invalid {
                                reason: format!("Verification error: {}", e),
                            }
                        }
                    }
                } else {
                    log::warn!("Privacy pool not available, cannot verify transfer proof");
                    crate::consensus::vote_tally::VerificationVote::Invalid {
                        reason: "Privacy pool not available".to_string(),
                    }
                };

                // Remember a transfer we verified Valid so we can later co-sign
                // its settlement against the exact parameters we saw (#260).
                if matches!(vote, crate::consensus::vote_tally::VerificationVote::Valid) {
                    cache_verified(
                        &self.verified_transfers,
                        request.request_id.clone(),
                        request.clone(),
                    )
                    .await;
                }

                let result = crate::consensus::transfer::TransferVerificationResult {
                    request_id: request.request_id,
                    validator: self.node_info.id.clone(),
                    vote,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let response = Message::TransferVerificationResult { result };
                if let Err(e) = self.network.send_message(source.clone(), response).await {
                    log::error!("Failed to send transfer verification result: {}", e);
                }
            }
            Message::TransferVerificationResult { result } => {
                info!(
                    "Received transfer verification result: {}",
                    result.request_id
                );
                // The vote must come from the validator it claims to be (audit),
                // mirroring the withdrawal path: reject any whose claimed
                // validator does not match the authenticated gossip sender.
                if result.validator != source {
                    log::warn!(
                        "dropping transfer vote for {}: claimed validator {:?} != sender {:?}",
                        result.request_id,
                        result.validator,
                        source
                    );
                    return Ok(());
                }
                // Route the vote into the transfer coordinator (#194); a node
                // that never started this request drops it.
                if let Some(coordinator) = &self.transfer_coordinator {
                    if let Err(e) = coordinator.submit_result(result).await {
                        log::debug!("dropping transfer vote: {}", e);
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

    /// Co-sign a settlement transaction for the round leader (#260).
    ///
    /// We sign only a settlement we ourselves verified `Valid`, and only its
    /// security-critical parameters as we saw them in the gossiped verification
    /// request — recipient/amount/nullifier for a withdrawal, the nullifiers,
    /// output commitments and new root for a transfer. We then rebuild the
    /// transaction message from the payload and sign that, so we never sign an
    /// opaque transaction the leader assembled: a substituted recipient or
    /// amount fails the match and is declined. (The proof itself is not matched
    /// byte-for-byte — it is carried in a different encoding and is verified
    /// on-chain regardless; what matters is that the binding parameters are the
    /// ones we approved.)
    async fn handle_cosign_request(
        &self,
        _source: NodeId,
        request: CoSignRequest,
    ) -> Result<CoSignResponse> {
        Ok(cosign_settlement(
            self.cosign_keypair.as_ref(),
            &self.verified_withdrawals,
            &self.verified_transfers,
            request,
        )
        .await)
    }
}

/// Produce a co-sign response for `request` (#260): sign the rebuilt settlement
/// message iff we hold a keypair and the payload matches — by request id and
/// binding parameters — a settlement we verified `Valid`; otherwise decline
/// (`signature: None`). Free-standing so the security-critical decision can be
/// unit-tested without standing up a full node.
async fn cosign_settlement(
    cosign_keypair: Option<&Arc<Keypair>>,
    verified_withdrawals: &Arc<Mutex<HashMap<String, WithdrawalVerificationRequest>>>,
    verified_transfers: &Arc<Mutex<HashMap<String, TransferVerificationRequest>>>,
    request: CoSignRequest,
) -> CoSignResponse {
    let request_id = request.request_id.clone();
    let declined = |reason: &str| {
        log::warn!("declining co-sign for {}: {}", request_id, reason);
        CoSignResponse {
            request_id: request_id.clone(),
            wallet_pubkey: String::new(),
            signature: None,
        }
    };

    let keypair = match cosign_keypair {
        Some(kp) => kp,
        None => return declined("no settlement keypair configured"),
    };

    let payload = match CoSignPayload::from_bytes(&request.message) {
        Ok(p) => p,
        Err(e) => return declined(&format!("undecodable payload: {e}")),
    };

    // Match the payload against a settlement we verified Valid, by request id
    // and binding parameters.
    let approved = match (request.kind, &payload.params) {
        (
            SettlementKind::Withdrawal,
            SettlementParams::Withdrawal {
                recipient,
                amount,
                nullifier,
                ..
            },
        ) => {
            let cache = verified_withdrawals.lock().await;
            cache.get(&request.request_id).is_some_and(|req| {
                req.recipient == *recipient && req.amount == *amount && req.nullifier == *nullifier
            })
        }
        (
            SettlementKind::Transfer,
            SettlementParams::Transfer {
                nullifiers,
                output_commitments,
                new_merkle_root,
                ..
            },
        ) => {
            let cache = verified_transfers.lock().await;
            cache.get(&request.request_id).is_some_and(|req| {
                req.nullifiers == *nullifiers
                    && req.output_commitments == *output_commitments
                    && req.new_merkle_root == *new_merkle_root
            })
        }
        _ => false,
    };
    if !approved {
        return declined("parameters do not match a settlement we verified");
    }

    // Rebuild the exact settlement message ourselves and sign it.
    let message = match build_settlement_message(&payload) {
        Ok(m) => m,
        Err(e) => return declined(&format!("could not build settlement message: {e}")),
    };
    let signature = keypair.sign_message(&message.serialize());

    CoSignResponse {
        request_id,
        wallet_pubkey: keypair.pubkey().to_string(),
        signature: Some(signature.as_ref().to_vec()),
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

/// Drain the consensus approval channel, settling each withdrawal via
/// `submit` (#164).
///
/// The approval channel is local to the coordinator that reached quorum: only
/// the node that gathered the votes for a request — the one the client
/// submitted it to — emits an [`ApprovedWithdrawal`] here, so exactly one node
/// settles and there is nothing to gate. (An earlier version gated submission
/// on a deterministically-selected leader, assuming the approval was gossiped
/// to every node. It is not — the channel is in-process — so the chosen leader
/// usually did not hold the approval and the settlement was silently dropped.
/// Replay protection on the nullifier PDA still makes a duplicate submit safe
/// if the model ever changes to several nodes tallying independently.)
///
/// A per-message failure — including a replay whose nullifier is already spent
/// — is logged and skipped so it cannot kill the task and stall later
/// approvals.
async fn settle_approved_withdrawals<F, Fut>(
    mut rx: mpsc::UnboundedReceiver<ApprovedWithdrawal>,
    mut submit: F,
) where
    F: FnMut(ApprovedWithdrawal) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<String, crate::bridge::BridgeError>>,
{
    while let Some(approved) = rx.recv().await {
        let request_id = approved.request_id.clone();
        match submit(approved).await {
            Ok(sig) => info!("on-chain withdraw submitted for {}: {}", request_id, sig),
            Err(e) if is_replay_error(&e) => {
                log::debug!(
                    "withdrawal {} already settled (nullifier spent), skipping",
                    request_id
                )
            }
            Err(e) => log::warn!("withdrawal {} submit failed: {}", request_id, e),
        }
    }
}

/// Drain the transfer coordinator's approval channel and settle each approved
/// transfer on-chain (#194), the transfer twin of [`settle_approved_withdrawals`].
/// A per-message failure — including a replay whose nullifier is already spent —
/// is logged and skipped so it cannot stall later approvals.
async fn settle_approved_transfers<F, Fut>(
    mut rx: mpsc::UnboundedReceiver<ApprovedTransfer>,
    mut submit: F,
) where
    F: FnMut(ApprovedTransfer) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<String, crate::bridge::BridgeError>>,
{
    while let Some(approved) = rx.recv().await {
        let request_id = approved.request_id.clone();
        match submit(approved).await {
            Ok(sig) => info!("on-chain transfer settled for {}: {}", request_id, sig),
            Err(e) if is_replay_error(&e) => {
                log::debug!(
                    "transfer {} already settled (nullifier spent), skipping",
                    request_id
                )
            }
            Err(e) => log::warn!("transfer {} submit failed: {}", request_id, e),
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

        // Advertise the Solana wallet this node co-signs settlement with (#260)
        // so peers can map this NodeId to the on-chain `(wallet, pda)` pair the
        // settlement quorum requires. Derived from the bridge authority keypair
        // (the validator's settlement key); `None` for non-bridge nodes or when
        // the keypair is unavailable.
        let wallet_pubkey = settings
            .bridge
            .authority_keypair_path
            .as_deref()
            .and_then(|p| crate::bridge::solana::pubkey_from_file(p).ok());

        let node_info = NodeInfo {
            id: node_id.clone(),
            node_type: node_type.clone(),
            resources,
            address: settings.network.listen_address.clone(),
            wallet_pubkey,
        };

        // Load the full settlement keypair for co-signing (#260) — the same key
        // whose pubkey is advertised above. A node without it declines co-sign
        // requests rather than failing to start.
        let cosign_keypair = settings
            .bridge
            .authority_keypair_path
            .as_deref()
            .and_then(|p| match crate::bridge::solana::load_keypair_from_file(p) {
                Ok(kp) => Some(Arc::new(kp)),
                Err(e) => {
                    log::warn!("co-sign keypair unavailable ({e}); will decline co-sign requests");
                    None
                }
            });

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

        // Transfer consensus coordinator + its approval channel (#194), the
        // transfer twin of the withdrawal pair above.
        let (transfer_coordinator, transfer_approval_rx) = if runs_bridge {
            let (coord, rx) = TransferVerificationCoordinator::new_with_approvals();
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
            proof_verifier_override: None,
            withdrawal_ingress: Arc::new(Mutex::new(None)),
            transfer_coordinator,
            transfer_approval_rx: Arc::new(Mutex::new(transfer_approval_rx)),
            transfer_submitter_task: Arc::new(Mutex::new(None)),
            transfer_proof_verifier_override: None,
            transfer_ingress: Arc::new(Mutex::new(None)),
            delivered_notes: Arc::new(Mutex::new(Vec::new())),
            cosign_keypair,
            verified_withdrawals: Arc::new(Mutex::new(HashMap::new())),
            verified_transfers: Arc::new(Mutex::new(HashMap::new())),
        };

        Ok(node)
    }

    /// Inject a withdrawal-proof verifier, overriding the real Groth16 path
    /// (#181). Intended for the multi-node consensus E2E, whose goal is to
    /// exercise the libp2p gossip → vote → quorum wiring rather than the
    /// cryptographic proof itself (covered by the privacy circuit tests and
    /// the on-chain settlement test). Production never calls this, so
    /// verification always uses the real verifier.
    pub fn with_proof_verifier(mut self, verifier: WithdrawalProofVerifier) -> Self {
        self.proof_verifier_override = Some(verifier);
        self
    }

    /// Override the withdrawal-consensus quorum thresholds (#181, testing
    /// seam — deliberately NOT wired to any config file). Production builds
    /// the node via `new()`, which always uses the BFT-safe defaults
    /// (7-of-10); because these thresholds are unreachable from a settings
    /// file, an operator can never weaken the quorum by misconfiguration and
    /// there is no runtime attack surface — reaching this requires writing
    /// and compiling code. A multi-node E2E calls it to drive consensus with
    /// a small validator set (e.g. 3-of-5).
    ///
    /// Must be called right after `new()`, before `run()` clones the node:
    /// the coordinator is uniquely owned then, so `Arc::get_mut` succeeds.
    /// A no-op on a node with no withdrawal coordinator, or once cloned.
    pub fn with_consensus_thresholds(
        mut self,
        min_validators: usize,
        total_validators: usize,
    ) -> Self {
        if let Some(coordinator) = self.withdrawal_coordinator.as_mut().and_then(Arc::get_mut) {
            coordinator.set_consensus_thresholds(min_validators, total_validators);
        }
        self
    }

    /// Inject a transfer-proof verifier override (#194 testing seam), the
    /// transfer twin of [`with_proof_verifier`](Self::with_proof_verifier).
    pub fn with_transfer_proof_verifier(mut self, verifier: TransferProofVerifier) -> Self {
        self.transfer_proof_verifier_override = Some(verifier);
        self
    }

    /// Override the transfer-consensus quorum thresholds (#194 testing seam),
    /// the transfer twin of [`with_consensus_thresholds`](Self::with_consensus_thresholds).
    /// Must be called right after `new()`, before `run()` clones the node.
    pub fn with_transfer_consensus_thresholds(
        mut self,
        min_validators: usize,
        total_validators: usize,
    ) -> Self {
        if let Some(coordinator) = self.transfer_coordinator.as_mut().and_then(Arc::get_mut) {
            coordinator.set_consensus_thresholds(min_validators, total_validators);
        }
        self
    }

    /// Quorum status for a transfer verification this node initiated (#194).
    /// `Ok(Some(vote))` once a quorum is reached, `Ok(None)` while votes
    /// accumulate or on a node with no transfer coordinator.
    pub async fn transfer_consensus_status(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::consensus::vote_tally::VerificationVote>> {
        match &self.transfer_coordinator {
            Some(coordinator) => coordinator.check_consensus(request_id).await,
            None => Ok(None),
        }
    }

    /// `(valid, invalid)` transfer-vote tally for a request this node
    /// initiated (#194), the transfer twin of
    /// [`withdrawal_vote_counts`](Self::withdrawal_vote_counts). Lets a test
    /// confirm a byzantine validator's dissent reached the quorum and was
    /// outvoted. `Ok(None)` on a node with no transfer coordinator.
    pub async fn transfer_vote_counts(&self, request_id: &str) -> Result<Option<(usize, usize)>> {
        match &self.transfer_coordinator {
            Some(coordinator) => {
                let (_pct, valid, invalid) = coordinator.get_status(request_id).await?;
                Ok(Some((valid, invalid)))
            }
            None => Ok(None),
        }
    }

    /// Consensus status for a withdrawal verification this node initiated
    /// (#181). Delegates to the withdrawal coordinator's quorum check:
    /// `Ok(Some(vote))` once a validator quorum is reached, `Ok(None)` while
    /// votes are still accumulating, `Ok(None)` on a node with no withdrawal
    /// coordinator. Lets a test observe quorum without reaching into the
    /// node's internals.
    pub async fn withdrawal_consensus_status(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::consensus::withdrawal::VerificationVote>> {
        match &self.withdrawal_coordinator {
            Some(coordinator) => coordinator.check_consensus(request_id).await,
            None => Ok(None),
        }
    }

    /// Tally of `(valid, invalid)` votes seen so far for a withdrawal
    /// verification this node initiated (#181). Read-only view over the
    /// coordinator's status — lets a test confirm that a byzantine
    /// (Invalid-voting) validator's dissent actually reached the quorum and
    /// was outvoted, rather than just observing the final Valid result.
    /// `Ok(None)` on a node with no withdrawal coordinator.
    pub async fn withdrawal_vote_counts(&self, request_id: &str) -> Result<Option<(usize, usize)>> {
        match &self.withdrawal_coordinator {
            Some(coordinator) => {
                let (_pct, valid, invalid) = coordinator.get_status(request_id).await?;
                Ok(Some((valid, invalid)))
            }
            None => Ok(None),
        }
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

        // Declare our public address if the operator configured one
        // (#226). A relay server must advertise its own external
        // address or the reservations it grants carry no usable
        // circuit address; a non-relay node benefits too, since peers
        // learn a confirmed way to dial it.
        if let Some(external) = self.settings.network.external_address.clone() {
            if let Err(e) = self.network.add_external_address(&external).await {
                log::warn!("declaring external address failed: {}", e);
            }
        }

        // Connect to bootstrap nodes, retrying until at least one peer is
        // connected. A single dial is not guaranteed to land: the bootstrap
        // target may still be starting, or its event loop briefly busy (e.g. a
        // cold-start deposit backfill), and a one-shot dial would leave this
        // node permanently islanded — never sending Discovery, never being
        // registered for consensus. Re-dial on a short cadence until connected
        // or a bounded number of attempts elapse (the Kademlia refresh task
        // can still recover later).
        if !self.settings.network.bootstrap_nodes.is_empty() {
            let bootstrap = self.settings.network.bootstrap_nodes.clone();
            info!("Connecting to {} bootstrap nodes", bootstrap.len());

            const MAX_BOOTSTRAP_ATTEMPTS: u32 = 30;
            let mut connected = false;
            for attempt in 1..=MAX_BOOTSTRAP_ATTEMPTS {
                if let Err(e) = self.network.connect_to_bootstrap(bootstrap.clone()).await {
                    log::warn!("bootstrap dial attempt {} failed: {}", attempt, e);
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                if !self.network.connected_peers().await.is_empty() {
                    connected = true;
                    info!("bootstrap connected after {} attempt(s)", attempt);
                    break;
                }
            }
            if !connected {
                log::warn!(
                    "no bootstrap peers after {} attempts; relying on Kademlia refresh",
                    MAX_BOOTSTRAP_ATTEMPTS
                );
            }

            // Send discovery to every connected peer so they register this
            // node (validators learn the consensus set this way).
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

        // Reserve a relay slot AFTER bootstrap (#226). Order matters: when
        // relay_address points at a node we also bootstrap from (the common
        // case — the anchor is both bootstrap and relay), the bootstrap dial
        // has already established a connection, so the relay client reserves
        // over that existing connection instead of opening a second dial to
        // the same peer. Reserving before bootstrap raced the two dials;
        // libp2p coalesced them and the reservation's listener was silently
        // dropped, so the node never became reachable via the relay. Non-fatal
        // on error: the node still works for outbound traffic and direct
        // dials, it just isn't reachable through the relay.
        if let Some(relay) = self.settings.network.relay_address.clone() {
            info!("Reserving a relay slot on {}", relay);
            if let Err(e) = self.network.listen_via_relay(&relay).await {
                log::warn!("relay reservation failed: {}", e);
            }
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

        // Serve the withdrawal-verification ingress over HTTP (#184) so a
        // client (wallet/CLI) can submit a withdrawal into the consensus
        // mesh. Only runs on a node that has a withdrawal coordinator and a
        // configured address; an empty address (the default) disables it, an
        // unparseable one is logged and skipped rather than failing start-up.
        if self.withdrawal_coordinator.is_some() {
            let addr_str = self.settings.bridge.withdrawal_ingress_address.trim();
            if !addr_str.is_empty() {
                match addr_str.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let ingress: Arc<dyn withdrawal_ingress::WithdrawalIngress> =
                            Arc::new(self.clone());
                        let handle = tokio::spawn(async move {
                            if let Err(e) = withdrawal_ingress::serve(ingress, addr).await {
                                log::error!(
                                    target: "paraloom::node::withdrawal_ingress",
                                    "withdrawal ingress server exited: {}",
                                    e
                                );
                            }
                        });
                        *self.withdrawal_ingress.lock().await = Some(handle);
                        info!("Withdrawal ingress server started on {}", addr_str);
                    }
                    Err(e) => {
                        log::warn!(
                            "invalid bridge.withdrawal_ingress_address '{}': {} — ingress not started",
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
        if let (Some(bridge), Some(_coordinator), Some(rx)) = (
            self.bridge.clone(),
            self.withdrawal_coordinator.clone(),
            self.approval_rx.lock().await.take(),
        ) {
            let handle = tokio::spawn(settle_approved_withdrawals(rx, move |approved| {
                let bridge = bridge.clone();
                async move { bridge.lock().await.submit_approved(approved).await }
            }));
            *self.submitter_task.lock().await = Some(handle);
            info!("withdrawal submitter task started");
        }

        // Serve the transfer-verification ingress over HTTP (#194), the
        // transfer twin of the withdrawal ingress above.
        if self.transfer_coordinator.is_some() {
            let addr_str = self.settings.bridge.transfer_ingress_address.trim();
            if !addr_str.is_empty() {
                match addr_str.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let ingress: Arc<dyn transfer_ingress::TransferIngress> =
                            Arc::new(self.clone());
                        let handle = tokio::spawn(async move {
                            if let Err(e) = transfer_ingress::serve(ingress, addr).await {
                                log::error!(
                                    target: "paraloom::node::transfer_ingress",
                                    "transfer ingress server exited: {}",
                                    e
                                );
                            }
                        });
                        *self.transfer_ingress.lock().await = Some(handle);
                        info!("Transfer ingress server started on {}", addr_str);
                    }
                    Err(e) => {
                        log::warn!(
                            "invalid bridge.transfer_ingress_address '{}': {} — ingress not started",
                            addr_str,
                            e
                        );
                    }
                }
            }
        }

        // Settle consensus-approved transfers (#194), the transfer twin of the
        // withdrawal submitter task above.
        if let (Some(bridge), Some(_coordinator), Some(rx)) = (
            self.bridge.clone(),
            self.transfer_coordinator.clone(),
            self.transfer_approval_rx.lock().await.take(),
        ) {
            let handle = tokio::spawn(settle_approved_transfers(rx, move |approved| {
                let bridge = bridge.clone();
                async move { bridge.lock().await.submit_approved_transfer(approved).await }
            }));
            *self.transfer_submitter_task.lock().await = Some(handle);
            info!("transfer submitter task started");
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
        if let Some(handle) = self.withdrawal_ingress.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.transfer_submitter_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.transfer_ingress.lock().await.take() {
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

    /// Initiate distributed verification of a shielded transfer (#194), the
    /// transfer twin of [`initiate_withdrawal_verification`](Self::initiate_withdrawal_verification).
    /// Records the request with this node's transfer coordinator and broadcasts
    /// it over the gossip mesh; validators verify and vote, and the resulting
    /// approval is settled on-chain by this node's transfer submitter task.
    pub async fn initiate_transfer_verification(
        &self,
        request: crate::consensus::TransferVerificationRequest,
    ) -> Result<String> {
        let coordinator = self.transfer_coordinator.as_ref().ok_or_else(|| {
            anyhow!("node has no transfer coordinator (bridge disabled or non-validator)")
        })?;
        let request_id = coordinator.start_verification(request.clone()).await?;
        // Record the encrypted notes locally (#196): the initiator does not
        // receive its own gossip broadcast, so it stores here to serve scan.
        self.record_delivered_notes(&request.output_commitments, &request.ciphertexts)
            .await;
        self.network
            .send_message(
                NodeId(vec![]),
                Message::TransferVerificationRequest { request },
            )
            .await?;
        info!("initiated transfer verification: {}", request_id);
        Ok(request_id)
    }

    /// Record the encrypted output notes of a transfer for recipient scanning
    /// (#196), de-duplicated by `(commitment, ciphertext)` so the same transfer
    /// seen via both ingress and gossip is stored once.
    async fn record_delivered_notes(
        &self,
        output_commitments: &[[u8; 32]; 2],
        ciphertexts: &[String; 2],
    ) {
        let mut store = self.delivered_notes.lock().await;
        for (commitment, ciphertext) in output_commitments.iter().zip(ciphertexts.iter()) {
            let note = transfer_ingress::DeliveredNote {
                output_commitment: hex::encode(commitment),
                ciphertext: ciphertext.clone(),
            };
            if !store.iter().any(|d| {
                d.output_commitment == note.output_commitment && d.ciphertext == note.ciphertext
            }) {
                store.push(note);
            }
        }
    }

    /// Snapshot of the encrypted notes this node has seen (#196), for the
    /// `GET /transfer/scan` endpoint.
    pub async fn delivered_transfer_notes(&self) -> Vec<transfer_ingress::DeliveredNote> {
        self.delivered_notes.lock().await.clone()
    }

    /// Number of peers this node is currently connected to (#181). Read-only
    /// introspection over the network manager — lets a test wait for the
    /// gossip mesh to form before initiating a verification, so the broadcast
    /// is not dropped for want of mesh peers.
    pub async fn connected_peer_count(&self) -> usize {
        self.network.connected_peers().await.len()
    }

    /// Get node info
    pub fn node_info(&self) -> NodeInfo {
        self.node_info.clone()
    }

    /// Run the co-signing round for an approved withdrawal as the round leader
    /// and return the assembled, fully-signed settlement transaction (#260).
    ///
    /// Collects signatures from the validators that approved this withdrawal —
    /// mapped to their advertised settlement wallets — and assembles them to
    /// meet the on-chain validator quorum. `blockhash` and `expiration_slot` are
    /// supplied by the caller (the submitter fetches a live blockhash and bound;
    /// tests pass fixed values). This is the integration point the settlement
    /// submitter drives; it is `pub` so the multi-node end-to-end test can drive
    /// the same path.
    pub async fn cosign_settlement_tx(
        &self,
        approved: &ApprovedWithdrawal,
        blockhash: [u8; 32],
        expiration_slot: u64,
    ) -> Result<Transaction> {
        let leader = self
            .cosign_keypair
            .as_ref()
            .ok_or_else(|| anyhow!("no settlement keypair configured"))?;
        let coordinator = self
            .withdrawal_coordinator
            .as_ref()
            .ok_or_else(|| anyhow!("no withdrawal coordinator"))?;

        let program_id = Pubkey::from_str(&self.settings.bridge.program_id)
            .map_err(|e| anyhow!("invalid program id: {e}"))?;
        let (vault, _) = derive_bridge_vault(&program_id);

        // The validators that approved this withdrawal become the co-signer
        // quorum, mapped to the settlement wallets they advertised via
        // discovery. The leader signs as itself and is excluded from the peers
        // it requests from.
        let self_id = self.node_info.id.clone();
        let mut peers: Vec<(Pubkey, NodeId)> = Vec::new();
        for voter in coordinator.valid_voters(&approved.request_id).await {
            if voter == self_id {
                continue;
            }
            if let Some(wallet) = coordinator.validator_wallet(&voter).await {
                if let Ok(pubkey) = wallet.parse::<Pubkey>() {
                    peers.push((pubkey, voter));
                }
            }
        }
        let mut quorum_wallets = vec![leader.pubkey()];
        quorum_wallets.extend(peers.iter().map(|(w, _)| *w));

        // Every wallet in the set is marked a required signer in the
        // instruction, so the transaction is only valid once all of them have
        // signed: the gather threshold is the whole set. The on-chain program
        // enforces its own supermajority (programs/paraloom/src/quorum.rs) over
        // the registry, so if too few operators participated the assembled
        // transaction simply fails on submit rather than settling under-quorum.
        let threshold = quorum_wallets.len();

        // The on-chain program verifies the proof in its 256-byte alt_bn128 wire
        // form; convert the prover's compressed proof.
        let onchain_proof =
            crate::privacy::onchain_verifier::compressed_proof_to_onchain_bytes(&approved.proof)
                .map_err(|e| anyhow!("withdrawal proof: {e}"))?;
        let params = SettlementParams::Withdrawal {
            recipient: approved.recipient,
            amount: approved.amount,
            nullifier: approved.nullifier,
            expiration_slot,
            proof: onchain_proof.to_vec(),
        };

        let network = self.network.clone();
        cosign_round::run_cosign_round(
            leader,
            program_id,
            vault,
            blockhash,
            &approved.request_id,
            SettlementKind::Withdrawal,
            params,
            quorum_wallets,
            &peers,
            threshold,
            |peer, request| {
                let network = network.clone();
                async move { network.send_cosign_request(peer, request).await.ok() }
            },
        )
        .await
        .map_err(|e| anyhow!("co-signing round failed: {e}"))
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
        // Override seam (#181): when a verifier is injected, use it instead
        // of the real Groth16 path. Never set in production.
        if let Some(verifier) = &self.proof_verifier_override {
            return Ok(verifier(request));
        }

        // Delegate to the canonical withdrawal verifier (#184) so the
        // verifying key (the trusted-setup ceremony key) and the public-input
        // layout match the prover (`generate-withdrawal-proof`) exactly. The
        // earlier path here generated an ephemeral seed-0 key and lifted the
        // inputs with `bytes_to_field`, so a real proof never verified — it
        // only passed under the injected verifier above.
        let merkle_root = pool.root().await;
        let result = crate::privacy::ProofVerifier::verify_withdrawal_parts(
            &merkle_root,
            &request.nullifier,
            request.amount,
            &request.proof,
        );
        if let crate::privacy::VerificationResult::Invalid { reason } = &result {
            log::warn!(
                "withdrawal proof rejected for {}: {}",
                request.request_id,
                reason
            );
        }
        Ok(matches!(result, crate::privacy::VerificationResult::Valid))
    }

    /// Verify a transfer zkSNARK proof (#194), the transfer twin of
    /// [`verify_withdrawal_proof`](Self::verify_withdrawal_proof). The proof's
    /// membership root is the pool's *current* root (the request's
    /// `new_merkle_root` is the post-state, used only at settle), and the
    /// public inputs are `[root, nullifiers.., output_commitments..]`.
    async fn verify_transfer_proof(
        &self,
        request: &crate::consensus::transfer::TransferVerificationRequest,
        pool: &Arc<crate::privacy::pool::ShieldedPool>,
    ) -> Result<bool> {
        // Override seam (#194): use the injected verifier when present.
        if let Some(verifier) = &self.transfer_proof_verifier_override {
            return Ok(verifier(request));
        }

        let merkle_root = pool.root().await;
        let result = crate::privacy::ProofVerifier::verify_transfer_parts(
            &merkle_root,
            &request.nullifiers,
            &request.output_commitments,
            &request.proof,
        );
        if let crate::privacy::VerificationResult::Invalid { reason } = &result {
            log::warn!(
                "transfer proof rejected for {}: {}",
                request.request_id,
                reason
            );
        }
        Ok(matches!(result, crate::privacy::VerificationResult::Valid))
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
            proof_verifier_override: self.proof_verifier_override.clone(),
            withdrawal_ingress: self.withdrawal_ingress.clone(),
            transfer_coordinator: self.transfer_coordinator.clone(),
            transfer_approval_rx: self.transfer_approval_rx.clone(),
            transfer_submitter_task: self.transfer_submitter_task.clone(),
            transfer_proof_verifier_override: self.transfer_proof_verifier_override.clone(),
            transfer_ingress: self.transfer_ingress.clone(),
            delivered_notes: self.delivered_notes.clone(),
            cosign_keypair: self.cosign_keypair.clone(),
            verified_withdrawals: self.verified_withdrawals.clone(),
            verified_transfers: self.verified_transfers.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // --- #260 co-sign handler (cosign_settlement) ---

    fn wd_request(
        id: &str,
        recipient: [u8; 32],
        amount: u64,
        nullifier: [u8; 32],
    ) -> WithdrawalVerificationRequest {
        WithdrawalVerificationRequest {
            request_id: id.to_string(),
            nullifier,
            amount,
            recipient,
            proof: vec![0u8; 256],
            fee: 0,
            timestamp: 0,
        }
    }

    fn wd_payload(
        authority: [u8; 32],
        recipient: [u8; 32],
        amount: u64,
        nullifier: [u8; 32],
    ) -> CoSignPayload {
        CoSignPayload {
            program_id: [1u8; 32],
            authority,
            bridge_vault: [3u8; 32],
            blockhash: [4u8; 32],
            quorum_validators: vec![authority],
            params: SettlementParams::Withdrawal {
                recipient,
                amount,
                nullifier,
                expiration_slot: u64::MAX,
                proof: vec![0u8; 256],
            },
        }
    }

    fn cosign_req(id: &str, kind: SettlementKind, payload: &CoSignPayload) -> CoSignRequest {
        CoSignRequest {
            request_id: id.to_string(),
            kind,
            message: payload.to_bytes().expect("serialize payload"),
        }
    }

    #[tokio::test]
    async fn cosign_signs_a_settlement_we_verified() {
        let kp = Arc::new(Keypair::new());
        let wds = Arc::new(Mutex::new(HashMap::new()));
        let trs = Arc::new(Mutex::new(HashMap::new()));

        let (recipient, amount, nullifier) = ([9u8; 32], 1_000_000_000u64, [7u8; 32]);
        wds.lock()
            .await
            .insert("w1".into(), wd_request("w1", recipient, amount, nullifier));

        let payload = wd_payload(kp.pubkey().to_bytes(), recipient, amount, nullifier);
        let resp = cosign_settlement(
            Some(&kp),
            &wds,
            &trs,
            cosign_req("w1", SettlementKind::Withdrawal, &payload),
        )
        .await;

        assert_eq!(resp.request_id, "w1");
        assert_eq!(resp.wallet_pubkey, kp.pubkey().to_string());
        let sig_bytes = resp.signature.expect("must sign a settlement it verified");
        // The signature must verify against the message we would actually submit.
        let message = build_settlement_message(&payload).expect("build message");
        let sig = solana_sdk::signature::Signature::try_from(sig_bytes.as_slice()).expect("sig");
        assert!(
            sig.verify(&kp.pubkey().to_bytes(), &message.serialize()),
            "the returned signature must be valid over the rebuilt settlement message"
        );
    }

    #[tokio::test]
    async fn cosign_declines_a_substituted_recipient() {
        let kp = Arc::new(Keypair::new());
        let wds = Arc::new(Mutex::new(HashMap::new()));
        let trs = Arc::new(Mutex::new(HashMap::new()));

        let (recipient, amount, nullifier) = ([9u8; 32], 1_000_000_000u64, [7u8; 32]);
        wds.lock()
            .await
            .insert("w1".into(), wd_request("w1", recipient, amount, nullifier));

        // Leader tries to redirect the funds to a different recipient.
        let tampered = wd_payload(kp.pubkey().to_bytes(), [0xFF; 32], amount, nullifier);
        let resp = cosign_settlement(
            Some(&kp),
            &wds,
            &trs,
            cosign_req("w1", SettlementKind::Withdrawal, &tampered),
        )
        .await;
        assert_eq!(
            resp.signature, None,
            "a substituted recipient must be declined even though we verified the original"
        );
    }

    #[tokio::test]
    async fn cosign_declines_unknown_request_and_without_keypair() {
        let kp = Arc::new(Keypair::new());
        let wds = Arc::new(Mutex::new(HashMap::new()));
        let trs = Arc::new(Mutex::new(HashMap::new()));
        let payload = wd_payload(kp.pubkey().to_bytes(), [9u8; 32], 1, [7u8; 32]);

        // Never verified this request id.
        let unknown = cosign_settlement(
            Some(&kp),
            &wds,
            &trs,
            cosign_req("nope", SettlementKind::Withdrawal, &payload),
        )
        .await;
        assert_eq!(unknown.signature, None);

        // No keypair configured at all.
        wds.lock()
            .await
            .insert("w1".into(), wd_request("w1", [9u8; 32], 1, [7u8; 32]));
        let no_key = cosign_settlement(
            None,
            &wds,
            &trs,
            cosign_req("w1", SettlementKind::Withdrawal, &payload),
        )
        .await;
        assert_eq!(no_key.signature, None);
    }

    fn approval(id: &str) -> ApprovedWithdrawal {
        ApprovedWithdrawal {
            request_id: id.to_string(),
            nullifier: [0u8; 32],
            amount: 1,
            recipient: [0u8; 32],
            proof: Vec::new(),
            fee: 0,
        }
    }

    // Every approval on the channel is settled: the submitter does not gate on
    // leader selection. Regression for #164 — a leader gate here dropped
    // approvals because the channel is in-process, not gossiped, so the
    // deterministically-chosen leader rarely held the approval and the
    // settlement was silently lost.
    #[tokio::test]
    async fn settles_every_approval_without_gating() {
        let (tx, rx) = mpsc::unbounded_channel();
        for i in 0..3 {
            tx.send(approval(&format!("req-{i}"))).unwrap();
        }
        drop(tx);

        let submitted = Arc::new(AtomicUsize::new(0));
        let counter = submitted.clone();
        settle_approved_withdrawals(rx, move |_approved| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok("signature".to_string())
            }
        })
        .await;

        assert_eq!(submitted.load(Ordering::SeqCst), 3);
    }

    // A replay (nullifier already spent) is skipped quietly and does not stop
    // the task from settling later approvals.
    #[tokio::test]
    async fn replay_error_does_not_stall_later_approvals() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(approval("replayed")).unwrap();
        tx.send(approval("fresh")).unwrap();
        drop(tx);

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        settle_approved_withdrawals(rx, move |_approved| {
            let counter = counter.clone();
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Err(crate::bridge::BridgeError::InvalidTransaction(
                        "nullifier already spent".to_string(),
                    ))
                } else {
                    Ok("signature".to_string())
                }
            }
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

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
