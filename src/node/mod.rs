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
use crate::compute::{ComputeAuthPolicy, JobCoordinator, JobExecutor, JobManager};
use crate::config::Settings;
use crate::consensus::transact::TransactVerificationRequest;
use crate::consensus::{ApprovedTransact, TransactVerificationCoordinator};
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
pub mod ingress_auth;
pub mod transact_ingress;

/// Transact-proof verifier override (#350). `None` in production, so
/// `verify_transact_proof` runs the real Groth16 path; a multi-node consensus
/// E2E injects a closure to exercise the gossip → vote → quorum wiring without
/// proving (which is covered by the privacy circuit tests and the on-chain
/// settlement test).
pub type TransactProofVerifier =
    Arc<dyn Fn(&crate::consensus::transact::TransactVerificationRequest) -> bool + Send + Sync>;

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
    // Authorization policy for inbound compute-job submissions (F3): who may
    // submit and the per-job resource ceiling. Built from `[compute]` settings.
    compute_auth: ComputeAuthPolicy,
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

    /// Transact consensus coordinator (#350), the v3 unified-transact twin of
    /// the retired withdrawal/transfer coordinators. Incoming
    /// `TransactVerificationResult` votes
    /// route into it; a quorum-approved transact is pushed onto the approval
    /// channel below.
    transact_coordinator: Option<Arc<TransactVerificationCoordinator>>,

    /// Receiver half of the transact coordinator's approval channel (#350).
    /// Taken once by run() to drive the transact submitter task.
    transact_approval_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ApprovedTransact>>>>,

    /// Transact submitter task handle (#350): drains approved transacts and
    /// settles them on-chain. Spawned in run(), aborted in stop().
    transact_submitter_task: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Optional transact-proof verifier override (#350 testing seam). `None`
    /// in production.
    transact_proof_verifier_override: Option<TransactProofVerifier>,

    /// Transact-ingress HTTP server handle (#350). Spawned in run() when
    /// `bridge.transact_ingress_address` is set; aborted in stop().
    transact_ingress: Arc<Mutex<Option<JoinHandle<()>>>>,

    /// Encrypted output notes this node has seen (#196), served from
    /// `GET /transact/scan` for recipients to trial-decrypt. Populated when the
    /// node initiates or receives a transact verification request. In-memory;
    /// persistence across restart is a follow-up.
    delivered_notes: Arc<Mutex<Vec<transact_ingress::DeliveredNote>>>,

    /// This validator's Solana settlement keypair (#260), loaded from
    /// `bridge.authority_keypair_path`. Used to co-sign settlement transactions
    /// when another validator (the round leader) requests it. `None` on nodes
    /// without a configured keypair; such a node declines all co-sign requests.
    cosign_keypair: Option<Arc<Keypair>>,

    /// Transact requests this node verified as `Valid` (#260/#350), keyed by
    /// request id. A co-sign request is honoured only if its parameters match
    /// the request cached here — so the round leader cannot get this validator
    /// to sign a transact it never verified, nor one with a substituted
    /// recipient (the recipient is the one every validator saw in the gossiped
    /// request). Bounded by `MAX_VERIFIED_CACHE`; entries are short-lived.
    verified_transacts: Arc<Mutex<HashMap<String, TransactVerificationRequest>>>,

    /// Per-spend co-sign counter (#593/#606), keyed on the input nullifiers.
    /// The co-sign signature is this node's Solana fee-payer signature; capping
    /// how many times we sign one spend bounds how many fee-paying replays a
    /// peer can extract, while still leaving headroom for the leader's
    /// legitimate blockhash-expiry retries. Keyed on the nullifiers rather than
    /// the request id, so randomized proofs of the same spend cannot each claim
    /// a fresh budget.
    cosign_counts: Arc<Mutex<HashMap<String, u32>>>,
}

/// Build the compute-job authorization policy (F3) from `[compute]` settings.
/// An empty `authorized_submitters` list leaves submission open to any peer
/// (dev/demo); a non-empty list restricts submission to exactly those NodeIds.
/// A configured entry that is not valid hex is dropped with a warning — so a
/// list that parses to nothing is fail-closed, never silently open.
fn build_compute_auth_policy(cfg: &crate::config::ComputeSettings) -> ComputeAuthPolicy {
    use crate::compute::auth::{
        DEFAULT_MAX_INSTRUCTIONS, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_TIMEOUT_SECS,
    };
    let max_limits = crate::compute::ResourceLimits {
        max_memory_bytes: cfg.max_memory_bytes.unwrap_or(DEFAULT_MAX_MEMORY_BYTES),
        max_instructions: cfg.max_instructions.unwrap_or(DEFAULT_MAX_INSTRUCTIONS),
        timeout_secs: cfg.max_timeout_secs.unwrap_or(DEFAULT_MAX_TIMEOUT_SECS),
    };

    if cfg.authorized_submitters.is_empty() {
        return ComputeAuthPolicy::open().with_max_limits(max_limits);
    }

    let mut allowed = std::collections::HashSet::new();
    for entry in &cfg.authorized_submitters {
        match entry.parse::<NodeId>() {
            Ok(id) => {
                allowed.insert(id);
            }
            Err(e) => log::warn!(
                "Ignoring invalid compute authorized_submitter '{}': {}",
                entry,
                e
            ),
        }
    }
    ComputeAuthPolicy::restricted(allowed, max_limits)
}

/// Upper bound on the per-node verified-settlement caches (#260). Entries are
/// consumed within seconds of the vote (the co-sign round follows immediately),
/// so this is only a safety ceiling against unbounded growth, never a working
/// limit in practice.
const MAX_VERIFIED_CACHE: usize = 1024;

/// Maximum times this node will co-sign one spend, keyed on its input
/// nullifiers (#593/#606).
/// The co-sign signature is the node's Solana fee-payer signature, so an
/// unbounded count lets a peer reuse a single cached approval to extract fresh
/// fee-payer signatures and burn the hot authority's SOL on replays. A small
/// cap still covers the leader rebuilding with a fresh blockhash when the
/// previous one expires before the quorum submits.
const MAX_COSIGNS_PER_SETTLEMENT: u32 = 4;

/// Upper bound on the number of per-nullifier co-sign counters retained (#626).
/// The counter map is never explicitly cleared, so without a ceiling it grows
/// one entry per settled spend for the life of the process. This is a safety
/// ceiling, not a working limit: entries are consumed within a co-sign round,
/// and an evicted entry belongs to an older spend whose nullifiers have almost
/// certainly settled on chain (a replay of it fails there regardless).
const MAX_COSIGN_COUNTS: usize = 1024;

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

                // Mirror the registration into the transact coordinator (#350)
                // so it knows the validator set: start_verification requires a
                // quorum-sized set, and leader selection weighs these members.
                // Independent of the compute coordinator above — a
                // bridge-enabled validator node has the former without being a
                // compute Coordinator.
                if let Some(transact) = &self.transact_coordinator {
                    if node_info.node_type == NodeType::ResourceProvider {
                        transact
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
                    coordinator.handle_task_result(&source, result).await?;
                }
            }
            Message::TaskError { task_id, error } => {
                if let Some(coordinator) = &self.coordinator {
                    coordinator.handle_task_error(task_id, error).await?;
                }
            }

            // Privacy-related messages
            Message::ShieldedTransaction { transaction } => {
                // This gossip message mutates shielded-pool state (nullifier set and
                // commitment tree) directly, with no zk-proof verification and no
                // authentication of the sender. No honest code path ever publishes it
                // (the real, proof-gated flow is TransactVerificationRequest),
                // so any traffic on this variant is
                // unauthenticated and untrusted. Applying it would let any mesh peer
                // mark arbitrary nullifiers spent (bricking honest notes) or append
                // junk commitments (corrupting the Merkle root that proof verification
                // is checked against). Drop it without touching pool state. The variant
                // is retained so the wire enum's discriminants stay stable for deployed
                // nodes; it is simply ignored.
                log::warn!(
                    "Ignoring unauthenticated ShieldedTransaction gossip ({}); \
                     proof-gated settlement goes through the verification-request path",
                    transaction.id()
                );
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

                // Only accept a result attributed to the authenticated sender —
                // a peer must not report a result under another validator's
                // identity. Parity with the transact vote path's
                // `result.validator == source` guard. The `verification_coordinator`
                // is not wired today (always `None`), so this handler is dormant;
                // the check keeps it safe against impersonation if it is ever wired.
                if validator_id != source {
                    log::warn!(
                        "dropping VerificationResult: claimed validator {:?} != authenticated source {:?}",
                        validator_id,
                        source
                    );
                } else if let Some(coord) = &self.verification_coordinator {
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
            Message::TransactVerificationRequest { request } => {
                // Bind the request id to the settlement content (#383): reject any
                // request whose id is not the canonical digest of its fields, so a
                // peer cannot choose an id to overwrite/poison a cache entry or
                // collide two distinct transacts onto one verification round.
                let canonical = request.canonical_id();
                if request.request_id != canonical {
                    log::warn!(
                        "Dropping transact request with non-canonical id {} (expected {})",
                        request.request_id,
                        canonical
                    );
                    return Ok(());
                }

                info!(
                    "Received transact verification request: {}",
                    request.request_id
                );

                // Verify the transact zkSNARK proof, mirroring the transfer
                // path (#350). Unlike a transfer, the v3 proof binds
                // `request.root` directly (the on-chain incremental-tree root
                // carried in the request), so verification needs no pool
                // state; the pool gate below only keeps non-bridge nodes from
                // voting on settlements they do not participate in.
                let vote = if self.shielded_pool.is_some() {
                    match self.verify_transact_proof(&request).await {
                        Ok(true) => {
                            info!(
                                "Transact proof verified successfully: {}",
                                request.request_id
                            );
                            // Record the encrypted output notes for recipient
                            // scanning (#196) only AFTER the proof verifies, and
                            // only the FIRST time we see this canonical settlement
                            // (#382). The ciphertexts are not proof-bound, so a
                            // replay of the same valid transact with mutated
                            // ciphertexts carries the same canonical id; gating on
                            // first-seen id keeps such a replay from adding extra
                            // scan records for the same commitments and evicting
                            // the authentic ciphertext.
                            let already_seen = self
                                .verified_transacts
                                .lock()
                                .await
                                .contains_key(&request.request_id);
                            if !already_seen {
                                self.record_delivered_notes(
                                    &request.output_commitments,
                                    &request.ciphertexts,
                                )
                                .await;
                            }
                            crate::consensus::vote_tally::VerificationVote::Valid
                        }
                        Ok(false) => {
                            log::warn!(
                                "Transact proof verification failed: {}",
                                request.request_id
                            );
                            crate::consensus::vote_tally::VerificationVote::Invalid {
                                reason: "Proof verification failed".to_string(),
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Error verifying transact proof {}: {}",
                                request.request_id,
                                e
                            );
                            crate::consensus::vote_tally::VerificationVote::Invalid {
                                reason: format!("Verification error: {}", e),
                            }
                        }
                    }
                } else {
                    log::warn!("Privacy pool not available, cannot verify transact proof");
                    crate::consensus::vote_tally::VerificationVote::Invalid {
                        reason: "Privacy pool not available".to_string(),
                    }
                };

                // Remember a transact we verified Valid so we can later co-sign
                // its settlement against the exact parameters we saw (#260).
                if matches!(vote, crate::consensus::vote_tally::VerificationVote::Valid) {
                    cache_verified(
                        &self.verified_transacts,
                        request.request_id.clone(),
                        request.clone(),
                    )
                    .await;
                }

                let result = crate::consensus::transact::TransactVerificationResult {
                    request_id: request.request_id,
                    validator: self.node_info.id.clone(),
                    vote,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let response = Message::TransactVerificationResult { result };
                if let Err(e) = self.network.send_message(source.clone(), response).await {
                    log::error!("Failed to send transact verification result: {}", e);
                }
            }
            Message::TransactVerificationResult { result } => {
                info!(
                    "Received transact verification result: {}",
                    result.request_id
                );
                // The vote must come from the validator it claims to be (audit),
                // mirroring the withdrawal path: reject any whose claimed
                // validator does not match the authenticated gossip sender.
                if result.validator != source {
                    log::warn!(
                        "dropping transact vote for {}: claimed validator {:?} != sender {:?}",
                        result.request_id,
                        result.validator,
                        source
                    );
                    return Ok(());
                }
                // Route the vote into the transact coordinator (#350); a node
                // that never started this request drops it.
                if let Some(coordinator) = &self.transact_coordinator {
                    if let Err(e) = coordinator.submit_result(result).await {
                        log::debug!("dropping transact vote: {}", e);
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

                    // Authorize the submitter and its requested limits BEFORE
                    // the bytecode reaches the executor (F3): an unauthorized
                    // or over-sized request is refused without ever being
                    // compiled, run, or stored.
                    if let Err(deny) = self.compute_auth.authorize(&source, &limits) {
                        log::warn!("Rejecting compute job {} from {}: {}", job_id, source, deny);
                        let response = Message::ComputeJobResponse {
                            job_id,
                            accepted: false,
                            message: format!("Job rejected: {}", deny),
                        };
                        if let Err(e) = self.network.send_message(source, response).await {
                            log::error!("Failed to send compute job response: {}", e);
                        }
                        return Ok(());
                    }

                    // Refuse a new job when the pending queue is full, before
                    // committing any per-job state (coordinator map, storage),
                    // so a flood of authorized-but-excess jobs cannot exhaust
                    // memory or disk and a rejected job leaves no residue (#610).
                    if !executor.has_pending_capacity() {
                        log::warn!(
                            "Rejecting compute job {} from {}: pending queue full",
                            job_id,
                            source
                        );
                        let response = Message::ComputeJobResponse {
                            job_id,
                            accepted: false,
                            message: "Job rejected: pending queue full".to_string(),
                        };
                        if let Err(e) = self.network.send_message(source, response).await {
                            log::error!("Failed to send compute job response: {}", e);
                        }
                        return Ok(());
                    }

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
            match coordinator
                .handle_task_result(&source, request.result)
                .await
            {
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
        source: NodeId,
        request: crate::network::HeartbeatRequest,
    ) -> Result<crate::network::HeartbeatResponse> {
        if let Some(coordinator) = &self.coordinator {
            Ok(coordinator.apply_heartbeat(&source, request).await)
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
        // Pin the program to our own config before the signer sees the request:
        // an unparseable configured id means we cannot bind it, so decline
        // rather than sign against a requester-supplied program.
        let expected_program_id = match self.settings.bridge.program_id.parse::<Pubkey>() {
            Ok(p) => p,
            Err(_) => {
                return Ok(CoSignResponse {
                    request_id: request.request_id,
                    wallet_pubkey: String::new(),
                    signature: None,
                });
            }
        };
        Ok(cosign_settlement(
            self.cosign_keypair.as_ref(),
            &expected_program_id,
            &self.verified_transacts,
            &self.cosign_counts,
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
    expected_program_id: &Pubkey,
    verified_transacts: &Arc<Mutex<HashMap<String, TransactVerificationRequest>>>,
    cosign_counts: &Arc<Mutex<HashMap<String, u32>>>,
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

    // Pin the program to our own configuration: never sign a settlement message
    // that invokes a program the requester chose, which would turn the validator
    // into a cross-program signing oracle for its settlement wallet.
    if payload.program_id != expected_program_id.to_bytes() {
        return declined("payload program id does not match our configured program");
    }

    // Match the payload against a settlement we verified Valid, by request id
    // and binding parameters, and take the input nullifiers as the per-nullifier
    // cap keys (see the cap block below for why the cap is keyed on those).
    let (approved, cap_nullifiers) = match (request.kind, &payload.params) {
        (
            SettlementKind::Transact,
            SettlementParams::Transact {
                recipient,
                nullifiers,
                output_commitments,
                root,
                ext_amount,
                ..
            },
        ) => {
            let cache = verified_transacts.lock().await;
            let approved = cache.get(&request.request_id).is_some_and(|req| {
                req.recipient == *recipient
                    && req.nullifiers == *nullifiers
                    && req.output_commitments == *output_commitments
                    && req.root == *root
                    && req.ext_amount == *ext_amount
            });
            // Cap keys = the two input nullifiers, each counted independently
            // (see the cap block for why per-nullifier, not per-pair).
            let cap_nullifiers = [hex::encode(nullifiers[0]), hex::encode(nullifiers[1])];
            (approved, cap_nullifiers)
        }
    };
    if !approved {
        return declined("parameters do not match a settlement we verified");
    }

    // Rebuild the exact settlement message ourselves and sign it.
    let message = match build_settlement_message(&payload) {
        Ok(m) => m,
        Err(e) => return declined(&format!("could not build settlement message: {e}")),
    };

    // Bound how many fee-payer signatures one spend can yield (#593), keyed on
    // each input nullifier independently — NOT the request id and NOT the
    // nullifier pair (#606):
    //
    // - `request_id` is the canonical hash of the request including the Groth16
    //   proof bytes, and proving is randomized, so one spend has many valid
    //   proofs and thus many request ids: keying on it let a peer reset the cap
    //   with a fresh proof.
    // - The nullifier *pair* is not invariant either: a 2-input transact can
    //   carry a zero-amount dummy whose nullifier the requester chooses freely,
    //   so pairing a fixed real note with different dummies yields fresh pair
    //   keys.
    //
    // A value-spending transact has at least one real input note whose
    // nullifier is fixed and appears in every equivalent settlement the peer
    // can build. Counting each nullifier on its own catches that fixed one
    // however the proof or the dummy input is perturbed. Nullifiers are unique
    // per note, so this never restricts distinct legitimate spends. Only a
    // settlement we approved and could rebuild reaches here, so a mismatched or
    // undecodable request is declined earlier and never spends the budget.
    {
        let mut counts = cosign_counts.lock().await;
        if cap_nullifiers
            .iter()
            .any(|nf| counts.get(nf).copied().unwrap_or(0) >= MAX_COSIGNS_PER_SETTLEMENT)
        {
            return declined("co-sign count limit reached for an input nullifier");
        }
        for nf in cap_nullifiers {
            // Bound the map so it cannot grow without limit as settlements
            // accumulate (#626): if a new nullifier would exceed the ceiling,
            // drop an arbitrary existing entry first. An evicted entry belongs
            // to an older spend whose nullifiers have almost certainly settled
            // on chain, so resetting its budget is harmless.
            if !counts.contains_key(&nf) && counts.len() >= MAX_COSIGN_COUNTS {
                if let Some(victim) = counts.keys().next().cloned() {
                    counts.remove(&victim);
                }
            }
            *counts.entry(nf).or_insert(0) += 1;
        }
    }

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

/// Drain the transact coordinator's approval channel and settle each approved
/// unified transact on-chain (#350). The approval channel is local to the
/// coordinator that reached quorum, so exactly one node settles.
/// A per-message failure — including a replay whose nullifier is already spent —
/// is logged and skipped so it cannot stall later approvals.
async fn settle_approved_transacts<F, Fut>(
    mut rx: mpsc::UnboundedReceiver<ApprovedTransact>,
    mut submit: F,
) where
    F: FnMut(ApprovedTransact) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<String, crate::bridge::BridgeError>>,
{
    // A settlement that fails on a transient error — an expired blockhash, a
    // co-signer briefly offline, a co-sign wallet not yet gossiped — must not be
    // dropped: the approval is emitted exactly once and never re-emitted, so
    // dropping it strands the transact permanently (recoverable only by the
    // client re-proving into a new canonical id). Retry the whole cosign+submit
    // a few times with a short backoff. Re-settling an attempt that actually
    // landed on-chain is safe — its nullifier is already spent, so the retry
    // returns a replay error and is skipped here.
    const MAX_SETTLE_ATTEMPTS: u32 = 3;
    const SETTLE_RETRY_BACKOFF: Duration = Duration::from_secs(2);
    while let Some(approved) = rx.recv().await {
        let request_id = approved.request.request_id.clone();
        for attempt in 1..=MAX_SETTLE_ATTEMPTS {
            match submit(approved.clone()).await {
                Ok(sig) => {
                    info!("on-chain transact settled for {}: {}", request_id, sig);
                    break;
                }
                Err(e) if is_replay_error(&e) => {
                    log::debug!(
                        "transact {} already settled (nullifier spent), skipping",
                        request_id
                    );
                    break;
                }
                Err(e) if attempt < MAX_SETTLE_ATTEMPTS => {
                    log::warn!(
                        "transact {} submit attempt {}/{} failed, retrying: {}",
                        request_id,
                        attempt,
                        MAX_SETTLE_ATTEMPTS,
                        e
                    );
                    tokio::time::sleep(SETTLE_RETRY_BACKOFF).await;
                }
                Err(e) => log::warn!(
                    "transact {} submit failed after {} attempts: {}",
                    request_id,
                    MAX_SETTLE_ATTEMPTS,
                    e
                ),
            }
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

        let compute_auth = build_compute_auth_policy(&settings.compute);

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
            // Persist the deposit listener's scan cursor under the node's data
            // directory so a restart resumes where it left off instead of
            // re-scanning from the chain tip and losing deposits taken while down.
            let mut bridge_cfg = settings.bridge.clone();
            bridge_cfg.cursor_path =
                Some(format!("{}/bridge_cursor", settings.storage.data_dir).into());
            Some(Arc::new(Mutex::new(Bridge::new(bridge_cfg))))
        } else {
            None
        };

        // Withdrawal consensus coordinator + its approval channel (#164).
        // Built only on bridge-enabled validator/bridge nodes; the
        // receiver is held until run() spawns the submitter task.
        // Transact consensus coordinator + its approval channel (#350); the
        // receiver is held until run() spawns the transact submitter task. This
        // is the sole settlement consensus flow (the legacy off-chain-root
        // withdrawal/transfer coordinators were removed).
        let (transact_coordinator, transact_approval_rx) = if runs_bridge {
            let (mut coord, rx) = TransactVerificationCoordinator::new_with_approvals();
            // This node is the settlement authority it would submit under, so
            // the off-chain quorum can mirror the on-chain stake-weighted check
            // and exclude it exactly as the program does (#611).
            coord = coord.with_local_node_id(node_id.clone());
            // Optional config override of the BFT consensus defaults (7/10/rep200).
            // Unset on mainnet → the secure defaults stand; devnet lowers them in
            // validator.toml to settle with a small live cohort (2/2), otherwise
            // it never reaches a Valid quorum and settlement silently times out.
            // The on-chain stake-weighted 2/3 quorum stays the real security gate.
            if let (Some(min), Some(total)) = (
                settings.bridge.consensus_min_validators,
                settings.bridge.consensus_total_validators,
            ) {
                coord.set_consensus_thresholds(min, total);
            }
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
            compute_auth,
            job_coordinators: Arc::new(Mutex::new(std::collections::HashMap::new())),
            ha_broadcast: Arc::new(Mutex::new(None)),
            ha_watchdog: Arc::new(Mutex::new(None)),
            kad_refresh: Arc::new(Mutex::new(None)),
            transact_coordinator,
            transact_approval_rx: Arc::new(Mutex::new(transact_approval_rx)),
            transact_submitter_task: Arc::new(Mutex::new(None)),
            transact_proof_verifier_override: None,
            transact_ingress: Arc::new(Mutex::new(None)),
            delivered_notes: Arc::new(Mutex::new(Vec::new())),
            cosign_keypair,
            verified_transacts: Arc::new(Mutex::new(HashMap::new())),
            cosign_counts: Arc::new(Mutex::new(HashMap::new())),
        };

        Ok(node)
    }

    /// Inject a transact-proof verifier override (#350 testing seam),
    /// overriding the real Groth16 path so a multi-node consensus E2E can
    /// exercise the libp2p gossip → vote → quorum wiring rather than the
    /// cryptographic proof itself (covered by the privacy circuit tests and
    /// the on-chain settlement test). Production never calls this.
    pub fn with_transact_proof_verifier(mut self, verifier: TransactProofVerifier) -> Self {
        self.transact_proof_verifier_override = Some(verifier);
        self
    }

    /// Override the transact-consensus quorum thresholds (#350 testing seam),
    /// the transact twin of [`with_consensus_thresholds`](Self::with_consensus_thresholds).
    /// Must be called right after `new()`, before `run()` clones the node.
    pub fn with_transact_consensus_thresholds(
        mut self,
        min_validators: usize,
        total_validators: usize,
    ) -> Self {
        if let Some(coordinator) = self.transact_coordinator.as_mut().and_then(Arc::get_mut) {
            coordinator.set_consensus_thresholds(min_validators, total_validators);
        }
        self
    }

    /// Quorum status for a transact verification this node initiated (#350).
    /// `Ok(Some(vote))` once a quorum is reached, `Ok(None)` while votes
    /// accumulate or on a node with no transact coordinator.
    pub async fn transact_consensus_status(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::consensus::vote_tally::VerificationVote>> {
        match &self.transact_coordinator {
            Some(coordinator) => coordinator.check_consensus(request_id).await,
            None => Ok(None),
        }
    }

    /// `(valid, invalid)` transact-vote tally for a request this node
    /// initiated (#350), the transact twin of
    /// [`transfer_vote_counts`](Self::transfer_vote_counts). `Ok(None)` on a
    /// node with no transact coordinator.
    pub async fn transact_vote_counts(&self, request_id: &str) -> Result<Option<(usize, usize)>> {
        match &self.transact_coordinator {
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
        }

        // Re-announce this node's NodeInfo (+ co-signing wallet) on a fixed
        // cadence, unconditionally, on EVERY node. The previous one-shot publish
        // was gated on having bootstrap peers, so the anchor — which has none —
        // never announced itself, and a single publish was lost whenever a peer
        // joined later, restarted, or missed the unformed-mesh window. A
        // periodic broadcast (the first tick fires immediately) means every peer
        // (re)learns the consensus set within one interval; combined with
        // gossipsub flood_publish the first announce lands even before the mesh
        // grafts. `send_message(NodeId(vec![]), ..)` publishes to the whole
        // gossip topic — the peer argument is ignored by the network layer.
        {
            const DISCOVERY_REANNOUNCE_INTERVAL: std::time::Duration =
                std::time::Duration::from_secs(15);
            let me = self.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(DISCOVERY_REANNOUNCE_INTERVAL);
                loop {
                    tick.tick().await;
                    let msg = Message::Discovery {
                        node_info: me.node_info.clone(),
                    };
                    if let Err(e) = me.network.send_message(NodeId(vec![]), msg).await {
                        log::debug!("periodic discovery re-announce failed: {e}");
                    }
                }
            });
        }

        // Reconcile the consensus validator set against live connectivity. The
        // periodic Discovery re-announce above carries each peer's NodeInfo +
        // co-sign wallet, but it is still best-effort gossip; a peer that
        // connected in a gap, or any coordinator that just restarted, could
        // otherwise sit with an empty in-memory set and reject withdrawals with
        // "No validators available". This backstop registers every currently
        // connected libp2p peer (wallet `None`) and unregisters peers that have
        // dropped, so the set tracks real connectivity independent of gossip
        // timing. A wallet learned via Discovery is preserved — registration is
        // wallet-preserving — and is what the #260 co-sign step uses.
        if self.transact_coordinator.is_some() {
            let network = Arc::clone(&self.network);
            let transact = self.transact_coordinator.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
                let mut registered: std::collections::HashSet<NodeId> =
                    std::collections::HashSet::new();
                loop {
                    ticker.tick().await;
                    let connected: std::collections::HashSet<NodeId> =
                        network.connected_peers().await.into_iter().collect();
                    for peer in connected.difference(&registered) {
                        if let Some(t) = &transact {
                            t.register_validator_with_wallet(peer.clone(), None).await;
                        }
                    }
                    for peer in registered.difference(&connected) {
                        if let Some(t) = &transact {
                            t.unregister_validator(peer).await;
                        }
                    }
                    registered = connected;
                }
            });
            info!("Consensus validator-set reconciler spawned (interval 30s)");
        }

        // On-chain stake reconciler (#333/#627/#611). The connectivity
        // reconciler above registers peers with ZERO stake; this task reads
        // every validator's real stake from its on-chain `ValidatorAccount`
        // (one `getProgramAccounts` call) and applies it to the consensus set,
        // keyed by co-sign wallet. The stake-weighted quorum then reflects real
        // at-risk capital — an unregistered/unstaked peer carries no weight and
        // cannot Sybil its way to a supermajority. Fail-closed: any validator
        // whose wallet has no active on-chain account stays at 0.
        if let (Some(bridge), Some(transact)) =
            (self.bridge.clone(), self.transact_coordinator.clone())
        {
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    ticker.tick().await;
                    let stakes = { bridge.lock().await.list_validator_stakes().await };
                    match stakes {
                        Ok(list) => {
                            let map: std::collections::HashMap<String, u64> = list
                                .into_iter()
                                .map(|(wallet, stake)| (wallet.to_string(), stake))
                                .collect();
                            transact.sync_onchain_stakes(map).await;
                        }
                        Err(e) => {
                            log::debug!("on-chain stake reconcile skipped this tick: {e}")
                        }
                    }
                }
            });
            info!("On-chain validator-stake reconciler spawned (interval 60s)");
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

        // Sweep timed-out verification entries so the consensus pending maps
        // cannot grow unbounded. The ingress write-surface inserts a request
        // before any proof check, and entries that never reach quorum were
        // never reclaimed; this drives the existing per-coordinator cleanup.
        if self.transact_coordinator.is_some() {
            let transact = self.transact_coordinator.clone();
            let status_clone = self.status.clone();
            tokio::spawn(async move {
                loop {
                    let current_status = status_clone.lock().await.clone();
                    if !matches!(current_status, NodeStatus::Running) {
                        info!("Verification timeout sweeper shutting down");
                        break;
                    }
                    if let Some(t) = &transact {
                        if let Ok(n) = t.cleanup_timeouts().await {
                            if n > 0 {
                                info!("Swept {} timed-out transact verifications", n);
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                }
            });
            info!("Verification timeout sweeper started");
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

        // Serve the transact-verification ingress over HTTP (#350) so a client
        // (wallet/CLI) can submit a settlement into the consensus mesh. Only
        // runs on a node that has a transact coordinator and a configured
        // address; an empty address (the default) disables it, an unparseable
        // one is logged and skipped rather than failing start-up.
        if self.transact_coordinator.is_some() {
            let addr_str = self.settings.bridge.transact_ingress_address.trim();
            if !addr_str.is_empty() {
                match addr_str.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        let ingress: Arc<dyn transact_ingress::TransactIngress> =
                            Arc::new(self.clone());
                        let token =
                            ingress_auth::token_from_config(&self.settings.bridge.ingress_token);
                        let handle = tokio::spawn(async move {
                            if let Err(e) = transact_ingress::serve(ingress, addr, token).await {
                                log::error!(
                                    target: "paraloom::node::transact_ingress",
                                    "transact ingress server exited: {}",
                                    e
                                );
                            }
                        });
                        *self.transact_ingress.lock().await = Some(handle);
                        info!("Transact ingress server started on {}", addr_str);
                    }
                    Err(e) => {
                        log::warn!(
                            "invalid bridge.transact_ingress_address '{}': {} — ingress not started",
                            addr_str,
                            e
                        );
                    }
                }
            }
        }

        // Settle consensus-approved unified transacts (#350). The `transact`
        // instruction settles exclusively through the #260 co-signing quorum
        // (no single-key fallback), so a node without a settlement keypair logs
        // each approval's failure rather than settling it single-key.
        if let (Some(_bridge), Some(_coordinator), Some(rx)) = (
            self.bridge.clone(),
            self.transact_coordinator.clone(),
            self.transact_approval_rx.lock().await.take(),
        ) {
            let node = self.clone();
            let handle = tokio::spawn(settle_approved_transacts(rx, move |approved| {
                let node = node.clone();
                async move { node.settle_transact_via_cosign(approved).await }
            }));
            *self.transact_submitter_task.lock().await = Some(handle);
            info!("transact submitter task started (co-signing)");
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
        if let Some(handle) = self.transact_submitter_task.lock().await.take() {
            handle.abort();
        }
        if let Some(handle) = self.transact_ingress.lock().await.take() {
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

    /// Initiate distributed verification of a v3 unified transact (#350).
    /// Records the request with this node's transact coordinator and broadcasts
    /// it over the gossip mesh; validators verify and vote. The approval a
    /// quorum produces is queued on `transact_approval_rx` for the transact
    /// submitter task to settle on-chain.
    pub async fn initiate_transact_verification(
        &self,
        request: crate::consensus::TransactVerificationRequest,
    ) -> Result<String> {
        let coordinator = self.transact_coordinator.as_ref().ok_or_else(|| {
            anyhow!("node has no transact coordinator (bridge disabled or non-validator)")
        })?;
        let request_id = coordinator.start_verification(request.clone()).await?;

        // The initiator does not receive its own gossip broadcast, so it must
        // self-verify and submit its own vote (registering self into the
        // validator set first so it is non-empty) — the withdrawal/transfer
        // twins do the same. Without it a 2-node cohort only ever collects the
        // remote vote and never reaches the quorum. Still one vote toward the
        // BFT threshold, not a bypass of it.
        {
            let self_id = self.node_info.id.clone();
            let wallet = self.cosign_keypair.as_ref().map(|k| k.pubkey().to_string());
            coordinator
                .register_validator_with_wallet(self_id.clone(), wallet)
                .await;
            let vote = match self.verify_transact_proof(&request).await {
                Ok(true) => {
                    // Record the encrypted notes (#196) only AFTER the proof
                    // verifies and only the first time we see this canonical
                    // settlement — mirroring the mesh path (#382). Recording
                    // before verify would let an invalid proof leave notes;
                    // recording on every sighting would let a replay with
                    // mutated (non-proof-bound) ciphertexts pollute and
                    // FIFO-evict the authentic ciphertext.
                    let already_seen = self
                        .verified_transacts
                        .lock()
                        .await
                        .contains_key(&request_id);
                    if !already_seen {
                        self.record_delivered_notes(
                            &request.output_commitments,
                            &request.ciphertexts,
                        )
                        .await;
                    }
                    cache_verified(
                        &self.verified_transacts,
                        request_id.clone(),
                        request.clone(),
                    )
                    .await;
                    crate::consensus::vote_tally::VerificationVote::Valid
                }
                Ok(false) => crate::consensus::vote_tally::VerificationVote::Invalid {
                    reason: "self-verify: proof verification failed".to_string(),
                },
                Err(e) => crate::consensus::vote_tally::VerificationVote::Invalid {
                    reason: format!("self-verify error: {e}"),
                },
            };
            let result = crate::consensus::TransactVerificationResult {
                request_id: request_id.clone(),
                validator: self_id,
                vote,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
            if let Err(e) = coordinator.submit_result(result).await {
                log::debug!("self-vote submit_result dropped for {request_id}: {e}");
            }
        }

        self.network
            .send_message(
                NodeId(vec![]),
                Message::TransactVerificationRequest { request },
            )
            .await?;
        info!("initiated transact verification: {}", request_id);
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
        // Bound the in-memory scan buffer so a high volume of transfers cannot
        // grow it without limit (this records only proof-verified transfers, so
        // it is not cheaply floodable, but the bound is defence in depth).
        const MAX_DELIVERED_NOTES: usize = 50_000;

        let mut store = self.delivered_notes.lock().await;
        for (commitment, ciphertext) in output_commitments.iter().zip(ciphertexts.iter()) {
            let note = transact_ingress::DeliveredNote {
                output_commitment: hex::encode(commitment),
                ciphertext: ciphertext.clone(),
            };
            if store.iter().any(|d| {
                d.output_commitment == note.output_commitment && d.ciphertext == note.ciphertext
            }) {
                continue;
            }
            // Evict the oldest note when at capacity (FIFO).
            if store.len() >= MAX_DELIVERED_NOTES {
                store.remove(0);
            }
            store.push(note);
        }
    }

    /// Snapshot of the encrypted notes this node has seen (#196), for the
    /// `GET /transact/scan` endpoint.
    pub async fn delivered_transfer_notes(&self) -> Vec<transact_ingress::DeliveredNote> {
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

    /// Assemble the co-signed multi-sig transaction for a quorum-approved
    /// unified transact (#350). This is the sole settlement path.
    /// The `transact` instruction nullifies two inputs, appends two output
    /// commitments, and pays out `|ext_amount|` from the vault when the signed
    /// external flow is negative (zero for a pure shielded transfer). The
    /// approving validators co-sign over libp2p and the leader assembles their
    /// signatures into one transaction.
    pub async fn cosign_settlement_transact_tx(
        &self,
        approved: &ApprovedTransact,
        blockhash: [u8; 32],
    ) -> Result<Transaction> {
        let leader = self
            .cosign_keypair
            .as_ref()
            .ok_or_else(|| anyhow!("no settlement keypair configured"))?;
        let coordinator = self
            .transact_coordinator
            .as_ref()
            .ok_or_else(|| anyhow!("no transact coordinator"))?;
        let request = &approved.request;

        let program_id = Pubkey::from_str(&self.settings.bridge.program_id)
            .map_err(|e| anyhow!("invalid program id: {e}"))?;
        let (vault, _) = derive_bridge_vault(&program_id);

        // The validators that approved this transact become the co-signer
        // quorum, mapped to their advertised settlement wallets; the leader
        // signs as itself and is excluded from the peers it requests from.
        let self_id = self.node_info.id.clone();
        let mut peers: Vec<(Pubkey, NodeId)> = Vec::new();
        for voter in coordinator.valid_voters(&request.request_id).await {
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
        let threshold = quorum_wallets.len();

        // The on-chain program verifies the proof in its 256-byte alt_bn128
        // wire form; convert the prover's compressed proof.
        let onchain_proof =
            crate::privacy::onchain_verifier::compressed_proof_to_onchain_bytes(&request.proof)
                .map_err(|e| anyhow!("transact proof: {e}"))?;
        let params = SettlementParams::Transact {
            recipient: request.recipient,
            nullifiers: request.nullifiers,
            output_commitments: request.output_commitments,
            root: request.root,
            ext_amount: request.ext_amount,
            proof: onchain_proof.to_vec(),
        };

        let network = self.network.clone();
        cosign_round::run_cosign_round(
            leader,
            program_id,
            vault,
            blockhash,
            &request.request_id,
            SettlementKind::Transact,
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

    /// Settle a quorum-approved unified transact via the #260 co-signing path,
    /// the v3 twin of `settle_transfer_via_cosign`. The on-chain submit error
    /// is preserved as its `BridgeError` so the caller's replay detection still
    /// applies; a co-signing-round failure maps to `Network`.
    async fn settle_transact_via_cosign(
        &self,
        approved: ApprovedTransact,
    ) -> std::result::Result<String, crate::bridge::BridgeError> {
        use crate::bridge::BridgeError;
        let bridge = self
            .bridge
            .as_ref()
            .ok_or_else(|| BridgeError::ConfigError("no bridge configured".to_string()))?;

        let blockhash = bridge.lock().await.latest_blockhash().await?;
        let tx = self
            .cosign_settlement_transact_tx(&approved, blockhash)
            .await
            .map_err(|e| BridgeError::Network(format!("transact co-signing round: {e}")))?;

        let result = bridge.lock().await.submit_signed_transaction(&tx).await;
        if result.is_ok() {
            // The settlement landed: mark its input nullifiers spent in the
            // off-chain set so this node's `check_batch` pre-filters replays of
            // it before consensus, matching the on-chain nullifier PDAs that are
            // the authoritative double-spend gate (#624).
            if let Some(pool) = &self.shielded_pool {
                pool.record_spent(approved.request.nullifiers).await;
            }
        }
        result
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

    /// Verify a v3 unified-transact zkSNARK proof (#350).
    ///
    /// Deliberately NOT verified against `pool.root().await`: the v3 proof is
    /// built against `request.root` — the on-chain incremental-tree root
    /// carried in the request — and the root's legitimacy is enforced at
    /// settlement by the program's `is_known_root` check over its root
    /// history. The method therefore needs no pool state at all, which is why
    /// it takes no pool parameter.
    async fn verify_transact_proof(
        &self,
        request: &crate::consensus::transact::TransactVerificationRequest,
    ) -> Result<bool> {
        // Override seam (#350): use the injected verifier when present.
        if let Some(verifier) = &self.transact_proof_verifier_override {
            return Ok(verifier(request));
        }

        // Asset is native SOL (the all-zero asset id) for now.
        let result = crate::privacy::ProofVerifier::verify_transact_parts(
            &request.root,
            &request.recipient,
            request.ext_amount,
            &[0u8; 32],
            &request.nullifiers,
            &request.output_commitments,
            &request.proof,
        );
        if let crate::privacy::VerificationResult::Invalid { reason } = &result {
            log::warn!(
                "transact proof rejected for {}: {}",
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
            compute_auth: self.compute_auth.clone(),
            job_coordinators: self.job_coordinators.clone(),
            ha_broadcast: self.ha_broadcast.clone(),
            ha_watchdog: self.ha_watchdog.clone(),
            kad_refresh: self.kad_refresh.clone(),
            bridge: self.bridge.clone(),
            transact_coordinator: self.transact_coordinator.clone(),
            transact_approval_rx: self.transact_approval_rx.clone(),
            transact_submitter_task: self.transact_submitter_task.clone(),
            transact_proof_verifier_override: self.transact_proof_verifier_override.clone(),
            transact_ingress: self.transact_ingress.clone(),
            delivered_notes: self.delivered_notes.clone(),
            cosign_keypair: self.cosign_keypair.clone(),
            verified_transacts: self.verified_transacts.clone(),
            cosign_counts: self.cosign_counts.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // --- #260/#350 co-sign handler (cosign_settlement), v3 transact ---

    fn cosign_req(id: &str, kind: SettlementKind, payload: &CoSignPayload) -> CoSignRequest {
        CoSignRequest {
            request_id: id.to_string(),
            kind,
            message: payload.to_bytes().expect("serialize payload"),
        }
    }

    /// The program id baked into the test payloads (`ta_payload`).
    fn configured_program() -> Pubkey {
        Pubkey::new_from_array([1u8; 32])
    }

    #[tokio::test]
    async fn cosign_declines_unknown_request_and_without_keypair_and_wrong_program() {
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));

        let recipient = [9u8; 32];
        let nullifiers = [[7u8; 32], [8u8; 32]];
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1i64;
        let payload = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers,
            outputs,
            root,
            ext_amount,
        );

        // Never verified this request id → declined.
        let unknown = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &Arc::new(Mutex::new(HashMap::new())),
            cosign_req("nope", SettlementKind::Transact, &payload),
        )
        .await;
        assert_eq!(unknown.signature, None);

        // No keypair configured at all → declined even for a verified request.
        tas.lock().await.insert(
            "t1".to_string(),
            ta_request("t1", recipient, nullifiers, outputs, root, ext_amount),
        );
        let no_key = cosign_settlement(
            None,
            &configured_program(),
            &tas,
            &Arc::new(Mutex::new(HashMap::new())),
            cosign_req("t1", SettlementKind::Transact, &payload),
        )
        .await;
        assert_eq!(no_key.signature, None);

        // A payload program id that does not match our config → declined.
        let wrong_program = cosign_settlement(
            Some(&kp),
            &Pubkey::new_from_array([2u8; 32]),
            &tas,
            &Arc::new(Mutex::new(HashMap::new())),
            cosign_req("t1", SettlementKind::Transact, &payload),
        )
        .await;
        assert_eq!(wrong_program.signature, None);
    }

    // --- #350 co-sign handler, v3 unified-transact settlements ---

    fn ta_request(
        id: &str,
        recipient: [u8; 32],
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        root: [u8; 32],
        ext_amount: i64,
    ) -> TransactVerificationRequest {
        TransactVerificationRequest {
            request_id: id.to_string(),
            recipient,
            nullifiers,
            output_commitments,
            root,
            ext_amount,
            proof: vec![0u8; 256],
            ciphertexts: ["ab".repeat(88), "cd".repeat(88)],
            timestamp: 0,
        }
    }

    fn ta_payload(
        authority: [u8; 32],
        recipient: [u8; 32],
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        root: [u8; 32],
        ext_amount: i64,
    ) -> CoSignPayload {
        CoSignPayload {
            program_id: [1u8; 32],
            authority,
            bridge_vault: [3u8; 32],
            blockhash: [4u8; 32],
            quorum_validators: vec![authority],
            params: SettlementParams::Transact {
                recipient,
                nullifiers,
                output_commitments,
                root,
                ext_amount,
                proof: vec![0u8; 256],
            },
        }
    }

    #[tokio::test]
    async fn cosign_signs_a_transact_we_verified() {
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));

        let recipient = [9u8; 32];
        let nullifiers = [[7u8; 32], [8u8; 32]];
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1_000_000_000i64;
        tas.lock().await.insert(
            "t1".to_string(),
            ta_request("t1", recipient, nullifiers, outputs, root, ext_amount),
        );

        let payload = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers,
            outputs,
            root,
            ext_amount,
        );
        let resp = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &Arc::new(Mutex::new(HashMap::new())),
            cosign_req("t1", SettlementKind::Transact, &payload),
        )
        .await;

        assert_eq!(resp.request_id, "t1");
        assert_eq!(resp.wallet_pubkey, kp.pubkey().to_string());
        let sig_bytes = resp.signature.expect("must sign a transact it verified");
        // The signature must verify against the message we would actually submit.
        let message = build_settlement_message(&payload).expect("build message");
        let sig = solana_sdk::signature::Signature::try_from(sig_bytes.as_slice()).expect("sig");
        assert!(
            sig.verify(&kp.pubkey().to_bytes(), &message.serialize()),
            "the returned signature must be valid over the rebuilt settlement message"
        );
    }

    #[tokio::test]
    async fn cosign_caps_repeated_signs_for_one_settlement() {
        // A peer holding one approved settlement must not be able to replay it
        // under fresh blockhashes to extract unlimited fee-payer signatures
        // (#593). The cap still admits the leader's legitimate retries.
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));

        let recipient = [9u8; 32];
        let nullifiers = [[7u8; 32], [8u8; 32]];
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1_000_000_000i64;
        tas.lock().await.insert(
            "t1".to_string(),
            ta_request("t1", recipient, nullifiers, outputs, root, ext_amount),
        );
        let payload = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers,
            outputs,
            root,
            ext_amount,
        );

        // Up to the cap, each request signs (a legitimate blockhash retry).
        for i in 0..MAX_COSIGNS_PER_SETTLEMENT {
            let resp = cosign_settlement(
                Some(&kp),
                &configured_program(),
                &tas,
                &counts,
                cosign_req("t1", SettlementKind::Transact, &payload),
            )
            .await;
            assert!(resp.signature.is_some(), "sign #{i} within the cap");
        }

        // One past the cap is declined.
        let over = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &counts,
            cosign_req("t1", SettlementKind::Transact, &payload),
        )
        .await;
        assert_eq!(
            over.signature, None,
            "co-signing past the per-settlement cap must be declined"
        );

        // The cap is per spend: a genuinely different spend (different input
        // nullifiers) has its own budget.
        let other_nullifiers = [[17u8; 32], [18u8; 32]];
        let other_payload = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            other_nullifiers,
            outputs,
            root,
            ext_amount,
        );
        tas.lock().await.insert(
            "t2".to_string(),
            ta_request("t2", recipient, other_nullifiers, outputs, root, ext_amount),
        );
        let other = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &counts,
            cosign_req("t2", SettlementKind::Transact, &other_payload),
        )
        .await;
        assert!(
            other.signature.is_some(),
            "a distinct spend must not inherit another's cap"
        );
    }

    #[tokio::test]
    async fn cosign_cap_follows_nullifiers_across_distinct_request_ids() {
        // Groth16 proving is randomized: one spend has many valid proofs and so
        // many canonical request ids. The per-spend cap must key on the input
        // nullifiers, not the request id, or a peer could pre-generate distinct
        // proofs of the same spend and get a fresh fee-payer-signature budget
        // under each, defeating the #593 cap (#606).
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));

        let recipient = [9u8; 32];
        let nullifiers = [[7u8; 32], [8u8; 32]];
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1_000_000_000i64;
        let payload = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers,
            outputs,
            root,
            ext_amount,
        );

        // Spend the whole budget under one request id (one proof of the spend).
        tas.lock().await.insert(
            "proof-a".to_string(),
            ta_request("proof-a", recipient, nullifiers, outputs, root, ext_amount),
        );
        for _ in 0..MAX_COSIGNS_PER_SETTLEMENT {
            let resp = cosign_settlement(
                Some(&kp),
                &configured_program(),
                &tas,
                &counts,
                cosign_req("proof-a", SettlementKind::Transact, &payload),
            )
            .await;
            assert!(resp.signature.is_some());
        }

        // A distinct request id for the SAME spend (same input nullifiers, a
        // different randomized proof) must not reset the budget.
        tas.lock().await.insert(
            "proof-b".to_string(),
            ta_request("proof-b", recipient, nullifiers, outputs, root, ext_amount),
        );
        let bypass = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &counts,
            cosign_req("proof-b", SettlementKind::Transact, &payload),
        )
        .await;
        assert_eq!(
            bypass.signature, None,
            "a fresh request id for the same input nullifiers must not reset the cap"
        );
    }

    #[tokio::test]
    async fn cosign_cap_follows_the_real_nullifier_across_dummy_variations() {
        // A transact can pair a real input note with a zero-amount dummy whose
        // nullifier the requester picks freely. Varying that dummy must NOT
        // reset the budget: the real note's nullifier is fixed and present in
        // every variation, and the cap counts each nullifier independently, so
        // it catches the real one however the dummy is perturbed (#606).
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));

        let recipient = [9u8; 32];
        let real_nf = [7u8; 32]; // the fixed real note's nullifier
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1_000_000_000i64;

        // Spend the whole budget with the real note plus one dummy.
        let nullifiers_a = [real_nf, [8u8; 32]];
        let payload_a = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers_a,
            outputs,
            root,
            ext_amount,
        );
        tas.lock().await.insert(
            "a".to_string(),
            ta_request("a", recipient, nullifiers_a, outputs, root, ext_amount),
        );
        for _ in 0..MAX_COSIGNS_PER_SETTLEMENT {
            let resp = cosign_settlement(
                Some(&kp),
                &configured_program(),
                &tas,
                &counts,
                cosign_req("a", SettlementKind::Transact, &payload_a),
            )
            .await;
            assert!(resp.signature.is_some());
        }

        // Same real note, a DIFFERENT dummy nullifier: still declined, because
        // the real nullifier is already at the cap.
        let nullifiers_b = [real_nf, [99u8; 32]];
        let payload_b = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers_b,
            outputs,
            root,
            ext_amount,
        );
        tas.lock().await.insert(
            "b".to_string(),
            ta_request("b", recipient, nullifiers_b, outputs, root, ext_amount),
        );
        let bypass = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &counts,
            cosign_req("b", SettlementKind::Transact, &payload_b),
        )
        .await;
        assert_eq!(
            bypass.signature, None,
            "varying the dummy nullifier must not reset the cap for the shared real nullifier"
        );
    }

    #[tokio::test]
    async fn cosign_counts_map_stays_bounded() {
        // The counter map is never explicitly cleared, so it must self-bound as
        // distinct settlements accumulate, or it grows for the life of the
        // process (#626).
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let recipient = [9u8; 32];
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1i64;

        // Co-sign more distinct spends (two fresh nullifiers each) than the
        // ceiling; the map must never exceed it.
        for i in 0..(MAX_COSIGN_COUNTS as u64 + 50) {
            let mut n0 = [0u8; 32];
            n0[0..8].copy_from_slice(&(2 * i).to_le_bytes());
            let mut n1 = [0u8; 32];
            n1[0..8].copy_from_slice(&(2 * i + 1).to_le_bytes());
            let nullifiers = [n0, n1];
            let id = format!("s{i}");
            tas.lock().await.insert(
                id.clone(),
                ta_request(&id, recipient, nullifiers, outputs, root, ext_amount),
            );
            let payload = ta_payload(
                kp.pubkey().to_bytes(),
                recipient,
                nullifiers,
                outputs,
                root,
                ext_amount,
            );
            let _ = cosign_settlement(
                Some(&kp),
                &configured_program(),
                &tas,
                &counts,
                cosign_req(&id, SettlementKind::Transact, &payload),
            )
            .await;
        }

        assert!(
            counts.lock().await.len() <= MAX_COSIGN_COUNTS,
            "cosign_counts must stay bounded"
        );
    }

    #[tokio::test]
    async fn cosign_declines_a_tampered_transact_parameter() {
        let kp = Arc::new(Keypair::new());
        let tas = Arc::new(Mutex::new(HashMap::new()));

        let recipient = [9u8; 32];
        let nullifiers = [[7u8; 32], [8u8; 32]];
        let outputs = [[5u8; 32], [6u8; 32]];
        let root = [2u8; 32];
        let ext_amount = -1_000_000_000i64;
        tas.lock().await.insert(
            "t1".to_string(),
            ta_request("t1", recipient, nullifiers, outputs, root, ext_amount),
        );

        // Leader tries to redirect the withdrawal leg to a different recipient.
        let tampered_recipient = ta_payload(
            kp.pubkey().to_bytes(),
            [0xFF; 32],
            nullifiers,
            outputs,
            root,
            ext_amount,
        );
        let resp = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &Arc::new(Mutex::new(HashMap::new())),
            cosign_req("t1", SettlementKind::Transact, &tampered_recipient),
        )
        .await;
        assert_eq!(
            resp.signature, None,
            "a substituted recipient must be declined even though we verified the original"
        );

        // Leader tries to withdraw more than the amount we verified.
        let tampered_ext = ta_payload(
            kp.pubkey().to_bytes(),
            recipient,
            nullifiers,
            outputs,
            root,
            -2_000_000_000i64,
        );
        let resp = cosign_settlement(
            Some(&kp),
            &configured_program(),
            &tas,
            &Arc::new(Mutex::new(HashMap::new())),
            cosign_req("t1", SettlementKind::Transact, &tampered_ext),
        )
        .await;
        assert_eq!(
            resp.signature, None,
            "a substituted ext_amount must be declined"
        );
    }

    fn ta_approval(id: &str) -> ApprovedTransact {
        ApprovedTransact {
            request: ta_request(
                id,
                [0u8; 32],
                [[1u8; 32], [2u8; 32]],
                [[3u8; 32], [4u8; 32]],
                [5u8; 32],
                0,
            ),
        }
    }

    // The transact submitter drains every approval into the settle closure,
    // ungated. Regression for #164 — a leader gate here dropped approvals
    // because the channel is in-process, not gossiped, so the
    // deterministically-chosen leader rarely held the approval and the
    // settlement was silently lost.
    #[tokio::test]
    async fn settles_every_transact_approval_without_gating() {
        let (tx, rx) = mpsc::unbounded_channel();
        for i in 0..3 {
            tx.send(ta_approval(&format!("ta-{i}"))).unwrap();
        }
        drop(tx);

        let submitted = Arc::new(AtomicUsize::new(0));
        let counter = submitted.clone();
        settle_approved_transacts(rx, move |_approved| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok("signature".to_string())
            }
        })
        .await;

        assert_eq!(submitted.load(Ordering::SeqCst), 3);
    }

    // A transact replay (nullifier already spent) is skipped quietly and does
    // not stop the task from settling later approvals.
    #[tokio::test]
    async fn transact_replay_error_does_not_stall_later_approvals() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(ta_approval("replayed")).unwrap();
        tx.send(ta_approval("fresh")).unwrap();
        drop(tx);

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        settle_approved_transacts(rx, move |_approved| {
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

    // A transient submit failure (expired blockhash, co-signer briefly offline)
    // must be RETRIED, not dropped — the approval is emitted once and never
    // re-emitted, so dropping it would strand the transact permanently. Two
    // failures then a success settles on the third attempt.
    #[tokio::test(start_paused = true)]
    async fn transient_submit_failure_is_retried_until_it_settles() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(ta_approval("flaky")).unwrap();
        drop(tx);

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        settle_approved_transacts(rx, move |_approved| {
            let counter = counter.clone();
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(crate::bridge::BridgeError::InvalidTransaction(
                        "blockhash not found".to_string(),
                    ))
                } else {
                    Ok("signature".to_string())
                }
            }
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    // A persistently-failing settlement gives up after MAX_SETTLE_ATTEMPTS
    // instead of retrying forever.
    #[tokio::test(start_paused = true)]
    async fn persistent_submit_failure_gives_up_after_max_attempts() {
        let (tx, rx) = mpsc::unbounded_channel();
        tx.send(ta_approval("doomed")).unwrap();
        drop(tx);

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        settle_approved_transacts(rx, move |_approved| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<String, _>(crate::bridge::BridgeError::InvalidTransaction(
                    "still failing".to_string(),
                ))
            }
        })
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 3);
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
        assert!(node.transact_coordinator.is_none());
    }

    // A validator-class node (ResourceProvider) with the bridge enabled
    // owns a shielded pool, a bridge manager, and a transact
    // coordinator, so run() can start the deposit listener (#163) and the
    // consensus→submit pipeline (#164).
    #[test]
    fn bridge_enabled_validator_owns_pool_and_bridge() {
        let mut settings = Settings::development();
        settings.bridge.enabled = true;
        let node = Node::new(settings).expect("construct node");
        assert!(node.shielded_pool.is_some());
        assert!(node.bridge.is_some());
        assert!(node.transact_coordinator.is_some());
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
        assert!(node.transact_coordinator.is_none());
    }
}
