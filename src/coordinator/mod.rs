//! Coordinator node logic

pub mod role;

pub use role::CoordinatorRole;

use crate::network::{HeartbeatRequest, HeartbeatResponse, Message, NetworkManager};
use crate::task::{ResultData, Task, TaskId, TaskResult, TaskStatus, TaskType};
use crate::types::NodeId;
use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Coordinator manages task distribution and aggregation
pub struct Coordinator {
    /// Available validators
    validators: Arc<Mutex<Vec<NodeId>>>,

    /// Active tasks (task_id -> task)
    active_tasks: Arc<Mutex<HashMap<TaskId, Task>>>,

    /// Task results (task_id -> result)
    results: Arc<Mutex<HashMap<TaskId, TaskResult>>>,

    /// Parent task tracking (chunk_id -> parent_id)
    parent_tasks: Arc<Mutex<HashMap<TaskId, TaskId>>>,

    /// Network manager
    network: Arc<NetworkManager>,

    /// Active role (Primary or Standby) for the HA failover work in
    /// #66. Defaults to Primary on `new()`; standbys are constructed
    /// via `standby_of()`.
    role: Arc<Mutex<CoordinatorRole>>,

    /// Monotonic sequence number stamped on outgoing heartbeats while
    /// this coordinator is the primary, and the highest sequence
    /// applied so far while this coordinator is a standby.
    heartbeat_sequence: Arc<Mutex<u64>>,
}

impl Coordinator {
    /// Create a new coordinator in the `Primary` role.
    pub fn new(network: Arc<NetworkManager>) -> Self {
        Coordinator {
            validators: Arc::new(Mutex::new(Vec::new())),
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
            results: Arc::new(Mutex::new(HashMap::new())),
            parent_tasks: Arc::new(Mutex::new(HashMap::new())),
            network,
            role: Arc::new(Mutex::new(CoordinatorRole::Primary)),
            heartbeat_sequence: Arc::new(Mutex::new(0)),
        }
    }

    /// Create a new coordinator in the `Standby` role, mirroring
    /// `primary` and watching for `stall_threshold` of silence.
    pub fn standby_of(
        network: Arc<NetworkManager>,
        primary: NodeId,
        stall_threshold: Duration,
    ) -> Self {
        Coordinator {
            validators: Arc::new(Mutex::new(Vec::new())),
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
            results: Arc::new(Mutex::new(HashMap::new())),
            parent_tasks: Arc::new(Mutex::new(HashMap::new())),
            network,
            role: Arc::new(Mutex::new(CoordinatorRole::standby_of(
                primary,
                stall_threshold,
                Instant::now(),
            ))),
            heartbeat_sequence: Arc::new(Mutex::new(0)),
        }
    }

    /// True if this coordinator is currently the primary.
    pub async fn is_primary(&self) -> bool {
        self.role.lock().await.is_primary()
    }

    /// Build the next outgoing heartbeat from this coordinator's
    /// current state. Caller is responsible for being in the primary
    /// role; calling this from a standby is allowed (returns the
    /// last-applied state) but uncommon and is logged as a hint of
    /// a misconfiguration upstream.
    pub async fn next_heartbeat_request(&self, primary: NodeId) -> HeartbeatRequest {
        let mut sequence = self.heartbeat_sequence.lock().await;
        *sequence = sequence.saturating_add(1);
        let snapshot = self.snapshot().await;
        HeartbeatRequest {
            primary,
            sequence: *sequence,
            snapshot,
        }
    }

    /// Apply an inbound heartbeat to this coordinator's state. Used
    /// by a standby to mirror the primary's snapshot.
    ///
    /// If this coordinator is itself a primary (already promoted, or
    /// never a standby) the heartbeat is rejected with
    /// `accepted: false` and the standby state is left untouched. A
    /// stale-or-replayed heartbeat (sequence not strictly greater
    /// than the highest applied) is also rejected so the standby's
    /// view never moves backwards.
    pub async fn apply_heartbeat(&self, request: HeartbeatRequest) -> HeartbeatResponse {
        let role = self.role.lock().await;
        if role.is_primary() {
            let last_applied = *self.heartbeat_sequence.lock().await;
            return HeartbeatResponse {
                accepted: false,
                last_applied_sequence: last_applied,
            };
        }
        drop(role);

        let mut sequence_slot = self.heartbeat_sequence.lock().await;
        if request.sequence <= *sequence_slot && *sequence_slot != 0 {
            return HeartbeatResponse {
                accepted: false,
                last_applied_sequence: *sequence_slot,
            };
        }
        *sequence_slot = request.sequence;
        drop(sequence_slot);

        // Replace local state with the primary's snapshot. Each
        // mutex is taken in turn and released immediately so the
        // window during which the standby is mid-mirror is short.
        {
            let mut validators = self.validators.lock().await;
            *validators = request.snapshot.validators;
        }
        {
            let mut active_tasks = self.active_tasks.lock().await;
            *active_tasks = request.snapshot.active_tasks;
        }
        {
            let mut parent_tasks = self.parent_tasks.lock().await;
            *parent_tasks = request.snapshot.parent_tasks;
        }
        {
            let mut results = self.results.lock().await;
            *results = request.snapshot.results;
        }

        // Reset the standby's stall watchdog.
        let mut role = self.role.lock().await;
        role.record_heartbeat(Instant::now());

        HeartbeatResponse {
            accepted: true,
            last_applied_sequence: request.sequence,
        }
    }

    /// If this coordinator is a standby and its primary has been
    /// silent past the configured stall threshold relative to `now`,
    /// promote to primary and return the previously-known primary
    /// identity. Returns `None` if already primary or if the standby
    /// has not yet stalled.
    pub async fn try_promote_if_stalled(&self, now: Instant) -> Option<NodeId> {
        let mut role = self.role.lock().await;
        if !role.is_stalled(now) {
            return None;
        }
        role.promote()
    }

    /// Register a validator
    pub async fn register_validator(&self, validator_id: NodeId) {
        let mut validators = self.validators.lock().await;
        if !validators.contains(&validator_id) {
            validators.push(validator_id.clone());
            info!("Validator registered: {:?}", validator_id);
        }
    }

    /// Register all connected peers as validators (workaround for p2p messaging)
    pub async fn register_connected_validators(&self) {
        let peers = self.network.connected_peers().await;
        info!("======================================");
        info!("Registering {} connected peers as validators", peers.len());

        if peers.is_empty() {
            log::warn!("No connected peers found! Validators may not have connected yet.");
            log::warn!("Wait a few more seconds and try submitting a task again.");
        }

        for (i, peer) in peers.iter().enumerate() {
            info!("  Registering validator {}: {}", i + 1, peer);
            self.register_validator(peer.clone()).await;
        }

        let validators = self.validators.lock().await;
        info!("Total registered validators: {}", validators.len());
        info!("======================================");
    }

    /// Get all connected peers from the network
    pub async fn get_connected_peers(&self) -> Vec<NodeId> {
        self.network.connected_peers().await
    }

    /// Submit a new task
    pub async fn submit_task(&self, task_type: TaskType) -> Result<TaskId> {
        let task = Task::new(task_type.clone());
        let parent_id = task.id.clone();

        info!("Task submitted: {}", parent_id);

        // Split task into chunks
        let chunks = self.split_task(&task).await?;
        let chunks_len = chunks.len();
        info!("Split into {} chunks", chunks_len);

        // Get available validators (clone to release lock immediately)
        let validators = {
            let v = self.validators.lock().await;
            info!("Available validators: {}", v.len());
            if v.is_empty() {
                log::error!("No validators available! Make sure validator nodes are connected.");
                return Err(anyhow::anyhow!("No validators available"));
            }
            v.clone()
        };

        // Assign and send chunks to validators
        for (i, mut chunk) in chunks.into_iter().enumerate() {
            let validator_id = validators[i % validators.len()].clone();
            chunk.assigned_to = Some(format!("{:?}", validator_id));
            chunk.status = TaskStatus::Assigned;

            // Track parent relationship and active task
            {
                let mut parent_tasks = self.parent_tasks.lock().await;
                parent_tasks.insert(chunk.id.clone(), parent_id.clone());
            }
            {
                let mut active = self.active_tasks.lock().await;
                active.insert(chunk.id.clone(), chunk.clone());
            }

            // Send TaskRequest (with brief timeout, non-blocking)
            let coordinator_id = self.network.local_peer_id();
            let msg = Message::TaskRequest {
                task: chunk.clone(),
                coordinator_id,
            };
            info!(
                "Sending task chunk {} to validator (chunk {} of {})",
                chunk.id,
                i + 1,
                chunks_len
            );

            // Send with timeout to prevent hanging
            let network = self.network.clone();
            let send_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(1),
                network.send_message(validator_id.clone(), msg),
            )
            .await;

            match send_result {
                Ok(Ok(_)) => {
                    log::debug!("Successfully sent chunk {} to validator", chunk.id);
                }
                Ok(Err(e)) => {
                    log::error!("Failed to send chunk {}: {}", chunk.id, e);
                }
                Err(_) => {
                    log::error!(
                        "Timeout sending chunk {} to validator {:?}",
                        chunk.id,
                        validator_id
                    );
                }
            }
        }

        info!("All {} task chunks distributed to validators", chunks_len);

        Ok(parent_id)
    }

    /// Split a task into chunks
    async fn split_task(&self, task: &Task) -> Result<Vec<Task>> {
        match &task.task_type {
            TaskType::HashCalculation {
                start,
                end,
                algorithm,
            } => {
                let validators = self.validators.lock().await;
                let num_validators = validators.len().max(1);
                let total = end - start + 1;
                let chunk_size = total.div_ceil(num_validators as u64);

                let mut chunks = Vec::new();
                let mut current_start = *start;

                for i in 0..num_validators {
                    let chunk_end = (current_start + chunk_size - 1).min(*end);

                    if current_start <= *end {
                        let mut chunk = Task::new(TaskType::HashCalculation {
                            start: current_start,
                            end: chunk_end,
                            algorithm: algorithm.clone(),
                        });
                        chunk.id = format!("{}-chunk-{}", task.id, i);

                        chunks.push(chunk);
                        current_start = chunk_end + 1;
                    }
                }

                Ok(chunks)
            }
        }
    }

    /// Handle task result from validator
    pub async fn handle_task_result(&self, result: TaskResult) -> Result<()> {
        info!("Task result received: {}", result.task_id);

        // Store result
        let mut results = self.results.lock().await;
        results.insert(result.task_id.clone(), result.clone());

        // Update task status
        let mut active = self.active_tasks.lock().await;
        if let Some(task) = active.get_mut(&result.task_id) {
            task.status = TaskStatus::Completed;
        }

        // Check if all chunks completed
        let parent_tasks = self.parent_tasks.lock().await;
        if let Some(parent_id) = parent_tasks.get(&result.task_id) {
            let parent_id_clone = parent_id.clone();

            // Check if all chunks are done
            let all_done = self
                .all_chunks_completed(&parent_id_clone, &results, &parent_tasks)
                .await;
            drop(parent_tasks); // Release lock before aggregation
            drop(results); // Release lock before aggregation

            if all_done {
                info!("All chunks completed for task: {}", parent_id_clone);
                self.aggregate_results(&parent_id_clone).await?;
            } else {
                info!("Waiting for more chunks... (parent: {})", parent_id_clone);
            }
        } else {
            info!("No parent task found for chunk: {}", result.task_id);
        }

        Ok(())
    }

    /// Check if all chunks for a parent task are completed
    async fn all_chunks_completed(
        &self,
        parent_id: &str,
        results: &HashMap<TaskId, TaskResult>,
        parent_tasks: &HashMap<TaskId, TaskId>,
    ) -> bool {
        let chunk_ids: Vec<_> = parent_tasks
            .iter()
            .filter(|(_, pid)| pid.as_str() == parent_id)
            .map(|(cid, _)| cid.clone())
            .collect();

        for chunk_id in chunk_ids {
            if !results.contains_key(&chunk_id) {
                return false;
            }
        }

        true
    }

    /// Aggregate results from all chunks
    async fn aggregate_results(&self, parent_id: &str) -> Result<()> {
        info!("╔═══════════════════════════════════════════╗");
        info!("║         AGGREGATING RESULTS               ║");
        info!("╚═══════════════════════════════════════════╝");

        // Clone the data and release locks immediately
        let chunk_results: Vec<TaskResult> = {
            let results = self.results.lock().await;
            let parent_tasks = self.parent_tasks.lock().await;

            let mut chunk_results: Vec<_> = results
                .iter()
                .filter(|(task_id, _)| {
                    parent_tasks
                        .get(task_id.as_str())
                        .map(|pid| pid == parent_id)
                        .unwrap_or(false)
                })
                .map(|(_, result)| result.clone())
                .collect();

            // Sort by task_id to ensure consistent ordering
            chunk_results.sort_by(|a, b| a.task_id.cmp(&b.task_id));
            chunk_results
        }; // Locks are dropped here

        info!(
            "Received {} chunk results for parent task {}",
            chunk_results.len(),
            parent_id
        );

        // Merge results based on task type
        if !chunk_results.is_empty() {
            info!("Processing {} chunk results...", chunk_results.len());
            match &chunk_results[0].data {
                ResultData::Hashes { .. } => {
                    let mut all_hashes = Vec::new();
                    let mut max_time = 0u64;
                    let mut total_time = 0u64;

                    for (i, result) in chunk_results.iter().enumerate() {
                        let ResultData::Hashes { hashes, .. } = &result.data;
                        info!(
                            "   Chunk {}: {} hashes in {}ms",
                            i + 1,
                            hashes.len(),
                            result.execution_time_ms
                        );
                        all_hashes.extend(hashes.clone());
                        max_time = max_time.max(result.execution_time_ms);
                        total_time += result.execution_time_ms;
                    }

                    info!("");
                    info!("TASK COMPLETED SUCCESSFULLY!");
                    info!("Total hashes computed: {}", all_hashes.len());
                    info!(
                        "Parallel execution time: {}ms (slowest chunk)",
                        max_time.max(1)
                    );
                    info!("Total chunk time: {}ms (sum of all)", total_time);

                    // Show first 5 hashes as examples
                    info!("");
                    info!("Sample results (first 5):");
                    for (num, hash) in all_hashes.iter().take(5) {
                        info!("   {} -> {}", num, hash);
                    }

                    // Estimate single-node time (approximate)
                    let avg_time = if max_time > 0 {
                        max_time
                    } else {
                        1 // Avoid division by zero
                    };
                    let estimated_single_node_time =
                        all_hashes.len() as u64 * avg_time / chunk_results.len() as u64;
                    let speedup = if max_time > 0 {
                        estimated_single_node_time as f64 / max_time as f64
                    } else {
                        chunk_results.len() as f64
                    };

                    info!("");
                    info!("Performance:");
                    info!(
                        "   Estimated single-node time: ~{}ms",
                        estimated_single_node_time
                    );
                    info!("   Actual parallel time: {}ms", max_time.max(1));
                    info!("   Speedup: ~{:.2}x faster", speedup);
                    info!("");
                }
            }
        } else {
            log::warn!("No chunk results found for task {}", parent_id);
        }

        Ok(())
    }

    /// Handle task error
    pub async fn handle_task_error(&self, task_id: String, error: String) -> Result<()> {
        info!("Task error: {} - {}", task_id, error);

        let mut active = self.active_tasks.lock().await;
        if let Some(task) = active.get_mut(&task_id) {
            task.status = TaskStatus::Failed { error };
        }

        Ok(())
    }

    /// Capture a serializable snapshot of all in-memory coordinator state.
    ///
    /// Acquires each of the four state mutexes in turn, clones the
    /// inner data, and releases the lock immediately. The snapshot is
    /// a point-in-time view: by the time the caller reads it, the
    /// underlying state may have moved on. Replication, heartbeat,
    /// and promotion logic on top of this surface is tracked under
    /// #66; this method is the data foothold those PRs build on.
    pub async fn snapshot(&self) -> CoordinatorSnapshot {
        let validators = self.validators.lock().await.clone();
        let active_tasks = self.active_tasks.lock().await.clone();
        let parent_tasks = self.parent_tasks.lock().await.clone();
        let results = self.results.lock().await.clone();
        CoordinatorSnapshot {
            validators,
            active_tasks,
            parent_tasks,
            results,
        }
    }
}

/// Serializable snapshot of all in-memory coordinator state.
///
/// Used as the data surface for the active/passive HA work tracked
/// in #66. Subsequent PRs build heartbeat, replication, and
/// promotion on top of this type.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoordinatorSnapshot {
    pub validators: Vec<NodeId>,
    pub active_tasks: HashMap<TaskId, Task>,
    pub parent_tasks: HashMap<TaskId, TaskId>,
    pub results: HashMap<TaskId, TaskResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot_has_zero_state() {
        let snapshot = CoordinatorSnapshot::default();
        assert!(snapshot.validators.is_empty());
        assert!(snapshot.active_tasks.is_empty());
        assert!(snapshot.parent_tasks.is_empty());
        assert!(snapshot.results.is_empty());
    }

    #[test]
    fn snapshot_round_trips_through_serde_json() {
        let snapshot = CoordinatorSnapshot::default();
        let encoded = serde_json::to_string(&snapshot).expect("serialize");
        let decoded: CoordinatorSnapshot = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.validators.len(), snapshot.validators.len());
        assert_eq!(decoded.active_tasks.len(), snapshot.active_tasks.len());
        assert_eq!(decoded.parent_tasks.len(), snapshot.parent_tasks.len());
        assert_eq!(decoded.results.len(), snapshot.results.len());
    }
}
