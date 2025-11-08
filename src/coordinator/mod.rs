//! Coordinator node logic

use crate::network::{Message, NetworkManager};
use crate::task::{ResultData, Task, TaskId, TaskResult, TaskStatus, TaskType};
use crate::types::NodeId;
use anyhow::Result;
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
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
}

impl Coordinator {
    /// Create a new coordinator
    pub fn new(network: Arc<NetworkManager>) -> Self {
        Coordinator {
            validators: Arc::new(Mutex::new(Vec::new())),
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
            results: Arc::new(Mutex::new(HashMap::new())),
            parent_tasks: Arc::new(Mutex::new(HashMap::new())),
            network,
        }
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
}
