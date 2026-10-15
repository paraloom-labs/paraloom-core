//! Validator node logic

use crate::network::{Message, NetworkManager, ResultRequest};
use crate::task::{ResultData, Task, TaskResult, TaskType};
use crate::types::NodeId;
use anyhow::Result;
use log::info;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;

/// Upper bound on the number of hashes one `HashCalculation` task may request.
/// The task is peer-supplied and its range is attacker-controlled; without a
/// cap a `start=0, end=u64::MAX` range overflows the item count (panic in
/// debug, wrap in release) and loops ~2^64 times, growing the output vector
/// until the validator is OOM-killed (#609).
pub const MAX_HASH_TASK_ITEMS: u64 = 1_000_000;

/// Validate a peer-supplied `HashCalculation` range and return its item count,
/// rejecting an inverted range or one larger than [`MAX_HASH_TASK_ITEMS`]. The
/// `+ 1` is overflow-checked so `end = u64::MAX` cannot panic or wrap (#609).
fn checked_hash_count(start: u64, end: u64) -> Result<u64> {
    if end < start {
        return Err(anyhow::anyhow!(
            "invalid hash range: end ({end}) < start ({start})"
        ));
    }
    (end - start)
        .checked_add(1)
        .filter(|c| *c <= MAX_HASH_TASK_ITEMS)
        .ok_or_else(|| {
            anyhow::anyhow!("hash range exceeds the {MAX_HASH_TASK_ITEMS}-item task limit")
        })
}

/// Validator executes tasks
pub struct Validator {
    network: Arc<NetworkManager>,
    coordinator_id: Option<NodeId>,
}

impl Validator {
    /// Create a new validator
    pub fn new(network: Arc<NetworkManager>) -> Self {
        Validator {
            network,
            coordinator_id: None,
        }
    }

    /// Set coordinator ID
    pub fn set_coordinator(&mut self, coordinator_id: NodeId) {
        self.coordinator_id = Some(coordinator_id);
    }

    /// Handle incoming task request
    pub async fn handle_task_request(
        &self,
        source: &NodeId,
        task: Task,
        coordinator_id: NodeId,
    ) -> Result<()> {
        if source != &coordinator_id {
            return Err(anyhow::anyhow!(
                "task request coordinator_id {:?} does not match authenticated sender {:?}",
                coordinator_id,
                source
            ));
        }

        if let Some(expected_coordinator) = &self.coordinator_id {
            if source != expected_coordinator {
                return Err(anyhow::anyhow!(
                    "task request from {:?} rejected: validator is bound to coordinator {:?}",
                    source,
                    expected_coordinator
                ));
            }
        }

        if let Some(assigned) = &task.assigned_to {
            let local_id = self.network.local_peer_id();
            let expected_debug = format!("{:?}", local_id);
            let expected_display = local_id.to_string();
            if assigned != &expected_debug && assigned != &expected_display {
                return Err(anyhow::anyhow!(
                    "task {} is assigned to {}, not local validator {:?}",
                    task.id,
                    assigned,
                    local_id
                ));
            }
        }

        info!("Validator received task: {} from coordinator", task.id);

        // Execute task
        info!("Executing task: {}", task.id);
        match self.execute_task(task.clone()).await {
            Ok(result) => {
                info!(
                    "Task completed: {} in {}ms",
                    result.task_id, result.execution_time_ms
                );

                let request = ResultRequest { result };
                self.network
                    .send_result_request(coordinator_id.clone(), request)
                    .await?;
            }
            Err(e) => {
                info!("Task failed: {} - {}", task.id, e);

                let msg = Message::TaskError {
                    task_id: task.id,
                    error: e.to_string(),
                };
                self.network.send_message(coordinator_id, msg).await?;
            }
        }

        Ok(())
    }

    /// Execute a task
    async fn execute_task(&self, task: Task) -> Result<TaskResult> {
        let start_time = Instant::now();

        let data = match task.task_type {
            TaskType::HashCalculation {
                start,
                end,
                algorithm,
            } => {
                // Reject an invalid or oversized range before doing any work.
                // `start=0, end=u64::MAX` would otherwise overflow `end - start
                // + 1` and loop ~2^64 times, exhausting memory (#609).
                let count = checked_hash_count(start, end)?;
                info!(
                    "Calculating {} hashes ({} to {}) using {}",
                    count, start, end, algorithm
                );

                let mut hashes = Vec::with_capacity(count as usize);
                for i in start..=end {
                    let hash = self.calculate_hash(i, &algorithm)?;
                    hashes.push((i, hash));
                }

                ResultData::Hashes {
                    hashes,
                    count: count as usize,
                }
            }
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(TaskResult {
            task_id: task.id,
            execution_time_ms,
            data,
        })
    }

    /// Calculate hash of a number
    fn calculate_hash(&self, number: u64, algorithm: &str) -> Result<String> {
        match algorithm {
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(number.to_le_bytes());
                let result = hasher.finalize();
                Ok(format!("{:x}", result))
            }
            _ => Err(anyhow::anyhow!("Unsupported algorithm: {}", algorithm)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;

    fn make_test_network() -> Arc<NetworkManager> {
        Arc::new(NetworkManager::new(&Settings::development()).expect("test network"))
    }

    fn sample_task(assigned_to: Option<String>) -> Task {
        let mut task = Task::new(TaskType::HashCalculation {
            start: 0,
            end: 0,
            algorithm: "sha256".to_string(),
        });
        task.assigned_to = assigned_to;
        task
    }

    #[test]
    fn hash_count_accepts_a_bounded_range() {
        assert_eq!(checked_hash_count(0, 0).unwrap(), 1);
        assert_eq!(checked_hash_count(10, 19).unwrap(), 10);
        assert_eq!(
            checked_hash_count(0, MAX_HASH_TASK_ITEMS - 1).unwrap(),
            MAX_HASH_TASK_ITEMS
        );
    }

    #[test]
    fn hash_count_rejects_the_overflowing_full_range() {
        // The #609 payload: start=0, end=u64::MAX. Must not panic or wrap.
        assert!(checked_hash_count(0, u64::MAX).is_err());
    }

    #[test]
    fn hash_count_rejects_oversized_and_inverted_ranges() {
        assert!(checked_hash_count(0, MAX_HASH_TASK_ITEMS).is_err());
        assert!(checked_hash_count(5, 4).is_err());
    }

    #[tokio::test]
    async fn handle_task_request_rejects_spoofed_coordinator_id() {
        let validator = Validator::new(make_test_network());
        let sender = NodeId(vec![0xAA]);
        let victim_coordinator = NodeId(vec![0xBB]);

        let err = validator
            .handle_task_request(&sender, sample_task(None), victim_coordinator)
            .await;
        assert!(
            err.is_err(),
            "spoofed coordinator_id != source must be rejected"
        );
    }

    #[tokio::test]
    async fn handle_task_request_rejects_non_configured_coordinator() {
        let mut validator = Validator::new(make_test_network());
        let configured_coord = NodeId(vec![0x01]);
        let attacker = NodeId(vec![0xEE]);
        validator.set_coordinator(configured_coord);

        let err = validator
            .handle_task_request(&attacker, sample_task(None), attacker.clone())
            .await;
        assert!(
            err.is_err(),
            "task request from peer other than configured coordinator must be rejected"
        );
    }

    #[tokio::test]
    async fn handle_task_request_rejects_task_assigned_to_another_validator() {
        let validator = Validator::new(make_test_network());
        let coord = NodeId(vec![0x01]);
        let other_validator = NodeId(vec![0xCC]);

        let err = validator
            .handle_task_request(
                &coord,
                sample_task(Some(format!("{:?}", other_validator))),
                coord.clone(),
            )
            .await;
        assert!(
            err.is_err(),
            "task assigned to a different validator must be rejected before execution"
        );
    }
}
