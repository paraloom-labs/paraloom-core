//! Validator node logic

use crate::network::{Message, NetworkManager, ResultRequest};
use crate::task::{ResultData, Task, TaskResult, TaskType};
use crate::types::NodeId;
use anyhow::Result;
use log::info;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;

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
    pub async fn handle_task_request(&self, task: Task, coordinator_id: NodeId) -> Result<()> {
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
                let count = end - start + 1;
                info!(
                    "Calculating {} hashes ({} to {}) using {}",
                    count, start, end, algorithm
                );

                let mut hashes = Vec::new();
                for i in start..=end {
                    let hash = self.calculate_hash(i, &algorithm)?;
                    hashes.push((i, hash));
                }

                ResultData::Hashes {
                    hashes,
                    count: (end - start + 1) as usize,
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
