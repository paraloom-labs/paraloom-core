//! Task system for distributed computation

use serde::{Deserialize, Serialize};

/// Unique task ID
pub type TaskId = String;

/// Task definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    /// Unique identifier
    pub id: TaskId,

    /// Task type and parameters
    pub task_type: TaskType,

    /// Current status
    pub status: TaskStatus,

    /// Creation timestamp (as milliseconds since epoch)
    pub created_at: u64,

    /// Assigned to which node (if any)
    pub assigned_to: Option<String>,
}

/// Types of tasks we support
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaskType {
    /// Calculate hashes of a range of numbers
    HashCalculation {
        start: u64,
        end: u64,
        algorithm: String,
    },
}

/// Task execution status
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    /// Waiting in queue
    Pending,

    /// Assigned to a validator, waiting for execution
    Assigned,

    /// Currently being executed
    Running,

    /// Completed successfully
    Completed,

    /// Failed with error
    Failed { error: String },
}

/// Task execution result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task ID this result belongs to
    pub task_id: TaskId,

    /// Execution time in milliseconds
    pub execution_time_ms: u64,

    /// Result data (specific to task type)
    pub data: ResultData,
}

/// Result data based on task type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ResultData {
    /// Hash calculation results
    Hashes {
        /// List of (number, hash) pairs
        hashes: Vec<(u64, String)>,
        /// Total count
        count: usize,
    },
}

impl Task {
    /// Create a new task
    pub fn new(task_type: TaskType) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Task {
            id,
            task_type,
            status: TaskStatus::Pending,
            created_at,
            assigned_to: None,
        }
    }
}
