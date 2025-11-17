//! Compute job definitions and types for WASM execution
//!
//! This module defines the structure of compute jobs that can be submitted
//! to the Paraloom network for private, distributed execution.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unique job identifier
pub type JobId = String;

/// Compute job submitted by users for execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeJob {
    /// Unique job identifier
    pub id: JobId,

    /// WASM bytecode to execute
    pub wasm_code: Vec<u8>,

    /// Input data for the computation
    pub input_data: Vec<u8>,

    /// Maximum memory allowed (in bytes)
    pub max_memory_bytes: u64,

    /// Maximum CPU instructions allowed
    pub max_instructions: u64,

    /// Timeout in seconds
    pub timeout_secs: u64,

    /// Current job status
    pub status: JobStatus,

    /// Job creation timestamp
    pub created_at: u64,

    /// Job completion timestamp (if completed)
    pub completed_at: Option<u64>,

    /// Assigned validator ID (if any)
    pub assigned_to: Option<String>,
}

/// Job execution status
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    /// Waiting in queue
    Pending,

    /// Assigned to a validator
    Assigned,

    /// Currently executing
    Running,

    /// Completed successfully
    Completed,

    /// Failed with error
    Failed { error: String },

    /// Timed out
    TimedOut,
}

/// Job execution result
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobResult {
    /// Job ID this result belongs to
    pub job_id: JobId,

    /// Execution status
    pub status: JobStatus,

    /// Output data (if successful)
    pub output_data: Option<Vec<u8>>,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Execution time in milliseconds
    pub execution_time_ms: u64,

    /// Memory used (in bytes)
    pub memory_used_bytes: u64,

    /// CPU instructions executed
    pub instructions_executed: u64,
}

/// Resource limits for job execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory (bytes)
    pub max_memory_bytes: u64,

    /// Maximum CPU instructions
    pub max_instructions: u64,

    /// Timeout (seconds)
    pub timeout_secs: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_instructions: 1_000_000_000,    // 1 billion instructions
            timeout_secs: 30,                   // 30 seconds
        }
    }
}

impl ComputeJob {
    /// Create a new compute job
    pub fn new(wasm_code: Vec<u8>, input_data: Vec<u8>, limits: ResourceLimits) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            id,
            wasm_code,
            input_data,
            max_memory_bytes: limits.max_memory_bytes,
            max_instructions: limits.max_instructions,
            timeout_secs: limits.timeout_secs,
            status: JobStatus::Pending,
            created_at,
            completed_at: None,
            assigned_to: None,
        }
    }

    /// Mark job as assigned to a validator
    pub fn assign_to(&mut self, validator_id: String) {
        self.assigned_to = Some(validator_id);
        self.status = JobStatus::Assigned;
    }

    /// Mark job as running
    pub fn mark_running(&mut self) {
        self.status = JobStatus::Running;
    }

    /// Mark job as completed
    pub fn mark_completed(&mut self) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
    }

    /// Mark job as failed
    pub fn mark_failed(&mut self, error: String) {
        self.status = JobStatus::Failed { error };
        self.completed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
    }

    /// Mark job as timed out
    pub fn mark_timed_out(&mut self) {
        self.status = JobStatus::TimedOut;
        self.completed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
    }
}

impl JobResult {
    /// Create a successful job result
    pub fn success(
        job_id: JobId,
        output_data: Vec<u8>,
        execution_time_ms: u64,
        memory_used_bytes: u64,
        instructions_executed: u64,
    ) -> Self {
        Self {
            job_id,
            status: JobStatus::Completed,
            output_data: Some(output_data),
            error: None,
            execution_time_ms,
            memory_used_bytes,
            instructions_executed,
        }
    }

    /// Create a failed job result
    pub fn failure(job_id: JobId, error: String, execution_time_ms: u64) -> Self {
        Self {
            job_id,
            status: JobStatus::Failed {
                error: error.clone(),
            },
            output_data: None,
            error: Some(error),
            execution_time_ms,
            memory_used_bytes: 0,
            instructions_executed: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_job_creation() {
        let limits = ResourceLimits::default();
        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d], // WASM magic bytes
            vec![1, 2, 3, 4],
            limits,
        );

        assert_eq!(job.status, JobStatus::Pending);
        assert!(job.assigned_to.is_none());
        assert!(job.completed_at.is_none());
    }

    #[test]
    fn test_job_status_transitions() {
        let limits = ResourceLimits::default();
        let mut job = ComputeJob::new(vec![], vec![], limits);

        // Pending -> Assigned
        job.assign_to("validator1".to_string());
        assert_eq!(job.status, JobStatus::Assigned);
        assert_eq!(job.assigned_to, Some("validator1".to_string()));

        // Assigned -> Running
        job.mark_running();
        assert_eq!(job.status, JobStatus::Running);

        // Running -> Completed
        job.mark_completed();
        assert_eq!(job.status, JobStatus::Completed);
        assert!(job.completed_at.is_some());
    }

    #[test]
    fn test_job_result_success() {
        let result = JobResult::success("job123".to_string(), vec![5, 6, 7, 8], 100, 1024, 50000);

        assert_eq!(result.status, JobStatus::Completed);
        assert!(result.output_data.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_job_result_failure() {
        let result = JobResult::failure("job456".to_string(), "Out of memory".to_string(), 50);

        assert!(matches!(result.status, JobStatus::Failed { .. }));
        assert!(result.output_data.is_none());
        assert!(result.error.is_some());
    }
}
