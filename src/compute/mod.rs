//! Compute layer for privacy-preserving distributed computation
//!
//! This module provides WASM-based compute capabilities with:
//! - Secure WASM execution with resource limits
//! - Job scheduling and queue management
//! - Resource isolation and sandboxing
//! - Result aggregation and verification
//!
//! # Architecture
//!
//! ```text
//! User → Job Submission → Executor → WASM Engine → Results
//!                            ↓
//!                      Resource Limits
//!                      (Memory, CPU, Time)
//! ```
//!
//! # Example
//!
//! ```no_run
//! use paraloom::compute::{ComputeJob, JobExecutor, ResourceLimits};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create executor
//!     let executor = JobExecutor::new().unwrap();
//!     executor.start().await.unwrap();
//!
//!     // Create a compute job
//!     let wasm_code = vec![/* WASM bytecode */];
//!     let input_data = vec![1, 2, 3, 4];
//!     let limits = ResourceLimits::default();
//!
//!     let job = ComputeJob::new(wasm_code, input_data, limits);
//!     let job_id = executor.submit_job(job).unwrap();
//!
//!     // Wait for completion and get result
//!     loop {
//!         if let Some(result) = executor.get_job_result(&job_id) {
//!             println!("Job completed: {:?}", result);
//!             break;
//!         }
//!         tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
//!     }
//! }
//! ```

pub mod distribution;
pub mod engine;
pub mod executor;
pub mod job;
pub mod manager;

// Re-export main types
pub use distribution::{
    CapacityAnnouncement, CoordinatorStats, JobAssignment, JobCoordinator, ValidatorJobFetcher,
};
pub use engine::WasmEngine;
pub use executor::{ExecutorStats, JobExecutor};
pub use job::{ComputeJob, JobId, JobResult, JobStatus, ResourceLimits};
pub use manager::{JobManager, ManagerStats, ValidatorCapacity, ValidatorId};
