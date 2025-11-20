//! Compute layer for privacy-preserving distributed computation
//!
//! This module provides a production-ready WASM-based compute infrastructure with:
//! - **Secure WASM execution** with resource limits (memory, CPU, time)
//! - **Distributed job coordination** with load balancing across validators
//! - **Byzantine fault tolerance** through multi-validator consensus (2/3 threshold)
//! - **Automatic error recovery** with timeout handling and job reassignment
//! - **Comprehensive monitoring** with detailed metrics tracking
//! - **Resource isolation** and sandboxing for untrusted code execution
//!
//! # Architecture Overview
//!
//! The compute layer consists of several components working together:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                         User/Client                               │
//! └───────────────────────────┬──────────────────────────────────────┘
//!                             │
//!                    ┌────────▼─────────┐
//!                    │  JobCoordinator  │  (Distributed assignment)
//!                    │  - Load balance  │
//!                    │  - Timeout track │
//!                    └────────┬─────────┘
//!                             │
//!              ┌──────────────┼──────────────┐
//!              │              │              │
//!         ┌────▼────┐    ┌───▼────┐    ┌───▼────┐
//!         │Validator│    │Validator│   │Validator│
//!         │    1    │    │    2    │   │    3    │
//!         └────┬────┘    └────┬───┘    └────┬───┘
//!              │              │             │
//!         ┌────▼────┐    ┌───▼────┐    ┌───▼────┐
//!         │Executor │    │Executor│    │Executor│
//!         │  WASM   │    │  WASM  │    │  WASM  │
//!         └────┬────┘    └────┬───┘    └────┬───┘
//!              │              │             │
//!              └──────────────┼─────────────┘
//!                             │
//!                    ┌────────▼──────────┐
//!                    │VerificationCoord. │  (Consensus)
//!                    │  - Compare results│
//!                    │  - 2/3 agreement  │
//!                    └───────────────────┘
//! ```
//!
//! # Components
//!
//! ## Core Execution
//! - [`JobExecutor`] - Local job execution with WASM engine
//! - [`WasmEngine`] - WASM runtime with resource limits
//! - [`ComputeJob`] - Job definition with code and input data
//! - [`JobResult`] - Execution result with metrics
//!
//! ## Distributed Coordination
//! - [`JobCoordinator`] - Assigns jobs to validators with load balancing
//! - [`JobManager`] - High-level job lifecycle management
//! - [`VerificationCoordinator`] - Multi-validator consensus verification
//!
//! ## Error Handling
//! - Automatic timeout detection (default: 5 minutes)
//! - Job reassignment on validator failure
//! - Maximum retry limits (3 attempts)
//! - Load-based smart reassignment
//!
//! ## Monitoring
//! - [`ExecutorStats`] - Execution metrics (time, memory, instructions)
//! - [`CoordinatorStats`] - Distribution metrics (load, retries, timeouts)
//! - [`VerificationStats`] - Consensus metrics (agreements, disagreements)
//!
//! # Quick Start Example
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
//!
//! # Distributed Execution Example
//!
//! ```no_run
//! use paraloom::compute::{
//!     JobCoordinator, ValidatorCapacity, VerificationCoordinator,
//!     ComputeJob, ResourceLimits, VERIFICATION_VALIDATOR_COUNT,
//!     CapacityAnnouncement,
//! };
//!
//! #[tokio::main]
//! async fn main() {
//!     // Setup coordinator
//!     let coordinator = JobCoordinator::new();
//!
//!     // Register validators
//!     for i in 1..=3 {
//!         let capacity = ValidatorCapacity::new(
//!             format!("validator-{}", i),
//!             8,      // CPU cores
//!             16384,  // Memory MB
//!             10,     // Max concurrent jobs
//!         );
//!         coordinator.update_validator_capacity(
//!             CapacityAnnouncement::new(capacity, 0)
//!         ).await;
//!     }
//!
//!     // Create and assign job
//!     let wasm_code = vec![/* WASM bytecode */];
//!     let job = ComputeJob::new(wasm_code, vec![], ResourceLimits::default());
//!     let job_id = job.id.clone();
//!
//!     // Assign to best available validator
//!     let assignment = coordinator.assign_job(job_id.clone()).await.unwrap();
//!     println!("Job assigned to: {}", assignment.unwrap().validator_id);
//!
//!     // Setup verification with 3 validators
//!     let verifier = VerificationCoordinator::new();
//!     let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];
//!     verifier.create_verification_request(job_id.clone(), validators).await.unwrap();
//!
//!     // ... validators execute and submit results ...
//!
//!     // Check consensus (requires 2/3 agreement)
//!     let consensus = verifier.check_consensus(&job_id).await.unwrap();
//!     match consensus {
//!         paraloom::compute::ConsensusResult::Agreed(result) => {
//!             println!("Consensus reached! Result: {:?}", result);
//!         }
//!         paraloom::compute::ConsensusResult::Disagreed { .. } => {
//!             println!("Validators disagreed on result");
//!         }
//!         paraloom::compute::ConsensusResult::Insufficient { .. } => {
//!             println!("Not enough results yet");
//!         }
//!     }
//! }
//! ```
//!
//! # Error Handling & Recovery
//!
//! ```no_run
//! use paraloom::compute::{JobCoordinator, DEFAULT_JOB_TIMEOUT_SECS, MAX_JOB_RETRIES};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let coordinator = Arc::new(JobCoordinator::new());
//!
//!     // Timeout handling (runs periodically)
//!     let coordinator_clone = coordinator.clone();
//!     tokio::spawn(async move {
//!         loop {
//!             tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
//!
//!             // Check for timed out jobs and reassign
//!             match coordinator_clone.handle_timeouts().await {
//!                 Ok(reassigned) => {
//!                     println!("Reassigned {} timed out jobs", reassigned.len());
//!                 }
//!                 Err(e) => eprintln!("Error handling timeouts: {}", e),
//!             }
//!         }
//!     });
//!
//!     // Validator failure handling
//!     let failed_validator = "validator-1".to_string();
//!     match coordinator.handle_validator_failure(&failed_validator).await {
//!         Ok(count) => println!("Reassigned {} jobs from failed validator", count),
//!         Err(e) => eprintln!("Error handling failure: {}", e),
//!     }
//! }
//! ```
//!
//! # Monitoring & Metrics
//!
//! ```no_run
//! use paraloom::compute::{JobExecutor, JobCoordinator, VerificationCoordinator};
//!
//! #[tokio::main]
//! async fn main() {
//!     let executor = JobExecutor::new().unwrap();
//!     let coordinator = JobCoordinator::new();
//!     let verifier = VerificationCoordinator::new();
//!
//!     // Get execution metrics
//!     let exec_stats = executor.get_stats();
//!     println!("Executor Stats:");
//!     println!("  Completed: {}", exec_stats.completed_jobs);
//!     println!("  Failed: {}", exec_stats.failed_jobs);
//!     println!("  Avg execution time: {}ms", exec_stats.average_execution_time_ms);
//!     println!("  Total memory used: {} bytes", exec_stats.total_memory_used_bytes);
//!
//!     // Get distribution metrics
//!     let coord_stats = coordinator.get_stats().await;
//!     println!("Coordinator Stats:");
//!     println!("  Active validators: {}", coord_stats.available_validators);
//!     println!("  Pending jobs: {}", coord_stats.pending_assignments);
//!     println!("  Jobs at max retries: {}", coord_stats.jobs_at_max_retries);
//!     println!("  Timed out jobs: {}", coord_stats.timed_out_jobs);
//!     println!("  Avg retry count: {:.2}", coord_stats.average_retry_count);
//!
//!     // Get consensus metrics
//!     let verify_stats = verifier.get_stats().await;
//!     println!("Verification Stats:");
//!     println!("  Consensus agreements: {}", verify_stats.consensus_agreements);
//!     println!("  Consensus disagreements: {}", verify_stats.consensus_disagreements);
//!     println!("  Avg validators per job: {:.1}", verify_stats.average_validators_per_job);
//! }
//! ```
//!
//! # Best Practices
//!
//! ## Resource Limits
//! - Always set appropriate resource limits for untrusted code
//! - Default limits: 10MB memory, 10M instructions, 30s timeout
//! - Adjust based on expected workload complexity
//!
//! ## Distributed Execution
//! - Use at least 3 validators for Byzantine fault tolerance
//! - Monitor validator health and capacity regularly
//! - Handle timeout and failure events proactively
//!
//! ## Error Recovery
//! - Implement periodic timeout checks (recommended: every 60s)
//! - Set up validator health monitoring
//! - Track retry counts and investigate jobs hitting max retries
//!
//! ## Performance Optimization
//! - Monitor average execution times to detect performance issues
//! - Use load balancing to distribute work evenly
//! - Track memory and instruction usage for optimization opportunities
//!
//! ## Security
//! - Always execute untrusted WASM in sandboxed environment
//! - Enforce instruction limits to prevent infinite loops
//! - Use memory limits to prevent resource exhaustion
//! - Verify results through multi-validator consensus

pub mod compute_circuit;
pub mod distribution;
pub mod engine;
pub mod executor;
pub mod job;
pub mod manager;
pub mod private_job;
pub mod verification;

// Re-export main types
pub use compute_circuit::{ComputeCircuit, ComputeProofSystem, MAX_DATA_SIZE};
pub use distribution::{
    CapacityAnnouncement, CoordinatorStats, JobAssignment, JobCoordinator, ValidatorJobFetcher,
    DEFAULT_JOB_TIMEOUT_SECS, MAX_JOB_RETRIES,
};
pub use engine::WasmEngine;
pub use executor::{ExecutorStats, JobExecutor};
pub use job::{ComputeJob, JobId, JobResult, JobStatus, ResourceLimits};
pub use manager::{JobManager, ManagerStats, ValidatorCapacity, ValidatorId};
pub use private_job::{PrivateComputeJob, PrivateJobCoordinator, PrivateJobResult};
pub use verification::{
    ConsensusResult, ValidatorResult, VerificationCoordinator, VerificationRequest,
    VerificationStats, CONSENSUS_THRESHOLD, VERIFICATION_VALIDATOR_COUNT,
};
