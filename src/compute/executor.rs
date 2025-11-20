//! Job executor with scheduling and resource management
//!
//! This module manages the execution queue, schedules jobs based on
//! available resources, and coordinates WASM execution.

use anyhow::Result;
use log::{debug, info, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::task;

use super::engine::WasmEngine;
use super::job::{ComputeJob, JobId, JobResult, JobStatus};

/// Maximum number of concurrent jobs
const MAX_CONCURRENT_JOBS: usize = 4;

/// Job execution coordinator
pub struct JobExecutor {
    /// WASM execution engine
    engine: Arc<WasmEngine>,

    /// Pending jobs queue
    pending_jobs: Arc<Mutex<VecDeque<ComputeJob>>>,

    /// Active jobs being executed
    active_jobs: Arc<Mutex<HashMap<JobId, ComputeJob>>>,

    /// Completed job results
    completed_results: Arc<Mutex<HashMap<JobId, JobResult>>>,

    /// Job result notification channel
    result_tx: mpsc::UnboundedSender<JobResult>,
    result_rx: Arc<Mutex<mpsc::UnboundedReceiver<JobResult>>>,
}

impl JobExecutor {
    /// Create a new job executor
    pub fn new() -> Result<Self> {
        let engine = Arc::new(WasmEngine::new()?);
        let (result_tx, result_rx) = mpsc::unbounded_channel();

        Ok(Self {
            engine,
            pending_jobs: Arc::new(Mutex::new(VecDeque::new())),
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            completed_results: Arc::new(Mutex::new(HashMap::new())),
            result_tx,
            result_rx: Arc::new(Mutex::new(result_rx)),
        })
    }

    /// Submit a new job for execution
    pub fn submit_job(&self, job: ComputeJob) -> Result<JobId> {
        let job_id = job.id.clone();

        info!("Submitting job {} to execution queue", job_id);

        let mut pending = self.pending_jobs.lock().unwrap();
        pending.push_back(job);

        debug!(
            "Job {} added to pending queue (total pending: {})",
            job_id,
            pending.len()
        );

        Ok(job_id)
    }

    /// Get job status
    pub fn get_job_status(&self, job_id: &JobId) -> Option<JobStatus> {
        // Check pending jobs
        {
            let pending = self.pending_jobs.lock().unwrap();
            if let Some(job) = pending.iter().find(|j| &j.id == job_id) {
                return Some(job.status.clone());
            }
        }

        // Check active jobs
        {
            let active = self.active_jobs.lock().unwrap();
            if let Some(job) = active.get(job_id) {
                return Some(job.status.clone());
            }
        }

        // Check completed results
        {
            let completed = self.completed_results.lock().unwrap();
            if let Some(result) = completed.get(job_id) {
                return Some(result.status.clone());
            }
        }

        None
    }

    /// Get job result (if completed)
    pub fn get_job_result(&self, job_id: &JobId) -> Option<JobResult> {
        let completed = self.completed_results.lock().unwrap();
        completed.get(job_id).cloned()
    }

    /// Get all completed job results
    pub fn get_all_results(&self) -> Vec<JobResult> {
        let completed = self.completed_results.lock().unwrap();
        completed.values().cloned().collect()
    }

    /// Start the executor (processes jobs from the queue)
    pub async fn start(&self) -> Result<()> {
        info!("Starting job executor");

        let pending_jobs = self.pending_jobs.clone();
        let active_jobs = self.active_jobs.clone();
        let completed_results = self.completed_results.clone();
        let engine = self.engine.clone();
        let result_tx = self.result_tx.clone();
        let result_rx = self.result_rx.clone();

        // Spawn executor task
        task::spawn(async move {
            loop {
                // Check if we can execute more jobs
                let active_count = active_jobs.lock().unwrap().len();

                if active_count < MAX_CONCURRENT_JOBS {
                    // Get next job from queue
                    let next_job = {
                        let mut pending = pending_jobs.lock().unwrap();
                        pending.pop_front()
                    };

                    if let Some(mut job) = next_job {
                        info!("Starting execution of job {}", job.id);

                        // Mark as running
                        job.mark_running();
                        let job_id = job.id.clone();

                        // Add to active jobs
                        {
                            let mut active = active_jobs.lock().unwrap();
                            active.insert(job_id.clone(), job.clone());
                        }

                        // Execute in separate task
                        let engine_clone = engine.clone();
                        let active_jobs_clone = active_jobs.clone();
                        let result_tx_clone = result_tx.clone();

                        task::spawn(async move {
                            // Execute the job
                            let result = match engine_clone.execute_job(&job) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!("Job {} execution error: {}", job_id, e);
                                    JobResult::failure(
                                        job_id.clone(),
                                        format!("Execution error: {}", e),
                                        0,
                                    )
                                }
                            };

                            info!(
                                "Job {} execution completed with status: {:?}",
                                job_id, result.status
                            );

                            // Remove from active jobs
                            {
                                let mut active = active_jobs_clone.lock().unwrap();
                                active.remove(&job_id);
                            }

                            // Send result notification
                            let _ = result_tx_clone.send(result);
                        });
                    } else {
                        // No pending jobs, sleep for a bit
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } else {
                    // Max concurrent jobs reached, wait
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }

                // Process completed results
                Self::process_results(result_rx.clone(), completed_results.clone()).await;
            }
        });

        Ok(())
    }

    /// Process completed job results
    async fn process_results(
        result_rx: Arc<Mutex<mpsc::UnboundedReceiver<JobResult>>>,
        completed_results: Arc<Mutex<HashMap<JobId, JobResult>>>,
    ) {
        let mut rx = result_rx.lock().unwrap();

        while let Ok(result) = rx.try_recv() {
            debug!("Processing result for job {}", result.job_id);

            let mut completed = completed_results.lock().unwrap();
            completed.insert(result.job_id.clone(), result);
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> ExecutorStats {
        let pending_count = self.pending_jobs.lock().unwrap().len();
        let active_count = self.active_jobs.lock().unwrap().len();
        let completed = self.completed_results.lock().unwrap();

        // Calculate aggregate metrics from completed jobs
        let mut failed_count = 0;
        let mut total_exec_time = 0u64;
        let mut total_memory = 0u64;
        let mut total_instructions = 0u64;
        let mut completed_count = 0;

        for result in completed.values() {
            match result.status {
                JobStatus::Completed => {
                    completed_count += 1;
                    total_exec_time += result.execution_time_ms;
                    total_memory += result.memory_used_bytes;
                    total_instructions += result.instructions_executed;
                }
                JobStatus::Failed { .. } => {
                    failed_count += 1;
                }
                _ => {}
            }
        }

        let avg_exec_time = if completed_count > 0 {
            total_exec_time / completed_count as u64
        } else {
            0
        };

        ExecutorStats {
            pending_jobs: pending_count,
            active_jobs: active_count,
            completed_jobs: completed_count,
            failed_jobs: failed_count,
            total_execution_time_ms: total_exec_time,
            average_execution_time_ms: avg_exec_time,
            total_memory_used_bytes: total_memory,
            total_instructions_executed: total_instructions,
        }
    }

    /// Clear completed results (useful for cleanup)
    pub fn clear_completed(&self) {
        let mut completed = self.completed_results.lock().unwrap();
        completed.clear();
        info!("Cleared completed job results");
    }
}

impl Default for JobExecutor {
    fn default() -> Self {
        Self::new().expect("Failed to create default job executor")
    }
}

/// Executor statistics
#[derive(Debug, Clone)]
pub struct ExecutorStats {
    pub pending_jobs: usize,
    pub active_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub total_execution_time_ms: u64,
    pub average_execution_time_ms: u64,
    pub total_memory_used_bytes: u64,
    pub total_instructions_executed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::job::ResourceLimits;

    #[tokio::test]
    async fn test_executor_creation() {
        let executor = JobExecutor::new();
        assert!(executor.is_ok());
    }

    #[tokio::test]
    async fn test_job_submission() {
        let executor = JobExecutor::new().unwrap();

        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d],
            vec![1, 2, 3],
            ResourceLimits::default(),
        );
        let job_id = job.id.clone();

        let result = executor.submit_job(job);
        assert!(result.is_ok());

        let status = executor.get_job_status(&job_id);
        assert_eq!(status, Some(JobStatus::Pending));
    }

    #[tokio::test]
    async fn test_executor_stats() {
        let executor = JobExecutor::new().unwrap();

        let stats = executor.get_stats();
        assert_eq!(stats.pending_jobs, 0);
        assert_eq!(stats.active_jobs, 0);
        assert_eq!(stats.completed_jobs, 0);

        // Submit a job
        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d],
            vec![],
            ResourceLimits::default(),
        );
        executor.submit_job(job).unwrap();

        let stats = executor.get_stats();
        assert_eq!(stats.pending_jobs, 1);
    }

    #[tokio::test]
    async fn test_multiple_job_submission() {
        let executor = JobExecutor::new().unwrap();

        // Submit multiple jobs
        for i in 0..5 {
            let job = ComputeJob::new(
                vec![0x00, 0x61, 0x73, 0x6d],
                vec![i],
                ResourceLimits::default(),
            );
            executor.submit_job(job).unwrap();
        }

        let stats = executor.get_stats();
        assert_eq!(stats.pending_jobs, 5);
    }
}
