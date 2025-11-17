//! Distributed job manager for coordinating compute across validators
//!
//! This module manages job distribution across multiple validators,
//! tracks their resources, and aggregates results.

use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::job::{ComputeJob, JobId, JobResult, JobStatus};

/// Validator identifier
pub type ValidatorId = String;

/// Validator resource capacity
#[derive(Clone, Debug)]
pub struct ValidatorCapacity {
    /// Validator identifier
    pub validator_id: ValidatorId,

    /// Number of CPU cores available
    pub cpu_cores: u8,

    /// Available memory in MB
    pub memory_mb: u64,

    /// Current active jobs
    pub active_jobs: usize,

    /// Maximum concurrent jobs this validator can handle
    pub max_concurrent_jobs: usize,

    /// Last heartbeat timestamp
    pub last_heartbeat: u64,
}

impl ValidatorCapacity {
    /// Create new validator capacity info
    pub fn new(
        validator_id: ValidatorId,
        cpu_cores: u8,
        memory_mb: u64,
        max_concurrent_jobs: usize,
    ) -> Self {
        Self {
            validator_id,
            cpu_cores,
            memory_mb,
            active_jobs: 0,
            max_concurrent_jobs,
            last_heartbeat: current_timestamp(),
        }
    }

    /// Check if validator can accept more jobs
    pub fn can_accept_job(&self) -> bool {
        self.active_jobs < self.max_concurrent_jobs
    }

    /// Calculate load factor (0.0 = idle, 1.0 = full)
    pub fn load_factor(&self) -> f64 {
        if self.max_concurrent_jobs == 0 {
            1.0
        } else {
            self.active_jobs as f64 / self.max_concurrent_jobs as f64
        }
    }

    /// Check if validator is alive (heartbeat within last 30 seconds)
    pub fn is_alive(&self) -> bool {
        let now = current_timestamp();
        now - self.last_heartbeat < 30_000 // 30 seconds
    }
}

/// Job assignment tracking
#[derive(Clone, Debug)]
pub struct JobAssignment {
    /// Job ID
    pub job_id: JobId,

    /// Assigned validator
    pub validator_id: ValidatorId,

    /// Assignment timestamp
    pub assigned_at: u64,
}

/// Distributed job manager
pub struct JobManager {
    /// Registered validators and their capacities
    validators: Arc<Mutex<HashMap<ValidatorId, ValidatorCapacity>>>,

    /// Pending jobs waiting for assignment
    pending_jobs: Arc<Mutex<Vec<ComputeJob>>>,

    /// Active job assignments
    assignments: Arc<Mutex<HashMap<JobId, JobAssignment>>>,

    /// Completed job results
    results: Arc<Mutex<HashMap<JobId, JobResult>>>,
}

impl JobManager {
    /// Create a new job manager
    pub fn new() -> Self {
        info!("Initializing distributed job manager");

        Self {
            validators: Arc::new(Mutex::new(HashMap::new())),
            pending_jobs: Arc::new(Mutex::new(Vec::new())),
            assignments: Arc::new(Mutex::new(HashMap::new())),
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a validator with the manager
    pub fn register_validator(&self, capacity: ValidatorCapacity) -> Result<()> {
        let validator_id = capacity.validator_id.clone();

        info!(
            "Registering validator {} with {} cores, {} MB memory, max {} jobs",
            validator_id, capacity.cpu_cores, capacity.memory_mb, capacity.max_concurrent_jobs
        );

        let mut validators = self.validators.lock().unwrap();
        validators.insert(validator_id, capacity);

        Ok(())
    }

    /// Update validator heartbeat
    pub fn update_heartbeat(&self, validator_id: &ValidatorId) -> Result<()> {
        let mut validators = self.validators.lock().unwrap();

        if let Some(validator) = validators.get_mut(validator_id) {
            validator.last_heartbeat = current_timestamp();
            debug!("Updated heartbeat for validator {}", validator_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Validator {} not found", validator_id))
        }
    }

    /// Submit a job for distributed execution
    pub fn submit_job(&self, job: ComputeJob) -> Result<JobId> {
        let job_id = job.id.clone();

        info!("Submitting job {} for distributed execution", job_id);

        let mut pending = self.pending_jobs.lock().unwrap();
        pending.push(job);

        Ok(job_id)
    }

    /// Assign pending jobs to available validators using load balancing
    pub fn assign_jobs(&self) -> Result<Vec<JobAssignment>> {
        let mut assignments_made = Vec::new();

        // Get pending jobs
        let mut pending = self.pending_jobs.lock().unwrap();
        if pending.is_empty() {
            return Ok(assignments_made);
        }

        // Get available validators sorted by load (clone to avoid borrow issues)
        let mut available_validators: Vec<ValidatorCapacity> = {
            let validators = self.validators.lock().unwrap();
            validators
                .values()
                .filter(|v| v.is_alive() && v.can_accept_job())
                .cloned()
                .collect()
        };

        // Sort by load factor (least loaded first)
        available_validators.sort_by(|a, b| a.load_factor().partial_cmp(&b.load_factor()).unwrap());

        // Assign jobs to validators
        let jobs_to_assign: Vec<_> = pending.drain(..).collect();
        drop(pending); // Release lock

        for job in jobs_to_assign {
            if let Some(validator) = available_validators.first() {
                let assignment = JobAssignment {
                    job_id: job.id.clone(),
                    validator_id: validator.validator_id.clone(),
                    assigned_at: current_timestamp(),
                };

                info!(
                    "Assigned job {} to validator {} (load: {:.2}%)",
                    assignment.job_id,
                    assignment.validator_id,
                    validator.load_factor() * 100.0
                );

                // Update validator active jobs
                let mut validators = self.validators.lock().unwrap();
                if let Some(v) = validators.get_mut(&validator.validator_id) {
                    v.active_jobs += 1;
                }
                drop(validators);

                // Record assignment
                let mut assignments = self.assignments.lock().unwrap();
                assignments.insert(job.id.clone(), assignment.clone());
                drop(assignments);

                assignments_made.push(assignment);

                // Re-sort validators after assignment
                available_validators = {
                    let validators = self.validators.lock().unwrap();
                    validators
                        .values()
                        .filter(|v| v.is_alive() && v.can_accept_job())
                        .cloned()
                        .collect()
                };
                available_validators
                    .sort_by(|a, b| a.load_factor().partial_cmp(&b.load_factor()).unwrap());
            } else {
                // No available validators, put job back in queue
                warn!("No available validators for job {}", job.id);
                let mut pending = self.pending_jobs.lock().unwrap();
                pending.push(job);
                break;
            }
        }

        Ok(assignments_made)
    }

    /// Submit a job result from a validator
    pub fn submit_result(&self, result: JobResult) -> Result<()> {
        let job_id = result.job_id.clone();

        info!(
            "Received result for job {} (status: {:?})",
            job_id, result.status
        );

        // Update validator active jobs
        let assignments = self.assignments.lock().unwrap();
        if let Some(assignment) = assignments.get(&job_id) {
            let mut validators = self.validators.lock().unwrap();
            if let Some(validator) = validators.get_mut(&assignment.validator_id) {
                validator.active_jobs = validator.active_jobs.saturating_sub(1);
            }
        }
        drop(assignments);

        // Store result
        let mut results = self.results.lock().unwrap();
        results.insert(job_id, result);

        Ok(())
    }

    /// Get job result
    pub fn get_result(&self, job_id: &JobId) -> Option<JobResult> {
        let results = self.results.lock().unwrap();
        results.get(job_id).cloned()
    }

    /// Get job status
    pub fn get_job_status(&self, job_id: &JobId) -> Option<JobStatus> {
        // Check results first
        {
            let results = self.results.lock().unwrap();
            if let Some(result) = results.get(job_id) {
                return Some(result.status.clone());
            }
        }

        // Check assignments
        {
            let assignments = self.assignments.lock().unwrap();
            if assignments.contains_key(job_id) {
                return Some(JobStatus::Running);
            }
        }

        // Check pending
        {
            let pending = self.pending_jobs.lock().unwrap();
            if pending.iter().any(|j| &j.id == job_id) {
                return Some(JobStatus::Pending);
            }
        }

        None
    }

    /// Get manager statistics
    pub fn get_stats(&self) -> ManagerStats {
        let validators = self.validators.lock().unwrap();
        let pending = self.pending_jobs.lock().unwrap();
        let results = self.results.lock().unwrap();

        let total_validators = validators.len();
        let active_validators = validators.values().filter(|v| v.is_alive()).count();
        let total_capacity: usize = validators.values().map(|v| v.max_concurrent_jobs).sum();
        let active_jobs: usize = validators.values().map(|v| v.active_jobs).sum();

        ManagerStats {
            total_validators,
            active_validators,
            total_capacity,
            active_jobs,
            pending_jobs: pending.len(),
            completed_jobs: results.len(),
        }
    }

    /// Remove stale validators (no heartbeat for 60+ seconds)
    pub fn cleanup_stale_validators(&self) -> usize {
        let mut validators = self.validators.lock().unwrap();
        let now = current_timestamp();
        let mut removed = 0;

        validators.retain(|id, v| {
            let age = now - v.last_heartbeat;
            if age > 60_000 {
                // 60 seconds
                warn!(
                    "Removing stale validator {} (last heartbeat: {}ms ago)",
                    id, age
                );
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Manager statistics
#[derive(Debug, Clone)]
pub struct ManagerStats {
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_capacity: usize,
    pub active_jobs: usize,
    pub pending_jobs: usize,
    pub completed_jobs: usize,
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::job::ResourceLimits;

    #[test]
    fn test_job_manager_creation() {
        let manager = JobManager::new();
        let stats = manager.get_stats();

        assert_eq!(stats.total_validators, 0);
        assert_eq!(stats.pending_jobs, 0);
    }

    #[test]
    fn test_validator_registration() {
        let manager = JobManager::new();

        let capacity = ValidatorCapacity::new("validator1".to_string(), 4, 8192, 2);

        manager.register_validator(capacity).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.total_validators, 1);
        assert_eq!(stats.total_capacity, 2);
    }

    #[test]
    fn test_job_submission() {
        let manager = JobManager::new();

        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d],
            vec![1, 2, 3],
            ResourceLimits::default(),
        );
        let job_id = job.id.clone();

        manager.submit_job(job).unwrap();

        let stats = manager.get_stats();
        assert_eq!(stats.pending_jobs, 1);

        let status = manager.get_job_status(&job_id);
        assert_eq!(status, Some(JobStatus::Pending));
    }

    #[test]
    fn test_job_assignment() {
        let manager = JobManager::new();

        // Register validator
        let capacity = ValidatorCapacity::new("validator1".to_string(), 4, 8192, 2);
        manager.register_validator(capacity).unwrap();

        // Submit job
        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d],
            vec![],
            ResourceLimits::default(),
        );
        manager.submit_job(job).unwrap();

        // Assign jobs
        let assignments = manager.assign_jobs().unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].validator_id, "validator1");

        let stats = manager.get_stats();
        assert_eq!(stats.pending_jobs, 0);
        assert_eq!(stats.active_jobs, 1);
    }

    #[test]
    fn test_load_balancing() {
        let manager = JobManager::new();

        // Register two validators
        manager
            .register_validator(ValidatorCapacity::new("validator1".to_string(), 4, 8192, 2))
            .unwrap();
        manager
            .register_validator(ValidatorCapacity::new("validator2".to_string(), 4, 8192, 2))
            .unwrap();

        // Submit 3 jobs
        for i in 0..3 {
            let job = ComputeJob::new(vec![i], vec![], ResourceLimits::default());
            manager.submit_job(job).unwrap();
        }

        // Assign jobs
        let assignments = manager.assign_jobs().unwrap();
        assert_eq!(assignments.len(), 3);

        // Jobs should be distributed across validators
        let validator1_jobs = assignments
            .iter()
            .filter(|a| a.validator_id == "validator1")
            .count();
        let validator2_jobs = assignments
            .iter()
            .filter(|a| a.validator_id == "validator2")
            .count();

        // Should be balanced (2 on one, 1 on other)
        assert!(validator1_jobs == 2 || validator2_jobs == 2);
        assert!(validator1_jobs == 1 || validator2_jobs == 1);
    }

    #[test]
    fn test_validator_capacity() {
        let capacity = ValidatorCapacity::new("test".to_string(), 4, 8192, 2);

        assert!(capacity.can_accept_job());
        assert_eq!(capacity.load_factor(), 0.0);
        assert!(capacity.is_alive());
    }
}
