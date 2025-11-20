//! Job distribution protocol for compute layer
//!
//! This module handles:
//! - Validator capacity announcements
//! - Job assignment by coordinator
//! - Job fetching by validators

use anyhow::Result;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::job::JobId;
use super::manager::{ValidatorCapacity, ValidatorId};

/// Validator capacity announcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityAnnouncement {
    pub validator_id: ValidatorId,
    pub cpu_cores: u8,
    pub memory_mb: u64,
    pub max_concurrent_jobs: usize,
    pub current_load: usize, // Number of currently running jobs
}

impl CapacityAnnouncement {
    /// Create a new capacity announcement
    pub fn new(capacity: ValidatorCapacity, current_load: usize) -> Self {
        Self {
            validator_id: capacity.validator_id,
            cpu_cores: capacity.cpu_cores,
            memory_mb: capacity.memory_mb,
            max_concurrent_jobs: capacity.max_concurrent_jobs,
            current_load,
        }
    }

    /// Calculate available capacity
    pub fn available_capacity(&self) -> usize {
        self.max_concurrent_jobs.saturating_sub(self.current_load)
    }

    /// Calculate load factor (0.0 to 1.0)
    pub fn load_factor(&self) -> f64 {
        if self.max_concurrent_jobs == 0 {
            1.0
        } else {
            self.current_load as f64 / self.max_concurrent_jobs as f64
        }
    }
}

/// Job assignment from coordinator to validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAssignment {
    pub job_id: JobId,
    pub validator_id: ValidatorId,
    pub assigned_at: u64, // Unix timestamp
    pub timeout_at: u64,  // When this assignment expires
    pub retry_count: u32, // Number of times this job has been retried
}

impl JobAssignment {
    pub fn new(job_id: JobId, validator_id: ValidatorId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            job_id,
            validator_id,
            assigned_at: now,
            timeout_at: now + DEFAULT_JOB_TIMEOUT_SECS,
            retry_count: 0,
        }
    }

    /// Create assignment with custom timeout
    pub fn with_timeout(job_id: JobId, validator_id: ValidatorId, timeout_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            job_id,
            validator_id,
            assigned_at: now,
            timeout_at: now + timeout_secs,
            retry_count: 0,
        }
    }

    /// Check if this assignment has timed out
    pub fn is_timed_out(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.timeout_at
    }

    /// Increment retry count and create new assignment
    pub fn retry(&self, new_validator_id: ValidatorId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            job_id: self.job_id.clone(),
            validator_id: new_validator_id,
            assigned_at: now,
            timeout_at: now + DEFAULT_JOB_TIMEOUT_SECS,
            retry_count: self.retry_count + 1,
        }
    }
}

/// Default job timeout (5 minutes)
pub const DEFAULT_JOB_TIMEOUT_SECS: u64 = 300;

/// Maximum retries before giving up
pub const MAX_JOB_RETRIES: u32 = 3;

/// Distributed job coordinator
///
/// Tracks validator capacities and assigns jobs to validators
pub struct JobCoordinator {
    /// Known validators and their capacities
    validators: Arc<RwLock<HashMap<ValidatorId, CapacityAnnouncement>>>,

    /// Pending job assignments waiting to be fetched
    /// Note: Public for integration testing
    pub pending_assignments: Arc<RwLock<HashMap<JobId, JobAssignment>>>,

    /// Active assignments (validator has fetched the job)
    active_assignments: Arc<RwLock<HashMap<JobId, JobAssignment>>>,
}

impl JobCoordinator {
    /// Create a new job coordinator
    pub fn new() -> Self {
        Self {
            validators: Arc::new(RwLock::new(HashMap::new())),
            pending_assignments: Arc::new(RwLock::new(HashMap::new())),
            active_assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register or update a validator's capacity
    pub async fn update_validator_capacity(&self, announcement: CapacityAnnouncement) {
        let mut validators = self.validators.write().await;
        info!(
            "Updated capacity for validator {}: {} cores, {} MB, {}/{} jobs",
            announcement.validator_id,
            announcement.cpu_cores,
            announcement.memory_mb,
            announcement.current_load,
            announcement.max_concurrent_jobs
        );
        validators.insert(announcement.validator_id.clone(), announcement);
    }

    /// Remove a validator (when it goes offline)
    pub async fn remove_validator(&self, validator_id: &ValidatorId) {
        let mut validators = self.validators.write().await;
        validators.remove(validator_id);
        info!("Removed validator: {}", validator_id);
    }

    /// Get all registered validators
    pub async fn get_validators(&self) -> Vec<CapacityAnnouncement> {
        let validators = self.validators.read().await;
        validators.values().cloned().collect()
    }

    /// Calculate actual load for a validator based on assignments
    pub async fn get_validator_load(&self, validator_id: &ValidatorId) -> usize {
        let pending = self.pending_assignments.read().await;
        let active = self.active_assignments.read().await;

        let pending_count = pending
            .values()
            .filter(|a| &a.validator_id == validator_id)
            .count();

        let active_count = active
            .values()
            .filter(|a| &a.validator_id == validator_id)
            .count();

        pending_count + active_count
    }

    /// Check if validator has available capacity based on actual assignments
    pub async fn has_available_capacity(&self, announcement: &CapacityAnnouncement) -> bool {
        let current_load = self.get_validator_load(&announcement.validator_id).await;
        current_load < announcement.max_concurrent_jobs
    }

    /// Assign a job to the best available validator
    pub async fn assign_job(&self, job_id: JobId) -> Result<Option<JobAssignment>> {
        let validators = self.validators.read().await;

        // Find validator with lowest load factor and available capacity
        let best_validator = validators
            .values()
            .filter(|v| v.available_capacity() > 0)
            .min_by(|a, b| {
                a.load_factor()
                    .partial_cmp(&b.load_factor())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        if let Some(validator) = best_validator {
            let assignment = JobAssignment::new(job_id.clone(), validator.validator_id.clone());

            // Store as pending assignment
            let mut pending = self.pending_assignments.write().await;
            pending.insert(job_id.clone(), assignment.clone());

            debug!(
                "Assigned job {} to validator {} (load: {:.1}%)",
                job_id,
                validator.validator_id,
                validator.load_factor() * 100.0
            );

            Ok(Some(assignment))
        } else {
            debug!("No available validators for job {}", job_id);
            Ok(None)
        }
    }

    /// Mark a job as fetched by the validator (moves from pending to active)
    pub async fn mark_job_fetched(&self, job_id: &JobId) -> Result<()> {
        let mut pending = self.pending_assignments.write().await;

        if let Some(assignment) = pending.remove(job_id) {
            let mut active = self.active_assignments.write().await;
            active.insert(job_id.clone(), assignment.clone());

            debug!(
                "Job {} marked as fetched by validator {}",
                job_id, assignment.validator_id
            );
        }

        Ok(())
    }

    /// Get pending assignment for a validator
    pub async fn get_pending_jobs_for_validator(&self, validator_id: &ValidatorId) -> Vec<JobId> {
        let pending = self.pending_assignments.read().await;
        pending
            .iter()
            .filter(|(_, assignment)| &assignment.validator_id == validator_id)
            .map(|(job_id, _)| job_id.clone())
            .collect()
    }

    /// Remove a completed job assignment
    pub async fn remove_assignment(&self, job_id: &JobId) -> Result<()> {
        let mut pending = self.pending_assignments.write().await;
        let mut active = self.active_assignments.write().await;

        pending.remove(job_id);
        active.remove(job_id);

        debug!("Removed assignment for job {}", job_id);
        Ok(())
    }

    /// Check for timed out jobs and reassign them
    pub async fn handle_timeouts(&self) -> Result<Vec<JobId>> {
        let mut reassigned_jobs = Vec::new();

        // Check pending assignments
        {
            let mut pending = self.pending_assignments.write().await;
            let timed_out: Vec<_> = pending
                .iter()
                .filter(|(_, assignment)| assignment.is_timed_out())
                .map(|(id, _)| id.clone())
                .collect();

            for job_id in timed_out {
                if let Some(old_assignment) = pending.remove(&job_id) {
                    warn!(
                        "Job {} timed out (assigned to {}), retry count: {}",
                        job_id, old_assignment.validator_id, old_assignment.retry_count
                    );

                    // Try to reassign if under retry limit
                    if old_assignment.retry_count < MAX_JOB_RETRIES {
                        // Find best validator with available capacity
                        let validators = self.validators.read().await;
                        let mut best_validator: Option<&CapacityAnnouncement> = None;
                        let mut best_load = usize::MAX;

                        for validator in validators.values() {
                            let current_load = {
                                let pending_count = pending
                                    .values()
                                    .filter(|a| a.validator_id == validator.validator_id)
                                    .count();
                                pending_count
                            };

                            if current_load < validator.max_concurrent_jobs
                                && current_load < best_load
                            {
                                best_load = current_load;
                                best_validator = Some(validator);
                            }
                        }

                        if let Some(validator) = best_validator {
                            // Create retried assignment with incremented retry count
                            let new_assignment =
                                old_assignment.retry(validator.validator_id.clone());
                            pending.insert(job_id.clone(), new_assignment);
                            reassigned_jobs.push(job_id.clone());

                            info!(
                                "Reassigned job {} to validator {} (retry {})",
                                job_id,
                                validator.validator_id,
                                old_assignment.retry_count + 1
                            );
                        } else {
                            warn!("No available validators to reassign job {}", job_id);
                        }
                    } else {
                        warn!(
                            "Job {} exceeded max retries ({}), giving up",
                            job_id, MAX_JOB_RETRIES
                        );
                    }
                }
            }
        }

        // Check active assignments
        {
            let mut active = self.active_assignments.write().await;
            let timed_out: Vec<_> = active
                .iter()
                .filter(|(_, assignment)| assignment.is_timed_out())
                .map(|(id, _)| id.clone())
                .collect();

            for job_id in timed_out {
                if let Some(old_assignment) = active.remove(&job_id) {
                    warn!(
                        "Active job {} timed out (validator {}), retry count: {}",
                        job_id, old_assignment.validator_id, old_assignment.retry_count
                    );

                    // Try to reassign if under retry limit
                    if old_assignment.retry_count < MAX_JOB_RETRIES {
                        // Find best validator with available capacity
                        let validators = self.validators.read().await;
                        let pending = self.pending_assignments.read().await;
                        let mut best_validator: Option<&CapacityAnnouncement> = None;
                        let mut best_load = usize::MAX;

                        for validator in validators.values() {
                            let current_load = {
                                let pending_count = pending
                                    .values()
                                    .filter(|a| a.validator_id == validator.validator_id)
                                    .count();
                                let active_count = active
                                    .values()
                                    .filter(|a| a.validator_id == validator.validator_id)
                                    .count();
                                pending_count + active_count
                            };

                            if current_load < validator.max_concurrent_jobs
                                && current_load < best_load
                            {
                                best_load = current_load;
                                best_validator = Some(validator);
                            }
                        }

                        if let Some(validator) = best_validator {
                            // Create retried assignment and add to pending
                            let new_assignment =
                                old_assignment.retry(validator.validator_id.clone());
                            drop(pending); // Release pending read lock
                            let mut pending_write = self.pending_assignments.write().await;
                            pending_write.insert(job_id.clone(), new_assignment);
                            reassigned_jobs.push(job_id.clone());

                            info!(
                                "Reassigned active job {} to validator {} (retry {})",
                                job_id,
                                validator.validator_id,
                                old_assignment.retry_count + 1
                            );
                        } else {
                            warn!("No available validators to reassign active job {}", job_id);
                        }
                    } else {
                        warn!(
                            "Active job {} exceeded max retries ({}), giving up",
                            job_id, MAX_JOB_RETRIES
                        );
                    }
                }
            }
        }

        if !reassigned_jobs.is_empty() {
            info!("Reassigned {} timed out jobs", reassigned_jobs.len());
        }

        Ok(reassigned_jobs)
    }

    /// Handle validator failure - reassign all its jobs
    pub async fn handle_validator_failure(&self, validator_id: &ValidatorId) -> Result<usize> {
        let mut reassigned_count = 0;

        // Remove validator from registry
        self.remove_validator(validator_id).await;

        // Reassign pending jobs
        {
            let mut pending = self.pending_assignments.write().await;
            let failed_jobs: Vec<_> = pending
                .iter()
                .filter(|(_, assignment)| &assignment.validator_id == validator_id)
                .map(|(id, _)| id.clone())
                .collect();

            for job_id in failed_jobs {
                if let Some(old_assignment) = pending.remove(&job_id) {
                    warn!(
                        "Reassigning job {} from failed validator {}, retry count: {}",
                        job_id, validator_id, old_assignment.retry_count
                    );

                    if old_assignment.retry_count < MAX_JOB_RETRIES {
                        // Find best validator with available capacity
                        let validators = self.validators.read().await;
                        let mut best_validator: Option<&CapacityAnnouncement> = None;
                        let mut best_load = usize::MAX;

                        for validator in validators.values() {
                            let current_load = {
                                let pending_count = pending
                                    .values()
                                    .filter(|a| a.validator_id == validator.validator_id)
                                    .count();
                                pending_count
                            };

                            if current_load < validator.max_concurrent_jobs
                                && current_load < best_load
                            {
                                best_load = current_load;
                                best_validator = Some(validator);
                            }
                        }

                        if let Some(validator) = best_validator {
                            // Create retried assignment with incremented retry count
                            let new_assignment =
                                old_assignment.retry(validator.validator_id.clone());
                            pending.insert(job_id.clone(), new_assignment);
                            reassigned_count += 1;

                            info!(
                                "Reassigned job {} to validator {} (retry {})",
                                job_id,
                                validator.validator_id,
                                old_assignment.retry_count + 1
                            );
                        } else {
                            warn!("No available validators to reassign job {}", job_id);
                        }
                    } else {
                        warn!(
                            "Job {} exceeded max retries ({}), giving up",
                            job_id, MAX_JOB_RETRIES
                        );
                    }
                }
            }
        }

        // Reassign active jobs
        {
            let mut active = self.active_assignments.write().await;
            let failed_jobs: Vec<_> = active
                .iter()
                .filter(|(_, assignment)| &assignment.validator_id == validator_id)
                .map(|(id, _)| id.clone())
                .collect();

            for job_id in failed_jobs {
                if let Some(old_assignment) = active.remove(&job_id) {
                    warn!(
                        "Reassigning active job {} from failed validator {}, retry count: {}",
                        job_id, validator_id, old_assignment.retry_count
                    );

                    if old_assignment.retry_count < MAX_JOB_RETRIES {
                        // Find best validator with available capacity
                        let validators = self.validators.read().await;
                        let pending = self.pending_assignments.read().await;
                        let mut best_validator: Option<&CapacityAnnouncement> = None;
                        let mut best_load = usize::MAX;

                        for validator in validators.values() {
                            let current_load = {
                                let pending_count = pending
                                    .values()
                                    .filter(|a| a.validator_id == validator.validator_id)
                                    .count();
                                let active_count = active
                                    .values()
                                    .filter(|a| a.validator_id == validator.validator_id)
                                    .count();
                                pending_count + active_count
                            };

                            if current_load < validator.max_concurrent_jobs
                                && current_load < best_load
                            {
                                best_load = current_load;
                                best_validator = Some(validator);
                            }
                        }

                        if let Some(validator) = best_validator {
                            // Create retried assignment and add to pending
                            let new_assignment =
                                old_assignment.retry(validator.validator_id.clone());
                            drop(pending); // Release pending read lock
                            let mut pending_write = self.pending_assignments.write().await;
                            pending_write.insert(job_id.clone(), new_assignment);
                            reassigned_count += 1;

                            info!(
                                "Reassigned active job {} to validator {} (retry {})",
                                job_id,
                                validator.validator_id,
                                old_assignment.retry_count + 1
                            );
                        } else {
                            warn!("No available validators to reassign active job {}", job_id);
                        }
                    } else {
                        warn!(
                            "Active job {} exceeded max retries ({}), giving up",
                            job_id, MAX_JOB_RETRIES
                        );
                    }
                }
            }
        }

        info!(
            "Reassigned {} jobs from failed validator {}",
            reassigned_count, validator_id
        );

        Ok(reassigned_count)
    }

    /// Get statistics
    pub async fn get_stats(&self) -> CoordinatorStats {
        let validators = self.validators.read().await;
        let pending = self.pending_assignments.read().await;
        let active = self.active_assignments.read().await;

        // Calculate retry and timeout metrics
        let mut total_retries = 0u64;
        let mut jobs_at_max_retries = 0;
        let mut timed_out_jobs = 0;

        for assignment in pending.values().chain(active.values()) {
            total_retries += assignment.retry_count as u64;

            if assignment.retry_count >= MAX_JOB_RETRIES {
                jobs_at_max_retries += 1;
            }

            if assignment.is_timed_out() {
                timed_out_jobs += 1;
            }
        }

        let total_jobs = pending.len() + active.len();
        let average_retry_count = if total_jobs > 0 {
            total_retries as f64 / total_jobs as f64
        } else {
            0.0
        };

        CoordinatorStats {
            total_validators: validators.len(),
            available_validators: validators
                .values()
                .filter(|v| v.available_capacity() > 0)
                .count(),
            total_capacity: validators.values().map(|v| v.max_concurrent_jobs).sum(),
            current_load: validators.values().map(|v| v.current_load).sum(),
            pending_assignments: pending.len(),
            active_assignments: active.len(),
            total_assignments: total_jobs,
            jobs_at_max_retries,
            timed_out_jobs,
            average_retry_count,
        }
    }
}

impl Default for JobCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Coordinator statistics
#[derive(Debug, Clone)]
pub struct CoordinatorStats {
    pub total_validators: usize,
    pub available_validators: usize,
    pub total_capacity: usize,
    pub current_load: usize,
    pub pending_assignments: usize,
    pub active_assignments: usize,
    pub total_assignments: usize,
    pub jobs_at_max_retries: usize,
    pub timed_out_jobs: usize,
    pub average_retry_count: f64,
}

/// Validator job fetcher
///
/// Validators use this to poll for assigned jobs
pub struct ValidatorJobFetcher {
    validator_id: ValidatorId,
    capacity: ValidatorCapacity,
}

impl ValidatorJobFetcher {
    /// Create a new job fetcher for a validator
    pub fn new(validator_id: ValidatorId, capacity: ValidatorCapacity) -> Self {
        Self {
            validator_id,
            capacity,
        }
    }

    /// Create a capacity announcement
    pub fn create_announcement(&self, current_load: usize) -> CapacityAnnouncement {
        CapacityAnnouncement::new(self.capacity.clone(), current_load)
    }

    /// Get validator ID
    pub fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let coordinator = JobCoordinator::new();
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.total_validators, 0);
    }

    #[tokio::test]
    async fn test_validator_registration() {
        let coordinator = JobCoordinator::new();

        let capacity = ValidatorCapacity::new("validator1".to_string(), 8, 16384, 4);
        let announcement = CapacityAnnouncement::new(capacity, 0);

        coordinator.update_validator_capacity(announcement).await;

        let stats = coordinator.get_stats().await;
        assert_eq!(stats.total_validators, 1);
        assert_eq!(stats.total_capacity, 4);
    }

    #[tokio::test]
    async fn test_job_assignment() {
        let coordinator = JobCoordinator::new();

        // Register validator
        let capacity = ValidatorCapacity::new("validator1".to_string(), 8, 16384, 4);
        let announcement = CapacityAnnouncement::new(capacity, 0);
        coordinator.update_validator_capacity(announcement).await;

        // Assign job
        let job_id = "job1".to_string();
        let assignment = coordinator.assign_job(job_id.clone()).await.unwrap();

        assert!(assignment.is_some());
        assert_eq!(assignment.unwrap().validator_id, "validator1");

        let stats = coordinator.get_stats().await;
        assert_eq!(stats.pending_assignments, 1);
    }

    #[tokio::test]
    async fn test_load_balancing() {
        let coordinator = JobCoordinator::new();

        // Register two validators with different loads
        let capacity1 = ValidatorCapacity::new("v1".to_string(), 4, 8192, 2);
        let announcement1 = CapacityAnnouncement::new(capacity1, 0); // Empty
        coordinator.update_validator_capacity(announcement1).await;

        let capacity2 = ValidatorCapacity::new("v2".to_string(), 8, 16384, 4);
        let announcement2 = CapacityAnnouncement::new(capacity2, 3); // Almost full
        coordinator.update_validator_capacity(announcement2).await;

        // Assign job - should go to v1 (lower load)
        let job_id = "job1".to_string();
        let assignment = coordinator.assign_job(job_id).await.unwrap();

        assert!(assignment.is_some());
        assert_eq!(assignment.unwrap().validator_id, "v1");
    }

    #[tokio::test]
    async fn test_no_available_validators() {
        let coordinator = JobCoordinator::new();

        // Register validator at full capacity
        let capacity = ValidatorCapacity::new("v1".to_string(), 4, 8192, 2);
        let announcement = CapacityAnnouncement::new(capacity, 2); // Full
        coordinator.update_validator_capacity(announcement).await;

        // Try to assign job
        let job_id = "job1".to_string();
        let assignment = coordinator.assign_job(job_id).await.unwrap();

        assert!(assignment.is_none());
    }

    #[tokio::test]
    async fn test_job_fetching() {
        let coordinator = JobCoordinator::new();

        let capacity = ValidatorCapacity::new("v1".to_string(), 4, 8192, 2);
        let announcement = CapacityAnnouncement::new(capacity, 0);
        coordinator.update_validator_capacity(announcement).await;

        let job_id = "job1".to_string();
        coordinator.assign_job(job_id.clone()).await.unwrap();

        let stats = coordinator.get_stats().await;
        assert_eq!(stats.pending_assignments, 1);
        assert_eq!(stats.active_assignments, 0);

        // Mark as fetched
        coordinator.mark_job_fetched(&job_id).await.unwrap();

        let stats = coordinator.get_stats().await;
        assert_eq!(stats.pending_assignments, 0);
        assert_eq!(stats.active_assignments, 1);
    }

    #[test]
    fn test_capacity_announcement() {
        let capacity = ValidatorCapacity::new("v1".to_string(), 8, 16384, 4);
        let announcement = CapacityAnnouncement::new(capacity, 2);

        assert_eq!(announcement.available_capacity(), 2);
        assert_eq!(announcement.load_factor(), 0.5);
    }

    #[tokio::test]
    async fn test_job_timeout_detection() {
        use std::time::Duration;
        use tokio::time::sleep;

        let coordinator = JobCoordinator::new();

        // Register validator
        let capacity = ValidatorCapacity::new("v1".to_string(), 4, 8192, 2);
        let announcement = CapacityAnnouncement::new(capacity, 0);
        coordinator.update_validator_capacity(announcement).await;

        // Assign job with short timeout
        let job_id = "job1".to_string();
        let assignment = JobAssignment::with_timeout(job_id.clone(), "v1".to_string(), 1); // 1 second

        {
            let mut pending = coordinator.pending_assignments.write().await;
            pending.insert(job_id.clone(), assignment);
        }

        // Wait for timeout
        sleep(Duration::from_secs(2)).await;

        // Check that assignment is timed out
        {
            let pending = coordinator.pending_assignments.read().await;
            let assignment = pending.get(&job_id).unwrap();
            assert!(assignment.is_timed_out());
        }
    }

    #[tokio::test]
    async fn test_timeout_handling_reassignment() {
        let coordinator = JobCoordinator::new();

        // Register two validators
        let capacity1 = ValidatorCapacity::new("v1".to_string(), 4, 8192, 2);
        let capacity2 = ValidatorCapacity::new("v2".to_string(), 4, 8192, 2);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity1, 0))
            .await;
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity2, 0))
            .await;

        // Create timed out assignment
        let job_id = "job1".to_string();
        let assignment = JobAssignment::with_timeout(job_id.clone(), "v1".to_string(), 0); // Already timed out

        {
            let mut pending = coordinator.pending_assignments.write().await;
            pending.insert(job_id.clone(), assignment);
        }

        // Handle timeouts - should reassign
        let reassigned = coordinator.handle_timeouts().await.unwrap();
        assert_eq!(reassigned.len(), 1);
        assert_eq!(reassigned[0], job_id);
    }

    #[tokio::test]
    async fn test_validator_failure_reassignment() {
        let coordinator = JobCoordinator::new();

        // Register v1 first (will be preferred due to load balancing)
        let capacity1 = ValidatorCapacity::new("v1".to_string(), 4, 8192, 10);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity1, 0))
            .await;

        // Assign 2 jobs while only v1 is available
        let assignment1 = coordinator.assign_job("job1".to_string()).await.unwrap();
        let assignment2 = coordinator.assign_job("job2".to_string()).await.unwrap();

        // Verify both jobs went to v1
        assert_eq!(assignment1.as_ref().unwrap().validator_id, "v1");
        assert_eq!(assignment2.as_ref().unwrap().validator_id, "v1");

        // Now register v2 for reassignment target
        let capacity2 = ValidatorCapacity::new("v2".to_string(), 4, 8192, 10);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity2, 0))
            .await;

        let stats_before = coordinator.get_stats().await;
        assert_eq!(stats_before.pending_assignments, 2);

        // Handle v1 failure - should reassign both jobs to v2
        let reassigned = coordinator
            .handle_validator_failure(&"v1".to_string())
            .await
            .unwrap();
        assert_eq!(reassigned, 2);

        // Check that jobs were reassigned to v2
        let stats_after = coordinator.get_stats().await;
        assert_eq!(stats_after.total_validators, 1); // v1 removed
        assert_eq!(stats_after.pending_assignments, 2); // Jobs reassigned
    }

    #[tokio::test]
    async fn test_max_retries() {
        let coordinator = JobCoordinator::new();

        // Register one validator
        let capacity = ValidatorCapacity::new("v1".to_string(), 4, 8192, 2);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity, 0))
            .await;

        // Create assignment with max retries already reached
        let job_id = "job1".to_string();
        let mut assignment = JobAssignment::with_timeout(job_id.clone(), "v1".to_string(), 0);
        assignment.retry_count = MAX_JOB_RETRIES; // Already at max

        {
            let mut pending = coordinator.pending_assignments.write().await;
            pending.insert(job_id.clone(), assignment);
        }

        // Handle timeouts - should NOT reassign (max retries reached)
        let reassigned = coordinator.handle_timeouts().await.unwrap();
        assert_eq!(reassigned.len(), 0);

        // Job should be removed from pending
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.pending_assignments, 0);
    }
}
