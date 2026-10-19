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

    /// Helper to compute a validator's effective live load from its announced base load
    /// plus in-flight coordinator assignments (`pending` + `active`).
    fn count_live_load(
        validator: &CapacityAnnouncement,
        pending: &HashMap<JobId, JobAssignment>,
        active: &HashMap<JobId, JobAssignment>,
    ) -> usize {
        let pending_count = pending
            .values()
            .filter(|a| a.validator_id == validator.validator_id)
            .count();
        let active_count = active
            .values()
            .filter(|a| a.validator_id == validator.validator_id)
            .count();
        validator
            .current_load
            .saturating_add(pending_count)
            .saturating_add(active_count)
    }

    /// Calculate actual load for a validator based on announced load + assignments
    pub async fn get_validator_load(&self, validator_id: &ValidatorId) -> usize {
        let validators = self.validators.read().await;
        let pending = self.pending_assignments.read().await;
        let active = self.active_assignments.read().await;

        let base_load = validators
            .get(validator_id)
            .map(|v| v.current_load)
            .unwrap_or(0);

        let pending_count = pending
            .values()
            .filter(|a| &a.validator_id == validator_id)
            .count();

        let active_count = active
            .values()
            .filter(|a| &a.validator_id == validator_id)
            .count();

        base_load + pending_count + active_count
    }

    /// Check if validator has available capacity based on actual assignments
    pub async fn has_available_capacity(&self, announcement: &CapacityAnnouncement) -> bool {
        let current_load = self.get_validator_load(&announcement.validator_id).await;
        current_load < announcement.max_concurrent_jobs
    }

    /// Assign a job to the best available validator
    ///
    /// Canonical lock acquisition order across `JobCoordinator`:
    /// `validators` -> `pending_assignments` -> `active_assignments`
    pub async fn assign_job(&self, job_id: JobId) -> Result<Option<JobAssignment>> {
        let validators = self.validators.read().await;
        let mut pending = self.pending_assignments.write().await;
        let active = self.active_assignments.read().await;

        // Find validator with lowest live load factor and available live capacity
        let best_validator = validators
            .values()
            .filter(|v| {
                v.max_concurrent_jobs > 0
                    && Self::count_live_load(v, &pending, &active) < v.max_concurrent_jobs
            })
            .min_by(|a, b| {
                let load_a = Self::count_live_load(a, &pending, &active) as f64
                    / a.max_concurrent_jobs as f64;
                let load_b = Self::count_live_load(b, &pending, &active) as f64
                    / b.max_concurrent_jobs as f64;
                load_a
                    .partial_cmp(&load_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

        if let Some(validator) = best_validator {
            let live_load = Self::count_live_load(validator, &pending, &active);
            let assignment = JobAssignment::new(job_id.clone(), validator.validator_id.clone());

            // Store as pending assignment
            pending.insert(job_id.clone(), assignment.clone());

            debug!(
                "Assigned job {} to validator {} (load: {:.1}%)",
                job_id,
                validator.validator_id,
                (live_load as f64 / validator.max_concurrent_jobs as f64) * 100.0
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

        // Acquire locks in canonical order: validators -> pending_assignments -> active_assignments
        let validators = self.validators.read().await;
        let mut pending = self.pending_assignments.write().await;
        let mut active = self.active_assignments.write().await;

        // Check pending assignments
        let timed_out_pending: Vec<_> = pending
            .iter()
            .filter(|(_, assignment)| assignment.is_timed_out())
            .map(|(id, _)| id.clone())
            .collect();

        for job_id in timed_out_pending {
            if let Some(old_assignment) = pending.remove(&job_id) {
                warn!(
                    "Job {} timed out (assigned to {}), retry count: {}",
                    job_id, old_assignment.validator_id, old_assignment.retry_count
                );

                // Try to reassign if under retry limit
                if old_assignment.retry_count < MAX_JOB_RETRIES {
                    let mut best_validator: Option<&CapacityAnnouncement> = None;
                    let mut best_load = usize::MAX;

                    for validator in validators.values() {
                        let current_load = Self::count_live_load(validator, &pending, &active);

                        if current_load < validator.max_concurrent_jobs && current_load < best_load
                        {
                            best_load = current_load;
                            best_validator = Some(validator);
                        }
                    }

                    if let Some(validator) = best_validator {
                        let new_assignment = old_assignment.retry(validator.validator_id.clone());
                        pending.insert(job_id.clone(), new_assignment);
                        reassigned_jobs.push(job_id.clone());

                        info!(
                            "Reassigned job {} to validator {} (retry {})",
                            job_id,
                            validator.validator_id,
                            old_assignment.retry_count + 1
                        );
                    } else {
                        warn!(
                            "No available validators to reassign job {}, retaining in pending queue",
                            job_id
                        );
                        let deferred = old_assignment.retry(old_assignment.validator_id.clone());
                        pending.insert(job_id.clone(), deferred);
                    }
                } else {
                    warn!(
                        "Job {} exceeded max retries ({}), giving up",
                        job_id, MAX_JOB_RETRIES
                    );
                }
            }
        }

        // Check active assignments
        let timed_out_active: Vec<_> = active
            .iter()
            .filter(|(_, assignment)| assignment.is_timed_out())
            .map(|(id, _)| id.clone())
            .collect();

        for job_id in timed_out_active {
            if let Some(old_assignment) = active.remove(&job_id) {
                warn!(
                    "Active job {} timed out (validator {}), retry count: {}",
                    job_id, old_assignment.validator_id, old_assignment.retry_count
                );

                // Try to reassign if under retry limit
                if old_assignment.retry_count < MAX_JOB_RETRIES {
                    let mut best_validator: Option<&CapacityAnnouncement> = None;
                    let mut best_load = usize::MAX;

                    for validator in validators.values() {
                        let current_load = Self::count_live_load(validator, &pending, &active);

                        if current_load < validator.max_concurrent_jobs && current_load < best_load
                        {
                            best_load = current_load;
                            best_validator = Some(validator);
                        }
                    }

                    if let Some(validator) = best_validator {
                        let new_assignment = old_assignment.retry(validator.validator_id.clone());
                        pending.insert(job_id.clone(), new_assignment);
                        reassigned_jobs.push(job_id.clone());

                        info!(
                            "Reassigned active job {} to validator {} (retry {})",
                            job_id,
                            validator.validator_id,
                            old_assignment.retry_count + 1
                        );
                    } else {
                        warn!(
                            "No available validators to reassign active job {}, retaining in pending queue",
                            job_id
                        );
                        let deferred = old_assignment.retry(old_assignment.validator_id.clone());
                        pending.insert(job_id.clone(), deferred);
                    }
                } else {
                    warn!(
                        "Active job {} exceeded max retries ({}), giving up",
                        job_id, MAX_JOB_RETRIES
                    );
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

        // Acquire locks in canonical order: validators -> pending_assignments -> active_assignments
        let validators = self.validators.read().await;
        let mut pending = self.pending_assignments.write().await;
        let mut active = self.active_assignments.write().await;

        // Reassign pending jobs
        let failed_pending: Vec<_> = pending
            .iter()
            .filter(|(_, assignment)| &assignment.validator_id == validator_id)
            .map(|(id, _)| id.clone())
            .collect();

        for job_id in failed_pending {
            if let Some(old_assignment) = pending.remove(&job_id) {
                warn!(
                    "Reassigning job {} from failed validator {}, retry count: {}",
                    job_id, validator_id, old_assignment.retry_count
                );

                if old_assignment.retry_count < MAX_JOB_RETRIES {
                    let mut best_validator: Option<&CapacityAnnouncement> = None;
                    let mut best_load = usize::MAX;

                    for validator in validators.values() {
                        let current_load = Self::count_live_load(validator, &pending, &active);

                        if current_load < validator.max_concurrent_jobs && current_load < best_load
                        {
                            best_load = current_load;
                            best_validator = Some(validator);
                        }
                    }

                    if let Some(validator) = best_validator {
                        let new_assignment = old_assignment.retry(validator.validator_id.clone());
                        pending.insert(job_id.clone(), new_assignment);
                        reassigned_count += 1;

                        info!(
                            "Reassigned job {} to validator {} (retry {})",
                            job_id,
                            validator.validator_id,
                            old_assignment.retry_count + 1
                        );
                    } else {
                        warn!(
                            "No available validators to reassign job {}, retaining in pending queue",
                            job_id
                        );
                        let deferred = old_assignment.retry(old_assignment.validator_id.clone());
                        pending.insert(job_id.clone(), deferred);
                    }
                } else {
                    warn!(
                        "Job {} exceeded max retries ({}), giving up",
                        job_id, MAX_JOB_RETRIES
                    );
                }
            }
        }

        // Reassign active jobs
        let failed_active: Vec<_> = active
            .iter()
            .filter(|(_, assignment)| &assignment.validator_id == validator_id)
            .map(|(id, _)| id.clone())
            .collect();

        for job_id in failed_active {
            if let Some(old_assignment) = active.remove(&job_id) {
                warn!(
                    "Reassigning active job {} from failed validator {}, retry count: {}",
                    job_id, validator_id, old_assignment.retry_count
                );

                if old_assignment.retry_count < MAX_JOB_RETRIES {
                    let mut best_validator: Option<&CapacityAnnouncement> = None;
                    let mut best_load = usize::MAX;

                    for validator in validators.values() {
                        let current_load = Self::count_live_load(validator, &pending, &active);

                        if current_load < validator.max_concurrent_jobs && current_load < best_load
                        {
                            best_load = current_load;
                            best_validator = Some(validator);
                        }
                    }

                    if let Some(validator) = best_validator {
                        let new_assignment = old_assignment.retry(validator.validator_id.clone());
                        pending.insert(job_id.clone(), new_assignment);
                        reassigned_count += 1;

                        info!(
                            "Reassigned active job {} to validator {} (retry {})",
                            job_id,
                            validator.validator_id,
                            old_assignment.retry_count + 1
                        );
                    } else {
                        warn!(
                            "No available validators to reassign active job {}, retaining in pending queue",
                            job_id
                        );
                        let deferred = old_assignment.retry(old_assignment.validator_id.clone());
                        pending.insert(job_id.clone(), deferred);
                    }
                } else {
                    warn!(
                        "Active job {} exceeded max retries ({}), giving up",
                        job_id, MAX_JOB_RETRIES
                    );
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
                .filter(|v| Self::count_live_load(v, &pending, &active) < v.max_concurrent_jobs)
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

    #[tokio::test]
    async fn test_assign_job_respects_live_pending_and_active_load() {
        let coordinator = JobCoordinator::new();

        // Register two validators with max_concurrent_jobs = 1 each and current_load = 0
        let cap1 = ValidatorCapacity::new("v1".to_string(), 4, 8192, 1);
        let cap2 = ValidatorCapacity::new("v2".to_string(), 4, 8192, 1);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(cap1, 0))
            .await;
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(cap2, 0))
            .await;

        let a1 = coordinator
            .assign_job("job1".to_string())
            .await
            .unwrap()
            .unwrap();
        let a2 = coordinator
            .assign_job("job2".to_string())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            a1.validator_id, a2.validator_id,
            "second job must be routed to the idle validator, not stacked on the first"
        );

        // Third job must return None because both validators are now at max live capacity (1/1)
        let a3 = coordinator.assign_job("job3".to_string()).await.unwrap();
        assert!(
            a3.is_none(),
            "assign_job must not exceed max_concurrent_jobs when pending assignments fill capacity"
        );
    }

    #[tokio::test]
    async fn test_timeout_retains_job_when_all_validators_busy() {
        let coordinator = JobCoordinator::new();

        // Single validator already at full base capacity
        let cap = ValidatorCapacity::new("v1".to_string(), 4, 8192, 1);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(cap, 1))
            .await;

        let job_id = "job_retryable".to_string();
        let assignment = JobAssignment::with_timeout(job_id.clone(), "v1".to_string(), 0);
        {
            let mut pending = coordinator.pending_assignments.write().await;
            pending.insert(job_id.clone(), assignment);
        }

        // Timeout handling when no validator has free capacity must retain the job in pending
        let reassigned = coordinator.handle_timeouts().await.unwrap();
        assert!(reassigned.is_empty());

        let pending = coordinator.pending_assignments.read().await;
        let retained = pending
            .get(&job_id)
            .expect("retryable job must not be dropped when capacity is temporarily full");
        assert_eq!(retained.retry_count, 1);
    }
}
