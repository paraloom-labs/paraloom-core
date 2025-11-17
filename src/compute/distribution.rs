//! Job distribution protocol for compute layer
//!
//! This module handles:
//! - Validator capacity announcements
//! - Job assignment by coordinator
//! - Job fetching by validators

use anyhow::Result;
use log::{debug, info};
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
}

impl JobAssignment {
    pub fn new(job_id: JobId, validator_id: ValidatorId) -> Self {
        Self {
            job_id,
            validator_id,
            assigned_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Distributed job coordinator
///
/// Tracks validator capacities and assigns jobs to validators
pub struct JobCoordinator {
    /// Known validators and their capacities
    validators: Arc<RwLock<HashMap<ValidatorId, CapacityAnnouncement>>>,

    /// Pending job assignments waiting to be fetched
    pending_assignments: Arc<RwLock<HashMap<JobId, JobAssignment>>>,

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

    /// Get statistics
    pub async fn get_stats(&self) -> CoordinatorStats {
        let validators = self.validators.read().await;
        let pending = self.pending_assignments.read().await;
        let active = self.active_assignments.read().await;

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
}
