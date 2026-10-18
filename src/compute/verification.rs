//! Result verification and consensus for compute jobs
//!
//! This module implements multi-validator verification:
//! - Assign same job to multiple validators
//! - Collect and compare results
//! - Require 2/3 consensus for deterministic WASM

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::job::{JobId, JobResult};
use super::manager::ValidatorId;

/// Number of validators required for verification
pub const VERIFICATION_VALIDATOR_COUNT: usize = 3;

/// Minimum validators needed for consensus (2 out of 3)
pub const CONSENSUS_THRESHOLD: usize = 2;

/// Verification request for a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub job_id: JobId,
    pub validators: Vec<ValidatorId>,
    pub created_at: u64,
}

impl VerificationRequest {
    pub fn new(job_id: JobId, validators: Vec<ValidatorId>) -> Self {
        Self {
            job_id,
            validators,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Verification result from a validator
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorResult {
    pub validator_id: ValidatorId,
    pub result: JobResult,
    pub submitted_at: u64,
}

impl ValidatorResult {
    pub fn new(validator_id: ValidatorId, result: JobResult) -> Self {
        Self {
            validator_id,
            result,
            submitted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Consensus result
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusResult {
    /// Consensus reached - result is verified
    Agreed(JobResult),

    /// No consensus - validators disagree
    Disagreed { results: Vec<ValidatorResult> },

    /// Insufficient results - need more validators
    Insufficient { received: usize, required: usize },
}

/// Result verification coordinator
pub struct VerificationCoordinator {
    /// Active verification requests
    requests: Arc<RwLock<HashMap<JobId, VerificationRequest>>>,

    /// Collected results per job
    results: Arc<RwLock<HashMap<JobId, Vec<ValidatorResult>>>>,
}

impl VerificationCoordinator {
    /// Create a new verification coordinator
    pub fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a verification request for a job
    pub async fn create_verification_request(
        &self,
        job_id: JobId,
        validators: Vec<ValidatorId>,
    ) -> Result<VerificationRequest> {
        let mut unique_validators = Vec::new();
        for v in validators {
            if !unique_validators.contains(&v) {
                unique_validators.push(v);
            }
        }
        if unique_validators.len() < VERIFICATION_VALIDATOR_COUNT {
            return Err(anyhow!(
                "Insufficient distinct validators: need {}, got {}",
                VERIFICATION_VALIDATOR_COUNT,
                unique_validators.len()
            ));
        }

        let request = VerificationRequest::new(job_id.clone(), unique_validators);

        let mut requests = self.requests.write().await;
        requests.insert(job_id.clone(), request.clone());

        info!(
            "Created verification request for job {} with {} validators",
            job_id,
            request.validators.len()
        );

        Ok(request)
    }

    /// Submit a result from a validator
    pub async fn submit_result(
        &self,
        job_id: &JobId,
        validator_id: ValidatorId,
        result: JobResult,
    ) -> Result<()> {
        if &result.job_id != job_id {
            return Err(anyhow!(
                "JobResult job_id '{}' does not match target job_id '{}'",
                result.job_id,
                job_id
            ));
        }
        // Bind the result to the job's assigned validator set: only a validator
        // this job was actually assigned to may contribute a result. Without
        // this, any peer could inject results toward the consensus tally for a
        // job it was never asked to run (F4). A result for an unknown job — or
        // from an unassigned validator — is rejected outright.
        {
            let requests = self.requests.read().await;
            let request = requests.get(job_id).ok_or_else(|| {
                anyhow!(
                    "No verification request for job {}; result from {} rejected",
                    job_id,
                    validator_id
                )
            })?;
            if !request.validators.contains(&validator_id) {
                return Err(anyhow!(
                    "Validator {} was not assigned to job {}; result rejected",
                    validator_id,
                    job_id
                ));
            }
        }

        let validator_result = ValidatorResult::new(validator_id.clone(), result);

        let mut results = self.results.write().await;
        let job_results = results.entry(job_id.clone()).or_insert_with(Vec::new);

        // Check if this validator already submitted
        if job_results.iter().any(|r| r.validator_id == validator_id) {
            warn!(
                "Validator {} already submitted result for job {}",
                validator_id, job_id
            );
            return Ok(());
        }

        job_results.push(validator_result);

        debug!(
            "Received result from validator {} for job {} ({}/{})",
            validator_id,
            job_id,
            job_results.len(),
            VERIFICATION_VALIDATOR_COUNT
        );

        Ok(())
    }

    /// Check if consensus has been reached for a job
    pub async fn check_consensus(&self, job_id: &JobId) -> Result<ConsensusResult> {
        let requests = self.requests.read().await;
        let results = self.results.read().await;

        let assigned_count = requests
            .get(job_id)
            .map(|r| r.validators.len())
            .unwrap_or(VERIFICATION_VALIDATOR_COUNT);
        let required_threshold =
            std::cmp::max(CONSENSUS_THRESHOLD, (2 * assigned_count + 2) / 3);

        let job_results = match results.get(job_id) {
            Some(r) => r,
            None => {
                return Ok(ConsensusResult::Insufficient {
                    received: 0,
                    required: required_threshold,
                });
            }
        };

        // Need at least `required_threshold` results
        if job_results.len() < required_threshold {
            return Ok(ConsensusResult::Insufficient {
                received: job_results.len(),
                required: required_threshold,
            });
        }

        // Group successful results by output data (for deterministic WASM).
        // Failed / TimedOut / None-output results must never be grouped together
        // to form a positive `ConsensusResult::Agreed` quorum.
        let mut result_groups: HashMap<Vec<u8>, Vec<&ValidatorResult>> = HashMap::new();

        for validator_result in job_results {
            if validator_result.result.status == super::job::JobStatus::Completed {
                if let Some(data) = &validator_result.result.output_data {
                    result_groups
                        .entry(data.clone())
                        .or_default()
                        .push(validator_result);
                }
            }
        }

        let majority_len = result_groups
            .values()
            .map(|validators| validators.len())
            .max()
            .unwrap_or(0);

        // Check if majority reaches consensus threshold
        if majority_len >= required_threshold {
            let (_majority_output, majority_results) = result_groups
                .iter()
                .max_by_key(|(_, validators)| validators.len())
                .unwrap();

            info!(
                "Consensus reached for job {}: {}/{} validators agree",
                job_id,
                majority_results.len(),
                job_results.len()
            );

            // Return the first result from the majority group (they're all the same)
            let consensus_result = majority_results[0].result.clone();
            return Ok(ConsensusResult::Agreed(consensus_result));
        }

        // If remaining unsubmitted validators could still reach `required_threshold`,
        // report `Insufficient` rather than prematurely declaring `Disagreed`.
        let remaining_validators = assigned_count.saturating_sub(job_results.len());
        if majority_len + remaining_validators >= required_threshold && remaining_validators > 0 {
            return Ok(ConsensusResult::Insufficient {
                received: job_results.len(),
                required: required_threshold,
            });
        }

        warn!(
            "No consensus for job {}: largest group has {}/{} validators",
            job_id,
            majority_len,
            required_threshold
        );

        Ok(ConsensusResult::Disagreed {
            results: job_results.clone(),
        })
    }

    /// Get verification request for a job
    pub async fn get_request(&self, job_id: &JobId) -> Option<VerificationRequest> {
        let requests = self.requests.read().await;
        requests.get(job_id).cloned()
    }

    /// Get collected results for a job
    pub async fn get_results(&self, job_id: &JobId) -> Vec<ValidatorResult> {
        let results = self.results.read().await;
        results.get(job_id).cloned().unwrap_or_default()
    }

    /// Remove verification data for a completed job
    pub async fn cleanup(&self, job_id: &JobId) {
        let mut requests = self.requests.write().await;
        let mut results = self.results.write().await;

        requests.remove(job_id);
        results.remove(job_id);

        debug!("Cleaned up verification data for job {}", job_id);
    }

    /// Get statistics
    pub async fn get_stats(&self) -> VerificationStats {
        let requests = self.requests.read().await;
        let results = self.results.read().await;

        let total_results: usize = results.values().map(|v| v.len()).sum();

        // Analyze current verifications for consensus state
        let mut consensus_agreements = 0;
        let mut consensus_disagreements = 0;
        let mut insufficient_results = 0;

        for (job_id, validator_results) in results.iter() {
            let assigned_count = requests
                .get(job_id)
                .map(|r| r.validators.len())
                .unwrap_or(VERIFICATION_VALIDATOR_COUNT);
            let required_threshold =
                std::cmp::max(CONSENSUS_THRESHOLD, (2 * assigned_count + 2) / 3);

            if validator_results.len() < required_threshold {
                insufficient_results += 1;
                continue;
            }

            // Count matching outputs among completed results only
            let mut hash_counts: HashMap<Vec<u8>, usize> = HashMap::new();
            for r in validator_results {
                if r.result.status == super::job::JobStatus::Completed {
                    if let Some(data) = &r.result.output_data {
                        *hash_counts.entry(data.clone()).or_insert(0) += 1;
                    }
                }
            }

            let max_agreement = hash_counts.values().max().copied().unwrap_or(0);
            if max_agreement >= required_threshold {
                consensus_agreements += 1;
            } else {
                let remaining = assigned_count.saturating_sub(validator_results.len());
                if max_agreement + remaining >= required_threshold && remaining > 0 {
                    insufficient_results += 1;
                } else {
                    consensus_disagreements += 1;
                }
            }
        }

        let avg_validators = if !requests.is_empty() {
            results.values().map(|v| v.len()).sum::<usize>() as f64 / requests.len() as f64
        } else {
            0.0
        };

        VerificationStats {
            active_verifications: requests.len(),
            total_results_collected: total_results,
            consensus_agreements,
            consensus_disagreements,
            insufficient_results,
            average_validators_per_job: avg_validators,
        }
    }
}

impl Default for VerificationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Verification statistics
#[derive(Debug, Clone)]
pub struct VerificationStats {
    pub active_verifications: usize,
    pub total_results_collected: usize,
    pub consensus_agreements: usize,
    pub consensus_disagreements: usize,
    pub insufficient_results: usize,
    pub average_validators_per_job: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verification_coordinator_creation() {
        let coordinator = VerificationCoordinator::new();
        let stats = coordinator.get_stats().await;
        assert_eq!(stats.active_verifications, 0);
    }

    #[tokio::test]
    async fn test_create_verification_request() {
        let coordinator = VerificationCoordinator::new();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        let request = coordinator
            .create_verification_request("job1".to_string(), validators.clone())
            .await;

        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.validators.len(), 3);
    }

    #[tokio::test]
    async fn test_insufficient_validators() {
        let coordinator = VerificationCoordinator::new();
        let validators = vec!["v1".to_string()]; // Only 1, need 3

        let request = coordinator
            .create_verification_request("job1".to_string(), validators)
            .await;

        assert!(request.is_err());
    }

    #[tokio::test]
    async fn test_consensus_all_agree() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job1".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        // All 3 validators return same result
        let output = vec![42u8];
        for v in &["v1", "v2", "v3"] {
            let result = JobResult::success(job_id.clone(), output.clone(), 100, 1024, 50000);
            coordinator
                .submit_result(&job_id, v.to_string(), result)
                .await
                .unwrap();
        }

        let consensus = coordinator.check_consensus(&job_id).await.unwrap();
        assert!(matches!(consensus, ConsensusResult::Agreed(_)));
    }

    #[tokio::test]
    async fn test_consensus_majority() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job1".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        // 2 validators agree, 1 disagrees
        let result1 = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);
        let result2 = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);
        let result3 = JobResult::success(job_id.clone(), vec![99], 100, 1024, 50000); // Different

        coordinator
            .submit_result(&job_id, "v1".to_string(), result1)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v2".to_string(), result2)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v3".to_string(), result3)
            .await
            .unwrap();

        let consensus = coordinator.check_consensus(&job_id).await.unwrap();

        // Should reach consensus with majority (2/3)
        match consensus {
            ConsensusResult::Agreed(result) => {
                assert_eq!(result.output_data.unwrap(), vec![42]);
            }
            _ => panic!("Expected consensus to be reached"),
        }
    }

    #[tokio::test]
    async fn test_no_consensus() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job1".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        // All 3 validators return different results
        let result1 = JobResult::success(job_id.clone(), vec![1], 100, 1024, 50000);
        let result2 = JobResult::success(job_id.clone(), vec![2], 100, 1024, 50000);
        let result3 = JobResult::success(job_id.clone(), vec![3], 100, 1024, 50000);

        coordinator
            .submit_result(&job_id, "v1".to_string(), result1)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v2".to_string(), result2)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v3".to_string(), result3)
            .await
            .unwrap();

        let consensus = coordinator.check_consensus(&job_id).await.unwrap();
        assert!(matches!(consensus, ConsensusResult::Disagreed { .. }));
    }

    #[tokio::test]
    async fn test_insufficient_results() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job1".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        // Only 1 validator submits
        let result = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);
        coordinator
            .submit_result(&job_id, "v1".to_string(), result)
            .await
            .unwrap();

        let consensus = coordinator.check_consensus(&job_id).await.unwrap();
        assert!(matches!(
            consensus,
            ConsensusResult::Insufficient {
                received: 1,
                required: 2
            }
        ));
    }

    #[tokio::test]
    async fn test_duplicate_submission() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job1".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        let result1 = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);
        let result2 = JobResult::success(job_id.clone(), vec![99], 100, 1024, 50000);

        coordinator
            .submit_result(&job_id, "v1".to_string(), result1)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v1".to_string(), result2)
            .await
            .unwrap();

        let results = coordinator.get_results(&job_id).await;
        assert_eq!(results.len(), 1); // Should only have 1 result (duplicate ignored)
    }

    #[tokio::test]
    async fn test_unassigned_validator_result_is_rejected() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job1".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        // A validator the job was never assigned to cannot contribute a result.
        let intruder = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);
        let rejected = coordinator
            .submit_result(&job_id, "attacker".to_string(), intruder)
            .await;
        assert!(rejected.is_err());
        assert!(coordinator.get_results(&job_id).await.is_empty());
    }

    #[tokio::test]
    async fn test_result_for_unknown_job_is_rejected() {
        let coordinator = VerificationCoordinator::new();
        // No verification request exists for this job.
        let result = JobResult::success("ghost".to_string(), vec![42], 100, 1024, 50000);
        let rejected = coordinator
            .submit_result(&"ghost".to_string(), "v1".to_string(), result)
            .await;
        assert!(rejected.is_err());
    }

    #[tokio::test]
    async fn test_failed_results_do_not_form_consensus_agreement() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job-failed-quorum".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        let fail1 = JobResult::failure(job_id.clone(), "OOM".to_string(), 10);
        let fail2 = JobResult::failure(job_id.clone(), "Timeout".to_string(), 20);
        let ok3 = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);

        coordinator
            .submit_result(&job_id, "v1".to_string(), fail1)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v2".to_string(), fail2)
            .await
            .unwrap();

        // After 2 failures and 1 remaining validator, 2/3 success is impossible.
        let early = coordinator.check_consensus(&job_id).await.unwrap();
        assert!(matches!(early, ConsensusResult::Disagreed { .. }));

        coordinator
            .submit_result(&job_id, "v3".to_string(), ok3)
            .await
            .unwrap();

        let final_res = coordinator.check_consensus(&job_id).await.unwrap();
        assert!(matches!(final_res, ConsensusResult::Disagreed { .. }));
    }

    #[tokio::test]
    async fn test_two_divergent_results_wait_for_third_validator() {
        let coordinator = VerificationCoordinator::new();
        let job_id = "job-tiebreaker".to_string();
        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];

        coordinator
            .create_verification_request(job_id.clone(), validators)
            .await
            .unwrap();

        let r1 = JobResult::success(job_id.clone(), vec![1], 100, 1024, 50000);
        let r2 = JobResult::success(job_id.clone(), vec![2], 100, 1024, 50000);

        coordinator
            .submit_result(&job_id, "v1".to_string(), r1)
            .await
            .unwrap();
        coordinator
            .submit_result(&job_id, "v2".to_string(), r2)
            .await
            .unwrap();

        // v3 can still break the tie, so status must be Insufficient, not Disagreed.
        let status = coordinator.check_consensus(&job_id).await.unwrap();
        assert!(matches!(
            status,
            ConsensusResult::Insufficient {
                received: 2,
                required: 2
            }
        ));

        // v3 agrees with v2 -> Consensus reached!
        let r3 = JobResult::success(job_id.clone(), vec![2], 100, 1024, 50000);
        coordinator
            .submit_result(&job_id, "v3".to_string(), r3)
            .await
            .unwrap();

        let resolved = coordinator.check_consensus(&job_id).await.unwrap();
        match resolved {
            ConsensusResult::Agreed(res) => assert_eq!(res.output_data.unwrap(), vec![2]),
            other => panic!("Expected Agreed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_duplicate_validators_in_request_rejected_and_mismatched_job_id_rejected() {
        let coordinator = VerificationCoordinator::new();
        let dup_validators = vec!["v1".to_string(), "v1".to_string(), "v2".to_string()];
        assert!(coordinator
            .create_verification_request("job-dup".to_string(), dup_validators)
            .await
            .is_err());

        let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];
        coordinator
            .create_verification_request("job-a".to_string(), validators)
            .await
            .unwrap();

        let wrong_job_res = JobResult::success("job-b".to_string(), vec![1], 10, 1024, 100);
        assert!(coordinator
            .submit_result(&"job-a".to_string(), "v1".to_string(), wrong_job_res)
            .await
            .is_err());
    }
}
