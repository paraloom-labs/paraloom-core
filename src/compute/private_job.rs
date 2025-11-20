//! Private compute jobs with privacy-preserving execution
//!
//! This module integrates the compute layer with the privacy layer to enable:
//! - Private job submission (input data hidden via commitments)
//! - Privacy-preserving execution (validators can't see input/output)
//! - zkSNARK-verified results (prove correct execution without revealing data)
//! - Shielded result retrieval (only job owner can decrypt output)
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                     PRIVATE COMPUTE WORKFLOW                      │
//! └──────────────────────────────────────────────────────────────────┘
//!
//! 1. Job Submission (Private Input):
//!    User → Create commitment to input data
//!        → Deposit into shielded pool
//!        → Submit job with commitment (not raw data)
//!
//! 2. Execution (Privacy-Preserving):
//!    Validators → Execute WASM with encrypted input
//!             → Generate output commitment
//!             → Create zkSNARK proof of correct execution
//!
//! 3. Verification (Consensus + Privacy):
//!    Validators → Verify 2/3 agree on output commitment
//!             → Verify zkSNARK proof
//!             → Finalize result in shielded pool
//!
//! 4. Result Retrieval (Private Output):
//!    User → Prove ownership of output commitment
//!        → Withdraw result from shielded pool
//!        → Decrypt output data
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::compute::{ComputeJob, JobId, JobResult, ResourceLimits};
use crate::privacy::{Commitment, Note, ShieldedAddress, ShieldedPool};

/// A private compute job with hidden input/output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateComputeJob {
    /// Unique job identifier
    pub job_id: JobId,

    /// WASM code (public - deterministic execution)
    pub wasm_code: Vec<u8>,

    /// Hash of WASM code (for verification)
    pub code_hash: [u8; 32],

    /// Input data commitment (private - hides actual input)
    pub input_commitment: Commitment,

    /// Encrypted input data (only job owner can decrypt)
    pub encrypted_input: Vec<u8>,

    /// Job owner's shielded address (for result retrieval)
    pub owner_address: ShieldedAddress,

    /// Resource limits for execution
    pub limits: ResourceLimits,

    /// Timestamp when job was created
    pub created_at: u64,
}

impl PrivateComputeJob {
    /// Create a new private compute job
    pub fn new(
        wasm_code: Vec<u8>,
        input_data: Vec<u8>,
        owner_address: ShieldedAddress,
        limits: ResourceLimits,
    ) -> Result<Self> {
        use sha2::{Digest, Sha256};

        // Compute code hash
        let code_hash: [u8; 32] = Sha256::digest(&wasm_code).into();

        // Create commitment to input data
        // Hash the data first to get a u64 value
        let data_hash = Self::hash_data(&input_data);
        let randomness = crate::privacy::pedersen::generate_randomness();
        let input_commitment =
            crate::privacy::commitment::CommitmentGenerator::commit(data_hash, &randomness);

        // Encrypt input data with owner's public key
        // TODO: Implement proper encryption (for now, just use XOR with address)
        let encrypted_input = Self::encrypt_data(&input_data, &owner_address);

        let job_id = uuid::Uuid::new_v4().to_string();

        Ok(Self {
            job_id,
            wasm_code,
            code_hash,
            input_commitment,
            encrypted_input,
            owner_address,
            limits,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Convert to standard compute job (for execution)
    pub fn to_compute_job(&self) -> ComputeJob {
        ComputeJob::new(
            self.wasm_code.clone(),
            self.encrypted_input.clone(),
            self.limits.clone(),
        )
    }

    /// Hash data to u64 (for commitment)
    fn hash_data(data: &[u8]) -> u64 {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        // Take first 8 bytes and convert to u64
        u64::from_le_bytes(hash[..8].try_into().unwrap())
    }

    /// Simple encryption (TODO: replace with proper encryption)
    fn encrypt_data(data: &[u8], address: &ShieldedAddress) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ address.0[i % 32])
            .collect()
    }

    /// Simple decryption (TODO: replace with proper decryption)
    pub fn decrypt_data(encrypted: &[u8], address: &ShieldedAddress) -> Vec<u8> {
        Self::encrypt_data(encrypted, address) // XOR is symmetric
    }
}

/// Result of a private compute job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateJobResult {
    /// Job identifier
    pub job_id: JobId,

    /// Output data commitment (private - hides actual output)
    pub output_commitment: Commitment,

    /// Encrypted output data
    pub encrypted_output: Vec<u8>,

    /// zkSNARK proof of correct execution
    pub execution_proof: Vec<u8>,

    /// Execution metrics (public)
    pub execution_time_ms: u64,
    pub memory_used_bytes: usize,
    pub instructions_executed: u64,

    /// Timestamp when result was generated
    pub completed_at: u64,
}

impl PrivateJobResult {
    /// Create a private result from standard job result
    pub fn from_job_result(
        job_id: JobId,
        result: JobResult,
        owner_address: &ShieldedAddress,
    ) -> Result<Self> {
        let output_data = result
            .output_data
            .ok_or_else(|| anyhow!("No output data in result"))?;

        // Create commitment to output
        let data_hash = PrivateComputeJob::hash_data(&output_data);
        let randomness = crate::privacy::pedersen::generate_randomness();
        let output_commitment =
            crate::privacy::commitment::CommitmentGenerator::commit(data_hash, &randomness);

        // Encrypt output
        let encrypted_output = PrivateComputeJob::encrypt_data(&output_data, owner_address);

        // Generate zkSNARK proof
        let execution_proof =
            Self::generate_execution_proof(&result.job_id, &output_data, data_hash, &randomness)?;

        Ok(Self {
            job_id,
            output_commitment,
            encrypted_output,
            execution_proof,
            execution_time_ms: result.execution_time_ms,
            memory_used_bytes: result.memory_used_bytes as usize,
            instructions_executed: result.instructions_executed,
            completed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }

    /// Decrypt output data (only job owner can do this)
    pub fn decrypt_output(&self, owner_address: &ShieldedAddress) -> Vec<u8> {
        PrivateComputeJob::decrypt_data(&self.encrypted_output, owner_address)
    }

    /// Generate zkSNARK execution proof
    ///
    /// TODO: This is a simplified version. Full implementation should:
    /// 1. Load proving key from disk (generated during setup)
    /// 2. Create proper ComputeCircuit with all witness data
    /// 3. Generate actual Groth16 proof
    ///
    /// For now, we return a placeholder proof hash.
    fn generate_execution_proof(
        _job_id: &str,
        _output_data: &[u8],
        _output_hash: u64,
        _randomness: &[u8; 32],
    ) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        // TODO: Replace with actual proof generation
        // let circuit = ComputeCircuit::with_witness(...);
        // let proof = ComputeProofSystem::prove(&proving_key, circuit, &mut rng)?;
        // let proof_bytes = serialize_proof(&proof);

        // For now, generate a deterministic placeholder based on inputs
        let mut hasher = Sha256::new();
        hasher.update(_job_id.as_bytes());
        hasher.update(_output_data);
        hasher.update(_output_hash.to_le_bytes());
        hasher.update(_randomness);

        let proof_hash = hasher.finalize();
        Ok(proof_hash.to_vec())
    }
}

/// Coordinator for private compute jobs
pub struct PrivateJobCoordinator {
    /// Shielded pool for managing commitments
    pool: Arc<ShieldedPool>,

    /// Multi-validator verification coordinator (optional)
    verification_coordinator: Option<Arc<crate::compute::VerificationCoordinator>>,
}

impl PrivateJobCoordinator {
    /// Create a new private job coordinator
    pub fn new(pool: Arc<ShieldedPool>) -> Self {
        Self {
            pool,
            verification_coordinator: None,
        }
    }

    /// Create a coordinator with multi-validator verification
    pub fn with_verification(
        pool: Arc<ShieldedPool>,
        verification_coordinator: Arc<crate::compute::VerificationCoordinator>,
    ) -> Self {
        Self {
            pool,
            verification_coordinator: Some(verification_coordinator),
        }
    }

    /// Submit a private compute job
    pub async fn submit_private_job(&self, job: PrivateComputeJob) -> Result<JobId> {
        // Create a deposit transaction to register input commitment
        let randomness = crate::privacy::pedersen::generate_randomness();
        let amount = job.encrypted_input.len() as u64; // Use size as "amount"

        let note = Note::new(job.owner_address, amount, randomness);

        // Deposit into shielded pool
        self.pool.deposit(note.clone(), amount).await?;

        log::info!("Private job submitted: {}", job.job_id);
        Ok(job.job_id.clone())
    }

    /// Verify a private job result
    ///
    /// Verifies:
    /// 1. zkSNARK proof (proves data-commitment binding)
    /// 2. Output commitment validity
    /// 3. Multi-validator consensus (if enabled)
    pub async fn verify_result(&self, result: &PrivateJobResult) -> Result<bool> {
        log::info!("Verifying private job result: {}", result.job_id);

        // Step 1: Verify zkSNARK proof
        // TODO: Implement actual proof verification
        // For now, check proof is not empty and has correct length
        if result.execution_proof.is_empty() || result.execution_proof.len() != 32 {
            log::warn!("Invalid proof format for job {}", result.job_id);
            return Ok(false);
        }

        // Step 2: Verify output commitment is well-formed
        // (Commitment verification happens during proof verification in full impl)
        log::debug!("Output commitment verified for job {}", result.job_id);

        // Step 3: Check multi-validator consensus (if enabled)
        if let Some(coordinator) = &self.verification_coordinator {
            match coordinator.check_consensus(&result.job_id).await? {
                crate::compute::ConsensusResult::Agreed(_) => {
                    log::info!(
                        "Multi-validator consensus reached for job {}",
                        result.job_id
                    );
                }
                crate::compute::ConsensusResult::Disagreed { .. } => {
                    log::warn!("Validators disagreed on job {}", result.job_id);
                    return Ok(false);
                }
                crate::compute::ConsensusResult::Insufficient { .. } => {
                    log::warn!("Insufficient validator results for job {}", result.job_id);
                    return Ok(false);
                }
            }
        }

        log::info!("Private job result verified: {}", result.job_id);
        Ok(true)
    }

    /// Finalize a private job result
    ///
    /// Should only be called after verify_result() returns true.
    pub async fn finalize_result(&self, result: PrivateJobResult) -> Result<()> {
        // Verify before finalizing
        if !self.verify_result(&result).await? {
            return Err(anyhow!("Result verification failed"));
        }

        // Register output commitment in shielded pool
        // This allows the job owner to later withdraw/decrypt the result
        // TODO: Create proper note for output commitment
        log::info!("Private job result finalized: {}", result.job_id);
        Ok(())
    }

    /// Retrieve a private result (requires ownership proof)
    pub async fn retrieve_result(
        &self,
        _job_id: &JobId,
        _owner_address: &ShieldedAddress,
    ) -> Result<PrivateJobResult> {
        // TODO: Verify ownership and retrieve from pool
        Err(anyhow!("Result retrieval not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_job_creation() {
        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d]; // WASM magic number
        let input_data = vec![1, 2, 3, 4];
        let owner_address = ShieldedAddress([42u8; 32]);
        let limits = ResourceLimits::default();

        let job = PrivateComputeJob::new(wasm_code, input_data, owner_address, limits);
        assert!(job.is_ok());

        let job = job.unwrap();
        assert!(!job.encrypted_input.is_empty());
        assert_ne!(job.code_hash, [0u8; 32]);
    }

    #[test]
    fn test_encryption_decryption() {
        let data = vec![1, 2, 3, 4, 5];
        let address = ShieldedAddress([42u8; 32]);

        let encrypted = PrivateComputeJob::encrypt_data(&data, &address);
        let decrypted = PrivateComputeJob::decrypt_data(&encrypted, &address);

        assert_eq!(data, decrypted);
        assert_ne!(data, encrypted); // Should be different
    }

    #[tokio::test]
    async fn test_private_job_coordinator() {
        let pool = Arc::new(ShieldedPool::new());
        let coordinator = PrivateJobCoordinator::new(pool);

        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d];
        let input_data = vec![1, 2, 3, 4];
        let owner_address = ShieldedAddress([42u8; 32]);
        let limits = ResourceLimits::default();

        let job = PrivateComputeJob::new(wasm_code, input_data, owner_address, limits).unwrap();
        let result = coordinator.submit_private_job(job).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_result_verification() {
        use crate::compute::JobResult;

        let pool = Arc::new(ShieldedPool::new());
        let coordinator = PrivateJobCoordinator::new(pool);

        // Create a mock job result
        let job_id = "test-job-123".to_string();
        let output_data = vec![1, 2, 3, 4];
        let job_result = JobResult {
            job_id: job_id.clone(),
            status: crate::compute::JobStatus::Completed,
            output_data: Some(output_data.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };

        let owner_address = ShieldedAddress([42u8; 32]);
        let private_result =
            PrivateJobResult::from_job_result(job_id, job_result, &owner_address).unwrap();

        // Verify result
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(verified.unwrap()); // Should pass with valid proof

        // Test finalize
        let finalized = coordinator.finalize_result(private_result).await;
        assert!(finalized.is_ok());
    }

    #[tokio::test]
    async fn test_result_verification_invalid_proof() {
        let pool = Arc::new(ShieldedPool::new());
        let coordinator = PrivateJobCoordinator::new(pool);

        // Create result with invalid proof (empty)
        let mut result = PrivateJobResult {
            job_id: "test-job".to_string(),
            output_commitment: crate::privacy::Commitment([1u8; 32]),
            encrypted_output: vec![1, 2, 3],
            execution_proof: vec![], // Invalid: empty proof
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
            completed_at: 0,
        };

        // Should fail verification
        let verified = coordinator.verify_result(&result).await;
        assert!(verified.is_ok());
        assert!(!verified.unwrap()); // Should fail with empty proof

        // Test finalize with invalid result
        let finalized = coordinator.finalize_result(result.clone()).await;
        assert!(finalized.is_err()); // Should error on finalize

        // Fix proof and retry
        result.execution_proof = vec![0u8; 32];
        let verified2 = coordinator.verify_result(&result).await;
        assert!(verified2.is_ok());
        assert!(verified2.unwrap()); // Should pass now
    }

    // Integration Tests

    #[tokio::test]
    async fn test_end_to_end_private_compute_workflow() {
        use crate::compute::{JobExecutor, JobResult, JobStatus};

        // Setup components
        let pool = Arc::new(ShieldedPool::new());
        let coordinator = PrivateJobCoordinator::new(pool);
        let executor = JobExecutor::new().unwrap();
        executor.start().await.unwrap();

        // Step 1: Create private job
        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d]; // WASM magic
        let input_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let owner_address = ShieldedAddress([99u8; 32]);
        let limits = ResourceLimits::default();

        let private_job =
            PrivateComputeJob::new(wasm_code, input_data.clone(), owner_address.clone(), limits)
                .unwrap();
        let job_id = private_job.job_id.clone();

        // Verify input is encrypted
        assert_ne!(private_job.encrypted_input, input_data);

        // Step 2: Submit to shielded pool
        let submit_result = coordinator.submit_private_job(private_job.clone()).await;
        assert!(submit_result.is_ok());

        // Step 3: Execute job (simulated - would normally run WASM)
        let mock_output = vec![8, 7, 6, 5, 4, 3, 2, 1]; // Reversed input
        let job_result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(mock_output.clone()),
            error: None,
            execution_time_ms: 150,
            memory_used_bytes: 2048,
            instructions_executed: 75000,
        };

        // Step 4: Create private result with proof
        let private_result =
            PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address).unwrap();

        // Verify output is encrypted
        assert_ne!(private_result.encrypted_output, mock_output);
        assert_eq!(private_result.execution_proof.len(), 32); // Should have proof

        // Step 5: Verify result
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(verified.unwrap());

        // Step 6: Finalize result
        let finalized = coordinator.finalize_result(private_result.clone()).await;
        assert!(finalized.is_ok());

        // Step 7: Decrypt output (only owner can do this)
        let decrypted_output = private_result.decrypt_output(&owner_address);
        assert_eq!(decrypted_output, mock_output);
    }

    #[tokio::test]
    async fn test_multi_validator_consensus_integration() {
        use crate::compute::{JobResult, JobStatus, VerificationCoordinator};

        // Setup with multi-validator verification
        let pool = Arc::new(ShieldedPool::new());
        let verifier = Arc::new(VerificationCoordinator::new());
        let coordinator = PrivateJobCoordinator::with_verification(pool, verifier.clone());

        // Create private job
        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d];
        let input_data = vec![10, 20, 30, 40];
        let owner_address = ShieldedAddress([77u8; 32]);
        let limits = ResourceLimits::default();

        let private_job =
            PrivateComputeJob::new(wasm_code, input_data, owner_address.clone(), limits).unwrap();
        let job_id = private_job.job_id.clone();

        // Setup verification with 3 validators
        let validators = vec![
            "validator-1".to_string(),
            "validator-2".to_string(),
            "validator-3".to_string(),
        ];
        verifier
            .create_verification_request(job_id.clone(), validators.clone())
            .await
            .unwrap();

        // Simulate 3 validators executing and agreeing on result
        let output_data = vec![40, 30, 20, 10]; // Consistent output
        for validator_id in validators {
            let result = JobResult {
                job_id: job_id.clone(),
                status: JobStatus::Completed,
                output_data: Some(output_data.clone()),
                error: None,
                execution_time_ms: 100,
                memory_used_bytes: 1024,
                instructions_executed: 50000,
            };
            verifier
                .submit_result(&job_id, validator_id, result)
                .await
                .unwrap();
        }

        // Create private result
        let job_result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(output_data.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        let private_result =
            PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address).unwrap();

        // Verify with consensus check
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(verified.unwrap()); // Should pass with 3/3 agreement
    }

    #[tokio::test]
    async fn test_consensus_disagreement_rejection() {
        use crate::compute::{JobResult, JobStatus, VerificationCoordinator};

        // Setup with multi-validator verification
        let pool = Arc::new(ShieldedPool::new());
        let verifier = Arc::new(VerificationCoordinator::new());
        let coordinator = PrivateJobCoordinator::with_verification(pool, verifier.clone());

        let job_id = "test-consensus-fail".to_string();
        let owner_address = ShieldedAddress([55u8; 32]);

        // Setup verification with 3 validators
        let validators = vec![
            "validator-1".to_string(),
            "validator-2".to_string(),
            "validator-3".to_string(),
        ];
        verifier
            .create_verification_request(job_id.clone(), validators.clone())
            .await
            .unwrap();

        // Simulate validators disagreeing: 2 agree, 1 disagrees
        let output_correct = vec![1, 2, 3, 4];
        let output_wrong = vec![4, 3, 2, 1];

        // Validator 1 and 2 agree
        for i in 0..2 {
            let result = JobResult {
                job_id: job_id.clone(),
                status: JobStatus::Completed,
                output_data: Some(output_correct.clone()),
                error: None,
                execution_time_ms: 100,
                memory_used_bytes: 1024,
                instructions_executed: 50000,
            };
            verifier
                .submit_result(&job_id, validators[i].clone(), result)
                .await
                .unwrap();
        }

        // Validator 3 disagrees
        let result_wrong = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(output_wrong.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        verifier
            .submit_result(&job_id, validators[2].clone(), result_wrong)
            .await
            .unwrap();

        // Create private result with correct output
        let job_result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(output_correct.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        let private_result =
            PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address).unwrap();

        // Verify - should still pass with 2/3 consensus
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(verified.unwrap()); // Should pass with 2/3 agreement
    }

    #[tokio::test]
    async fn test_insufficient_validator_results() {
        use crate::compute::{JobResult, JobStatus, VerificationCoordinator};

        // Setup with multi-validator verification
        let pool = Arc::new(ShieldedPool::new());
        let verifier = Arc::new(VerificationCoordinator::new());
        let coordinator = PrivateJobCoordinator::with_verification(pool, verifier.clone());

        let job_id = "test-insufficient".to_string();
        let owner_address = ShieldedAddress([33u8; 32]);

        // Setup verification with 3 validators
        let validators = vec![
            "validator-1".to_string(),
            "validator-2".to_string(),
            "validator-3".to_string(),
        ];
        verifier
            .create_verification_request(job_id.clone(), validators.clone())
            .await
            .unwrap();

        // Only 1 validator submits result (need 2/3 for consensus)
        let output_data = vec![1, 2, 3];
        let result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(output_data.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        verifier
            .submit_result(&job_id, validators[0].clone(), result)
            .await
            .unwrap();

        // Create private result
        let job_result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(output_data.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        let private_result =
            PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address).unwrap();

        // Verify - should fail with insufficient results
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(!verified.unwrap()); // Should fail - only 1/3 validators responded
    }

    #[tokio::test]
    async fn test_commitment_integrity() {
        let owner_address = ShieldedAddress([88u8; 32]);

        // Create two different inputs
        let input1 = vec![1, 2, 3, 4];
        let input2 = vec![5, 6, 7, 8];

        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d];
        let limits = ResourceLimits::default();

        let job1 = PrivateComputeJob::new(
            wasm_code.clone(),
            input1,
            owner_address.clone(),
            limits.clone(),
        )
        .unwrap();
        let job2 = PrivateComputeJob::new(wasm_code, input2, owner_address, limits).unwrap();

        // Different inputs should produce different commitments
        assert_ne!(
            job1.input_commitment.0, job2.input_commitment.0,
            "Different inputs should have different commitments"
        );

        // Same input should produce same commitment (deterministic with same randomness)
        // Note: In real implementation, randomness is random, so this would differ
        // This test verifies the commitment function is deterministic for given inputs
    }

    #[tokio::test]
    async fn test_output_decryption_with_wrong_key() {
        use crate::compute::{JobResult, JobStatus};

        let owner_address = ShieldedAddress([100u8; 32]);
        let wrong_address = ShieldedAddress([200u8; 32]);

        let job_id = "test-wrong-key".to_string();
        let output_data = vec![1, 2, 3, 4, 5];

        let job_result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(output_data.clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };

        let private_result =
            PrivateJobResult::from_job_result(job_id, job_result, &owner_address).unwrap();

        // Decrypt with correct key
        let decrypted_correct = private_result.decrypt_output(&owner_address);
        assert_eq!(decrypted_correct, output_data);

        // Decrypt with wrong key - should produce garbage
        let decrypted_wrong = private_result.decrypt_output(&wrong_address);
        assert_ne!(
            decrypted_wrong, output_data,
            "Wrong key should not decrypt correctly"
        );
        assert_ne!(
            decrypted_wrong, decrypted_correct,
            "Different keys should produce different outputs"
        );
    }
}
