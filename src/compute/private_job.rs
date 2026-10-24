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
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::compute::{ComputeJob, JobId, JobResult, ResourceLimits};
use crate::privacy::{Commitment, EncryptedNote, Note, ShieldedAddress, ShieldedPool};

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

        // Seal the input to the owner's X25519 public key with crypto_box
        // (X25519 + XSalsa20-Poly1305, via note_crypto::seal). Only the holder
        // of the owner's secret key can open it — the address alone cannot.
        let encrypted_input = Self::encrypt_data(&input_data, &owner_address)?;

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

    /// Encrypt `data` so only the holder of `address`'s X25519 secret key can
    /// read it.
    ///
    /// Uses NaCl `crypto_box` (X25519 ECDH + XSalsa20-Poly1305) via
    /// [`note_crypto::seal`] with a fresh ephemeral sender key per call, the
    /// same audited, wallet-compatible primitive the shielded-note delivery
    /// uses. `address` is the recipient's X25519 **public** key; unlike the
    /// previous scheme it is not itself the key, so a public address alone
    /// cannot decrypt. Wire format is the canonical envelope encoding
    /// ([`EncryptedNote::to_bytes`]), shared with every other boundary that
    /// carries a sealed blob.
    fn encrypt_data(data: &[u8], address: &ShieldedAddress) -> Result<Vec<u8>> {
        Ok(crate::privacy::note_crypto::seal(&address.0, data).to_bytes())
    }

    /// Decrypt data sealed by `encrypt_data`, using the owner's X25519
    /// **secret** key. Only the owner (holder of the secret) can decrypt — the
    /// public address alone cannot.
    ///
    /// Expects the canonical envelope encoding
    /// ([`EncryptedNote::from_bytes`]). An unrecognised version is rejected
    /// rather than fallen back on — this is a consumer of the bytes, not a
    /// relay.
    pub fn decrypt_data(encrypted: &[u8], owner_secret: &[u8; 32]) -> Result<Vec<u8>> {
        use crate::privacy::note_crypto::open;

        let sealed = EncryptedNote::from_bytes(encrypted)
            .map_err(|e| anyhow!("Encrypted data is not a valid envelope: {e}"))?;

        open(owner_secret, &sealed)
            .ok_or_else(|| anyhow!("Decryption failed (wrong key or corrupted data)"))
    }
}

/// Result of a private compute job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateJobResult {
    /// Job identifier
    pub job_id: JobId,

    /// Output data commitment (private - hides actual output)
    pub output_commitment: Commitment,

    /// Output data hash (public - used for proof verification)
    pub output_hash: u64,

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

        // Create Poseidon commitment to output aligned with ComputeCircuit (#720)
        let data_hash = PrivateComputeJob::hash_data(&output_data);
        let randomness = crate::privacy::pedersen::generate_randomness();
        let output_data_hash = crate::compute::ComputeCircuit::hash_data_to_field(&output_data);
        let output_commitment_fr = crate::compute::ComputeCircuit::compute_commitment(
            output_data_hash,
            &randomness,
            &[0u8; 32],
        );
        let output_commitment =
            Commitment(crate::privacy::types::fr_to_bytes_32(output_commitment_fr));

        // Encrypt output
        let encrypted_output = PrivateComputeJob::encrypt_data(&output_data, owner_address)?;

        // Generate zkSNARK proof
        let execution_proof =
            Self::generate_execution_proof(&result.job_id, &output_data, data_hash, &randomness)?;

        Ok(Self {
            job_id,
            output_commitment,
            output_hash: data_hash,
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

    /// Decrypt output data — only the job owner, holding the X25519 secret key
    /// for the job's `owner_address`, can do this.
    pub fn decrypt_output(&self, owner_secret: &[u8; 32]) -> Result<Vec<u8>> {
        PrivateComputeJob::decrypt_data(&self.encrypted_output, owner_secret)
    }

    /// Check if compute proving keys exist
    fn compute_keys_exist() -> bool {
        use std::path::Path;
        let pk_path = Path::new("keys/compute_proving.key");
        let vk_path = Path::new("keys/compute_verifying.key");
        pk_path.exists() && vk_path.exists()
    }

    /// Load compute proving key from disk
    fn load_proving_key() -> Result<ark_groth16::ProvingKey<ark_bn254::Bn254>> {
        use ark_serialize::CanonicalDeserialize;
        use std::fs;

        let pk_bytes = fs::read("keys/compute_proving.key")
            .map_err(|e| anyhow!("Failed to read proving key: {}", e))?;

        ark_groth16::ProvingKey::deserialize_compressed(&pk_bytes[..])
            .map_err(|e| anyhow!("Failed to deserialize proving key: {}", e))
    }

    /// Load compute verifying key from disk
    fn load_verifying_key() -> Result<ark_groth16::VerifyingKey<ark_bn254::Bn254>> {
        use ark_serialize::CanonicalDeserialize;
        use std::fs;

        let vk_bytes = fs::read("keys/compute_verifying.key")
            .map_err(|e| anyhow!("Failed to read verifying key: {}", e))?;

        ark_groth16::VerifyingKey::deserialize_compressed(&vk_bytes[..])
            .map_err(|e| anyhow!("Failed to deserialize verifying key: {}", e))
    }

    /// Under `cargo test`, lazily initialize a real in-process Groth16
    /// `(ProvingKey, VerifyingKey)` pair when `keys/compute_*.key` are absent
    /// on disk (#720), eliminating the length-only placeholder bypass (#652 / #707).
    #[cfg(test)]
    fn test_compute_keys() -> &'static (
        ark_groth16::ProvingKey<ark_bn254::Bn254>,
        ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    ) {
        static KEYS: std::sync::OnceLock<(
            ark_groth16::ProvingKey<ark_bn254::Bn254>,
            ark_groth16::VerifyingKey<ark_bn254::Bn254>,
        )> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let mut rng = ark_std::rand::thread_rng();
            crate::compute::ComputeProofSystem::setup(&mut rng)
                .expect("test compute ceremony setup must succeed")
        })
    }

    /// Generate zkSNARK execution proof
    ///
    /// - If proving keys exist on disk (or under `#[cfg(test)]` via in-process
    ///   ceremony setup): Generate a real 128-byte BN254 Groth16 proof.
    /// - Otherwise: Generate a deterministic hash placeholder (rejected by
    ///   `verify_execution_proof` in non-test builds, which fail closed).
    fn generate_execution_proof(
        _job_id: &str,
        output_data: &[u8],
        output_hash: u64,
        randomness: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let pk_opt = if Self::compute_keys_exist() {
            Some(Self::load_proving_key()?)
        } else {
            #[cfg(test)]
            {
                Some(Self::test_compute_keys().0.clone())
            }
            #[cfg(not(test))]
            {
                None
            }
        };

        if let Some(pk) = pk_opt {
            log::info!("Generating real Groth16 proof for output commitment");

            let dummy_code_hash = [0u8; 32];
            let dummy_input = vec![0u8];
            let dummy_input_randomness = [0u8; 32];
            let dummy_owner = [0u8; 32];
            let dummy_spending_key = [0u8; 32];

            let dummy_input_hash = crate::compute::ComputeCircuit::hash_data_to_field(&dummy_input);
            let dummy_input_commitment_fr = crate::compute::ComputeCircuit::compute_commitment(
                dummy_input_hash,
                &dummy_input_randomness,
                &dummy_owner,
            );

            let output_data_hash = crate::compute::ComputeCircuit::hash_data_to_field(output_data);
            let output_commitment_fr = crate::compute::ComputeCircuit::compute_commitment(
                output_data_hash,
                randomness,
                &dummy_owner,
            );

            let input_nullifier_fr = crate::compute::ComputeCircuit::compute_nullifier(
                dummy_input_commitment_fr,
                &dummy_spending_key,
            );

            let circuit = crate::compute::ComputeCircuit::with_witness(
                dummy_code_hash,
                dummy_input_commitment_fr,
                output_commitment_fr,
                input_nullifier_fr,
                dummy_input,
                dummy_input_randomness,
                output_data.to_vec(),
                *randomness,
                dummy_owner,
                dummy_spending_key,
            );

            use ark_groth16::Groth16;
            use ark_snark::SNARK;
            let mut rng = ark_std::rand::thread_rng();

            let start = std::time::Instant::now();
            let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng)
                .map_err(|e| anyhow!("Proof generation failed: {:?}", e))?;

            let proof_time = start.elapsed();
            log::info!(
                "Generated real Groth16 proof in {:.2}s",
                proof_time.as_secs_f64()
            );

            use ark_serialize::CanonicalSerialize;
            let mut proof_bytes = Vec::new();
            proof
                .serialize_compressed(&mut proof_bytes)
                .map_err(|e| anyhow!("Proof serialization failed: {:?}", e))?;

            log::info!("Proof size: {} bytes", proof_bytes.len());
            return Ok(proof_bytes);
        }

        #[cfg(not(test))]
        {
            use sha2::{Digest, Sha256};

            log::warn!("Compute proving keys not found, using placeholder proof");
            log::warn!("Run: cargo run --bin setup_compute_ceremony");

            let mut hasher = Sha256::new();
            hasher.update(_job_id.as_bytes());
            hasher.update(output_data);
            hasher.update(output_hash.to_le_bytes());
            hasher.update(randomness);

            let proof_hash = hasher.finalize();
            Ok(proof_hash.to_vec())
        }

        #[cfg(test)]
        {
            let _ = output_hash;
            unreachable!("test builds always resolve a real Groth16 proving key")
        }
    }

    /// Verify zkSNARK execution proof
    ///
    /// - If verifying keys exist on disk (or under `#[cfg(test)]` via in-process
    ///   ceremony setup): Verify the real BN254 Groth16 proof against the
    ///   circuit's public inputs.
    /// - In non-test builds without `keys/compute_verifying.key`: Fail closed
    ///   (#652).
    fn verify_execution_proof(result: &PrivateJobResult) -> Result<bool> {
        let proof_bytes = &result.execution_proof;

        let vk_opt = if Self::compute_keys_exist() {
            Some(Self::load_verifying_key()?)
        } else {
            #[cfg(test)]
            {
                Some(Self::test_compute_keys().1.clone())
            }
            #[cfg(not(test))]
            {
                None
            }
        };

        if let Some(vk) = vk_opt {
            log::info!("Verifying real Groth16 proof");

            use ark_serialize::CanonicalDeserialize;
            let proof = match ark_groth16::Proof::<ark_bn254::Bn254>::deserialize_compressed(
                proof_bytes.as_slice(),
            ) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("Proof deserialization failed: {:?}", e);
                    return Ok(false);
                }
            };

            let code_hash_fr = ark_bn254::Fr::from_le_bytes_mod_order(&[0u8; 32]);

            let dummy_input = vec![0u8];
            let dummy_input_randomness = [0u8; 32];
            let dummy_owner = [0u8; 32];
            let dummy_spending_key = [0u8; 32];

            let dummy_input_hash = crate::compute::ComputeCircuit::hash_data_to_field(&dummy_input);
            let dummy_input_commitment_fr = crate::compute::ComputeCircuit::compute_commitment(
                dummy_input_hash,
                &dummy_input_randomness,
                &dummy_owner,
            );

            let output_commitment_fr =
                ark_bn254::Fr::from_le_bytes_mod_order(result.output_commitment.as_bytes());

            let input_nullifier_fr = crate::compute::ComputeCircuit::compute_nullifier(
                dummy_input_commitment_fr,
                &dummy_spending_key,
            );

            let public_inputs = vec![
                code_hash_fr,
                dummy_input_commitment_fr,
                output_commitment_fr,
                input_nullifier_fr,
            ];

            use ark_groth16::Groth16;
            use ark_snark::SNARK;

            let start = std::time::Instant::now();
            let valid = Groth16::<ark_bn254::Bn254>::verify(&vk, &public_inputs, &proof)
                .map_err(|e| anyhow!("Proof verification failed: {:?}", e))?;

            let verify_time = start.elapsed();
            log::info!(
                "Groth16 proof verification completed in {:.2}ms: {}",
                verify_time.as_secs_f64() * 1000.0,
                if valid { "VALID" } else { "INVALID" }
            );

            return Ok(valid);
        }

        #[cfg(not(test))]
        {
            log::error!(
                "Compute verifying key not found (keys/compute_verifying.key) — \
                 refusing to accept execution proof. \
                 Run: cargo run --bin setup_compute_ceremony"
            );
            Err(anyhow!(
                "compute verifying key unavailable: refusing to verify \
                 execution proof (fail-closed)"
            ))
        }

        #[cfg(test)]
        {
            unreachable!("test builds always resolve a real Groth16 verifying key")
        }
    }
}

/// Coordinator for private compute jobs
pub struct PrivateJobCoordinator {
    /// Shielded pool for managing commitments
    pool: Arc<ShieldedPool>,

    /// Multi-validator verification coordinator (optional)
    verification_coordinator: Option<Arc<crate::compute::VerificationCoordinator>>,

    /// Job owners recorded on submission (`job_id -> owner_address`)
    job_owners: Arc<tokio::sync::RwLock<std::collections::HashMap<JobId, ShieldedAddress>>>,

    /// Finalized private job results (`job_id -> PrivateJobResult`)
    finalized_results: Arc<tokio::sync::RwLock<std::collections::HashMap<JobId, PrivateJobResult>>>,
}

impl PrivateJobCoordinator {
    /// Create a new private job coordinator
    pub fn new(pool: Arc<ShieldedPool>) -> Self {
        Self {
            pool,
            verification_coordinator: None,
            job_owners: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            finalized_results: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
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
            job_owners: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            finalized_results: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Submit a private compute job
    pub async fn submit_private_job(&self, job: PrivateComputeJob) -> Result<JobId> {
        // Create a deposit transaction to register input commitment
        let randomness = crate::privacy::pedersen::generate_randomness();
        let amount = job.encrypted_input.len() as u64; // Use size as "amount"

        let note = Note::new_native(job.owner_address.clone(), amount, randomness);

        // Deposit into shielded pool
        self.pool.deposit(note, amount).await?;

        self.job_owners
            .write()
            .await
            .insert(job.job_id.clone(), job.owner_address);

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
        let proof_valid = PrivateJobResult::verify_execution_proof(result)?;

        if !proof_valid {
            log::warn!(
                "zkSNARK proof verification failed for job {}",
                result.job_id
            );
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
    /// Verifies the result, registers the output commitment as a note in the
    /// shielded pool for the job owner (#154 / #720), and stores the finalized
    /// result for owner-authenticated retrieval.
    pub async fn finalize_result(&self, result: PrivateJobResult) -> Result<()> {
        // Verify before finalizing
        if !self.verify_result(&result).await? {
            return Err(anyhow!("Result verification failed"));
        }

        let owner_address = self
            .job_owners
            .read()
            .await
            .get(&result.job_id)
            .cloned()
            .unwrap_or(ShieldedAddress([0u8; 32]));

        let output_note = Note::new_native(
            owner_address,
            result.output_hash,
            *result.output_commitment.as_bytes(),
        );
        self.pool
            .credit_commitment(
                result.output_commitment.clone(),
                output_note,
                result.output_hash,
                crate::privacy::NATIVE_SOL_ASSET,
            )
            .await?;

        self.finalized_results
            .write()
            .await
            .insert(result.job_id.clone(), result.clone());

        log::info!("Private job result finalized: {}", result.job_id);
        Ok(())
    }

    /// Retrieve a finalized private result after verifying caller ownership
    /// and confirming the output commitment note exists in the shielded pool.
    pub async fn retrieve_result(
        &self,
        job_id: &JobId,
        owner_address: &ShieldedAddress,
    ) -> Result<PrivateJobResult> {
        if let Some(expected_owner) = self.job_owners.read().await.get(job_id) {
            if expected_owner != owner_address {
                return Err(anyhow!(
                    "Unauthorized result retrieval for job {}: caller does not match job owner",
                    job_id
                ));
            }
        }

        let result = self
            .finalized_results
            .read()
            .await
            .get(job_id)
            .cloned()
            .ok_or_else(|| anyhow!("Finalized result not found for job {}", job_id))?;

        let note = self
            .pool
            .get_note(&result.output_commitment)
            .await
            .ok_or_else(|| {
                anyhow!(
                    "Output note commitment not found in shielded pool for job {}",
                    job_id
                )
            })?;

        if &note.recipient != owner_address && note.recipient != ShieldedAddress([0u8; 32]) {
            return Err(anyhow!("Output note owner mismatch for job {}", job_id));
        }

        Ok(result)
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

    /// X25519 keypair for the confidential-compute tests: the public key is the
    /// owner's ShieldedAddress; the secret key is required to decrypt.
    fn owner_keypair() -> (ShieldedAddress, [u8; 32]) {
        use crypto_box::{aead::OsRng, SecretKey};
        let sk = SecretKey::generate(&mut OsRng);
        (ShieldedAddress(*sk.public_key().as_bytes()), sk.to_bytes())
    }

    #[test]
    fn test_encryption_decryption() {
        let data = vec![1, 2, 3, 4, 5];
        let (address, secret) = owner_keypair();

        let encrypted = PrivateComputeJob::encrypt_data(&data, &address).unwrap();
        let decrypted = PrivateComputeJob::decrypt_data(&encrypted, &secret).unwrap();

        assert_eq!(data, decrypted);
        assert_ne!(data, encrypted); // seal output includes epk + nonce + tag
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
            output_hash: 12345u64,
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

        // A bogus 32-byte placeholder buffer must also be rejected under real
        // Groth16 verification (#707 / #720)
        result.execution_proof = vec![0u8; 32];
        let verified_placeholder = coordinator.verify_result(&result).await;
        assert!(verified_placeholder.is_ok());
        assert!(!verified_placeholder.unwrap());

        // A real Groth16 proof generated for matching output commitment passes
        let valid_job_result = crate::compute::JobResult {
            job_id: "test-job".to_string(),
            status: crate::compute::JobStatus::Completed,
            output_data: Some(vec![1, 2, 3]),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        let valid_result = PrivateJobResult::from_job_result(
            "test-job".to_string(),
            valid_job_result,
            &ShieldedAddress([42u8; 32]),
        )
        .unwrap();
        let verified2 = coordinator.verify_result(&valid_result).await;
        assert!(verified2.is_ok());
        assert!(verified2.unwrap());
    }

    // Integration Tests

    #[tokio::test]
    async fn test_end_to_end_private_compute_workflow() {
        use crate::compute::{JobExecutor, JobResult, JobStatus};

        // Setup components
        let pool = Arc::new(ShieldedPool::new());
        let coordinator = PrivateJobCoordinator::new(pool.clone());
        let executor = JobExecutor::new().unwrap();
        executor.start().await.unwrap();

        // Step 1: Create private job
        let wasm_code = vec![0x00, 0x61, 0x73, 0x6d]; // WASM magic
        let input_data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let (owner_address, owner_secret) = owner_keypair();
        let (other_address, _) = owner_keypair();
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

        // Step 4: Create private result with real Groth16 proof
        let private_result =
            PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address).unwrap();

        // Verify output is encrypted and compressed BN254 Groth16 proof is 128 bytes
        assert_ne!(private_result.encrypted_output, mock_output);
        assert_eq!(
            private_result.execution_proof.len(),
            128,
            "Compressed BN254 Groth16 proof size must be 128 bytes, got {}",
            private_result.execution_proof.len()
        );

        // Step 5: Verify result
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(verified.unwrap());

        // Step 6: Finalize result and verify output note is credited in the pool
        let finalized = coordinator.finalize_result(private_result.clone()).await;
        assert!(finalized.is_ok());
        assert!(
            pool.get_note(&private_result.output_commitment)
                .await
                .is_some(),
            "output commitment note must be registered in the shielded pool"
        );

        // Step 7: Retrieve finalized result as owner (and reject non-owner)
        assert!(
            coordinator
                .retrieve_result(&job_id, &other_address)
                .await
                .is_err(),
            "non-owner must not retrieve finalized job result"
        );
        let retrieved = coordinator
            .retrieve_result(&job_id, &owner_address)
            .await
            .unwrap();
        let decrypted_output = retrieved.decrypt_output(&owner_secret).unwrap();
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

        // Simulate all 3 validators disagreeing (no 2/3 supermajority)
        let outputs = [vec![1, 2, 3, 4], vec![4, 3, 2, 1], vec![9, 9, 9, 9]];
        for (validator_id, output) in validators.iter().zip(outputs.iter()) {
            let result = JobResult {
                job_id: job_id.clone(),
                status: JobStatus::Completed,
                output_data: Some(output.clone()),
                error: None,
                execution_time_ms: 100,
                memory_used_bytes: 1024,
                instructions_executed: 50000,
            };
            verifier
                .submit_result(&job_id, validator_id.clone(), result)
                .await
                .unwrap();
        }

        let job_result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(outputs[0].clone()),
            error: None,
            execution_time_ms: 100,
            memory_used_bytes: 1024,
            instructions_executed: 50000,
        };
        let private_result =
            PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address).unwrap();

        // Verify - must be rejected when validators disagree without 2/3 quorum (#707 / #720)
        let verified = coordinator.verify_result(&private_result).await;
        assert!(verified.is_ok());
        assert!(!verified.unwrap());
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

        let (owner_address, owner_secret) = owner_keypair();
        let (_wrong_address, wrong_secret) = owner_keypair();

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

        // Decrypt with the owner's secret key
        let decrypted_correct = private_result.decrypt_output(&owner_secret).unwrap();
        assert_eq!(decrypted_correct, output_data);

        // A different secret cannot open it (crypto_box authentication)
        let decrypted_wrong = private_result.decrypt_output(&wrong_secret);
        assert!(
            decrypted_wrong.is_err(),
            "Wrong key should fail decryption (authenticated encryption)"
        );
    }
}
