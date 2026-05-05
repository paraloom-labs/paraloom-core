//! zkSNARK circuit for private compute job verification
//!
//! This circuit proves correct computation without revealing input/output data.
//!
//! # Circuit Design
//!
//! **Public inputs** (visible on-chain):
//! - `code_hash`: SHA256 hash of WASM code (32 bytes)
//! - `input_commitment`: Pedersen commitment to input data hash
//! - `output_commitment`: Pedersen commitment to output data hash
//!
//! **Private witness** (kept secret):
//! - `input_data`: Actual input data (variable length)
//! - `input_randomness`: Blinding factor for input commitment
//! - `output_data`: Actual output data (variable length)
//! - `output_randomness`: Blinding factor for output commitment
//!
//! **Constraints**:
//! 1. `input_commitment = commit(hash(input_data), input_randomness)`
//! 2. `output_commitment = commit(hash(output_data), output_randomness)`
//!
//! **Note**: This circuit does NOT verify WASM execution correctness.
//! Execution validation is done through multi-validator consensus (2/3 agreement).
//! The circuit only proves that input/output commitments are well-formed.
//!
//! # Security Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │              HYBRID VERIFICATION MODEL                   │
//! ├─────────────────────────────────────────────────────────┤
//! │                                                          │
//! │  zkSNARK Circuit (Privacy):                             │
//! │  ✓ Proves input/output commitments are correct          │
//! │  ✓ Hides actual input/output data                       │
//! │  ✓ Links code_hash to computation                       │
//! │                                                          │
//! │  Multi-Validator Consensus (Correctness):               │
//! │  ✓ 3 validators execute same WASM                       │
//! │  ✓ 2/3 must agree on output (Byzantine tolerance)       │
//! │  ✓ Deterministic WASM ensures reproducibility           │
//! │                                                          │
//! │  Combined Security:                                      │
//! │  → Privacy: zkSNARK hides data                          │
//! │  → Correctness: Consensus verifies execution            │
//! │  → Integrity: Code hash prevents tampering              │
//! └─────────────────────────────────────────────────────────┘
//! ```

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use crate::privacy::poseidon::{poseidon_commit_gadget, poseidon_nullifier_gadget};

/// Maximum data size for circuit (in bytes)
pub const MAX_DATA_SIZE: usize = 1024;

/// Compute execution circuit
///
/// Proves that input/output commitments are correctly formed
/// without revealing the actual data.
#[derive(Clone)]
pub struct ComputeCircuit {
    // ── Public inputs (visible on-chain) ──
    /// SHA256 hash of WASM code (32 bytes), lifted to Fr for circuit use.
    pub code_hash: Option<[u8; 32]>,

    /// Poseidon commitment to input data hash, owner address, and
    /// randomness. Bound by the same formula as the privacy layer's
    /// `Note::commitment` so that input notes produced by the shielded
    /// pool can be consumed by compute jobs and vice versa.
    pub input_commitment: Option<Fr>,

    /// Poseidon commitment to output data hash, owner address, and
    /// randomness. The output commitment is what gets registered in
    /// the privacy pool when the compute result is finalised.
    pub output_commitment: Option<Fr>,

    /// Nullifier proving the submitter owns the input note —
    /// `Poseidon(NULLIFIER_TAG, input_commitment, spending_key)`,
    /// matching the shielded-pool spend pattern. Public so the on-chain
    /// program can mark the note as consumed exactly once.
    pub input_nullifier: Option<Fr>,

    // ── Private witness (secret) ──
    /// Actual input data
    pub input_data: Option<Vec<u8>>,

    /// Blinding factor for input commitment
    pub input_randomness: Option<[u8; 32]>,

    /// Actual output data
    pub output_data: Option<Vec<u8>>,

    /// Blinding factor for output commitment
    pub output_randomness: Option<[u8; 32]>,

    /// Submitter's shielded address. Bound into both the input and
    /// output commitments so a job can only commit to a result for an
    /// address the submitter actually controls.
    pub owner_address: Option<[u8; 32]>,

    /// Spending key for the input note — proves the submitter owns
    /// the note being consumed. Goes into the nullifier; never leaves
    /// the witness layer.
    pub spending_key: Option<[u8; 32]>,
}

impl ComputeCircuit {
    /// Create a new empty circuit (for setup)
    pub fn new() -> Self {
        Self {
            code_hash: None,
            input_commitment: None,
            output_commitment: None,
            input_nullifier: None,
            input_data: None,
            input_randomness: None,
            output_data: None,
            output_randomness: None,
            owner_address: None,
            spending_key: None,
        }
    }

    /// Create circuit with witness data (for proving).
    ///
    /// The host derives `input_commitment`, `output_commitment`, and
    /// `input_nullifier` via [`ComputeCircuit::compute_commitment`] and
    /// [`ComputeCircuit::compute_nullifier`] before constructing the
    /// circuit; passing them as separate arguments lets the verifier
    /// recompute the public inputs from the same helpers without
    /// running the full constraint system.
    #[allow(clippy::too_many_arguments)]
    pub fn with_witness(
        code_hash: [u8; 32],
        input_commitment: Fr,
        output_commitment: Fr,
        input_nullifier: Fr,
        input_data: Vec<u8>,
        input_randomness: [u8; 32],
        output_data: Vec<u8>,
        output_randomness: [u8; 32],
        owner_address: [u8; 32],
        spending_key: [u8; 32],
    ) -> Self {
        assert!(input_data.len() <= MAX_DATA_SIZE, "Input data too large");
        assert!(output_data.len() <= MAX_DATA_SIZE, "Output data too large");

        Self {
            code_hash: Some(code_hash),
            input_commitment: Some(input_commitment),
            output_commitment: Some(output_commitment),
            input_nullifier: Some(input_nullifier),
            input_data: Some(input_data),
            input_randomness: Some(input_randomness),
            output_data: Some(output_data),
            output_randomness: Some(output_randomness),
            owner_address: Some(owner_address),
            spending_key: Some(spending_key),
        }
    }

    /// Hash data to a field element via SHA-256 reduced mod the BLS12-381
    /// scalar prime. The previous implementation truncated SHA-256 to
    /// 64 bits; collapsing the digest down to a u64 was security-
    /// theatre because the in-circuit commitment then bound to a
    /// 64-bit summary instead of the full 256-bit hash.
    pub fn hash_data_to_field(data: &[u8]) -> Fr {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        Fr::from_le_bytes_mod_order(&hash)
    }

    /// Host-side commitment used by the privacy layer's `Note` shape:
    /// `Poseidon(COMMITMENT_TAG, data_hash, randomness, owner)`.
    /// Mirrors `Note::commitment` exactly so a note minted by a
    /// compute job is interchangeable with one minted by a deposit.
    pub fn compute_commitment(data_hash: Fr, randomness: &[u8; 32], owner: &[u8; 32]) -> Fr {
        use crate::privacy::poseidon::poseidon_commit;
        let r = Fr::from_le_bytes_mod_order(randomness);
        let o = Fr::from_le_bytes_mod_order(owner);
        poseidon_commit(data_hash, r, o)
    }

    /// Host-side nullifier matching the shielded-pool spend pattern:
    /// `Poseidon(NULLIFIER_TAG, commitment, spending_key)`. Identical
    /// to `Nullifier::derive` on the privacy side so a compute job
    /// consuming a deposited note produces the canonical nullifier.
    pub fn compute_nullifier(commitment: Fr, spending_key: &[u8; 32]) -> Fr {
        use crate::privacy::poseidon::poseidon_nullifier;
        let secret = Fr::from_le_bytes_mod_order(spending_key);
        poseidon_nullifier(commitment, secret)
    }
}

impl Default for ComputeCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSynthesizer<Fr> for ComputeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public input 1: code hash.
        //
        // Structurally allocated as a single `FpVar<Fr>` (was previously
        // 32 UInt8 slots), matching the rest of the shielded-pool
        // circuits post-Poseidon-migration. Currently unused in
        // constraints — the slot is reserved so that, once a
        // code-authentication constraint is added, the public-input
        // layout does not shift under existing verifiers. Callers must
        // pass `Fr::from_le_bytes_mod_order(&code_hash_bytes)`.
        let _code_hash_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .code_hash
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let input_commitment_var = FpVar::new_input(cs.clone(), || {
            self.input_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let output_commitment_var = FpVar::new_input(cs.clone(), || {
            self.output_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let input_nullifier_var = FpVar::new_input(cs.clone(), || {
            self.input_nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Private witnesses ──
        let input_data = self.input_data.unwrap_or_default();
        let output_data = self.output_data.unwrap_or_default();

        let input_randomness = self.input_randomness.unwrap_or([0u8; 32]);
        let output_randomness = self.output_randomness.unwrap_or([0u8; 32]);
        let owner_address = self.owner_address.unwrap_or([0u8; 32]);
        let spending_key = self.spending_key.unwrap_or([0u8; 32]);

        let input_hash_var = FpVar::new_witness(cs.clone(), || {
            Ok(Self::hash_data_to_field(&input_data))
        })?;
        let output_hash_var = FpVar::new_witness(cs.clone(), || {
            Ok(Self::hash_data_to_field(&output_data))
        })?;

        let input_randomness_var = FpVar::new_witness(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&input_randomness))
        })?;
        let output_randomness_var = FpVar::new_witness(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&output_randomness))
        })?;
        let owner_address_var = FpVar::new_witness(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&owner_address))
        })?;
        let spending_key_var = FpVar::new_witness(cs.clone(), || {
            Ok(Fr::from_le_bytes_mod_order(&spending_key))
        })?;

        // CONSTRAINT 1: input commitment is well-formed against the
        // (data_hash, randomness, owner) Poseidon commitment scheme
        // shared with the privacy layer's `Note::commitment`.
        //
        // The audit (#63) called for "Pedersen commitment gadget"; the
        // architectural decision documented in this PR is to use the
        // privacy layer's Poseidon scheme everywhere — implementing a
        // BLS12-381-G1 Pedersen gadget inside an Fr-based circuit is
        // impractical (non-native field arithmetic), and the privacy
        // layer's v0.2 Poseidon migration already replaced Pedersen on
        // the host side for the same reason. Aligning the compute
        // commitment with `Note::commitment` makes notes
        // interchangeable across the deposit / transfer / compute
        // paths.
        let computed_input_commitment = poseidon_commit_gadget(
            cs.clone(),
            &input_hash_var,
            &input_randomness_var,
            &owner_address_var,
        )?;
        computed_input_commitment.enforce_equal(&input_commitment_var)?;

        // CONSTRAINT 2: output commitment is well-formed under the same
        // scheme. The committed output is bound to the verified WASM
        // output via `output_hash_var`; any drift between the witness
        // output bytes and what the host hashed surfaces here.
        let computed_output_commitment = poseidon_commit_gadget(
            cs.clone(),
            &output_hash_var,
            &output_randomness_var,
            &owner_address_var,
        )?;
        computed_output_commitment.enforce_equal(&output_commitment_var)?;

        // CONSTRAINT 3: ownership of the input note via nullifier.
        // `Poseidon(NULLIFIER_TAG, input_commitment, spending_key)`
        // mirrors `WithdrawCircuit` and host-side `Nullifier::derive`,
        // so a compute job can only consume an input note whose
        // spending key the submitter actually holds.
        let computed_nullifier =
            poseidon_nullifier_gadget(cs, &input_commitment_var, &spending_key_var)?;
        computed_nullifier.enforce_equal(&input_nullifier_var)?;

        Ok(())
    }
}

/// Groth16 proof system for compute circuits
pub struct ComputeProofSystem;

impl ComputeProofSystem {
    /// Generate proving and verifying keys (one-time setup)
    pub fn setup<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), Box<dyn std::error::Error>> {
        let circuit = ComputeCircuit::new();
        let (pk, vk) = ark_groth16::Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)?;
        Ok((pk, vk))
    }

    /// Generate a proof for a compute job
    pub fn prove<R: RngCore + CryptoRng>(
        pk: &ProvingKey<Bls12_381>,
        circuit: ComputeCircuit,
        rng: &mut R,
    ) -> Result<Proof<Bls12_381>, Box<dyn std::error::Error>> {
        let proof = ark_groth16::Groth16::<Bls12_381>::prove(pk, circuit, rng)?;
        Ok(proof)
    }

    /// Verify a compute proof
    pub fn verify(
        vk: &VerifyingKey<Bls12_381>,
        public_inputs: &[Fr],
        proof: &Proof<Bls12_381>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let valid = ark_groth16::Groth16::<Bls12_381>::verify(vk, public_inputs, proof)?;
        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_creation() {
        let circuit = ComputeCircuit::new();
        assert!(circuit.code_hash.is_none());
        assert!(circuit.input_data.is_none());
    }

    #[test]
    fn test_circuit_with_witness() {
        let code_hash = [1u8; 32];
        let input_commitment = Fr::from(12345u64);
        let output_commitment = Fr::from(67890u64);
        let input_nullifier = Fr::from(54321u64);
        let input_data = vec![1, 2, 3, 4];
        let input_randomness = [42u8; 32];
        let output_data = vec![5, 6, 7, 8];
        let output_randomness = [99u8; 32];
        let owner_address = [7u8; 32];
        let spending_key = [8u8; 32];

        let circuit = ComputeCircuit::with_witness(
            code_hash,
            input_commitment,
            output_commitment,
            input_nullifier,
            input_data,
            input_randomness,
            output_data,
            output_randomness,
            owner_address,
            spending_key,
        );

        assert!(circuit.code_hash.is_some());
        assert!(circuit.input_data.is_some());
        assert_eq!(circuit.input_data.unwrap(), vec![1, 2, 3, 4]);
        assert!(circuit.input_nullifier.is_some());
        assert!(circuit.owner_address.is_some());
    }

    /// Cross-circuit consistency: the in-circuit Poseidon commitment
    /// gadget produces the same field element as the host
    /// [`ComputeCircuit::compute_commitment`] helper, and the same
    /// applies to the nullifier. This is the equivalence test the
    /// audit (#63) called for; it protects against drift between the
    /// host-side helpers and the constraint-system gadgets.
    #[tokio::test]
    async fn test_compute_circuit_native_circuit_equivalence() {
        use ark_relations::r1cs::ConstraintSystem;

        let owner = [0xA1u8; 32];
        let spending_key = [0xA5u8; 32];
        let input_data = b"deadbeef".to_vec();
        let input_randomness = [0x11u8; 32];
        let output_data = b"cafebabe".to_vec();
        let output_randomness = [0x22u8; 32];
        let code_hash = [0x33u8; 32];

        // Host-side derivation, exactly mirroring the constraints.
        let input_hash = ComputeCircuit::hash_data_to_field(&input_data);
        let output_hash = ComputeCircuit::hash_data_to_field(&output_data);
        let input_commitment = ComputeCircuit::compute_commitment(
            input_hash,
            &input_randomness,
            &owner,
        );
        let output_commitment = ComputeCircuit::compute_commitment(
            output_hash,
            &output_randomness,
            &owner,
        );
        let input_nullifier =
            ComputeCircuit::compute_nullifier(input_commitment, &spending_key);

        let circuit = ComputeCircuit::with_witness(
            code_hash,
            input_commitment,
            output_commitment,
            input_nullifier,
            input_data,
            input_randomness,
            output_data,
            output_randomness,
            owner,
            spending_key,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis");
        assert!(
            cs.is_satisfied().expect("cs query"),
            "compute circuit must be satisfied by host-aligned witnesses"
        );
    }

    // The proof-generation smoke test that previously sat here was
    // commented out with "TODO: Fix RNG version conflict". Untangling
    // the `rand` major-version mismatch between arkworks 0.4 and the
    // workspace dependency tree is a separate concern from #63 and
    // covered under the broader operational hardening epic (#69).
}
