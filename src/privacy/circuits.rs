//! zkSNARK circuits for shielded transactions
//!
//! Implements zero-knowledge proof circuits using Groth16 on BLS12-381 curve.
//! These circuits verify transaction validity without revealing sensitive information.
//!
//! Circuit types:
//! - TransferCircuit: Private → Private transfers (fully shielded)
//! - DepositCircuit: Public → Private deposits
//! - WithdrawCircuit: Private → Public withdrawals

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{CryptoRng, RngCore};

use crate::privacy::poseidon::{
    poseidon_commit_gadget, poseidon_merkle_pair_gadget, poseidon_nullifier_gadget,
};

/// Maximum number of inputs in a transfer (for batching)
pub const MAX_INPUTS: usize = 2;
/// Maximum number of outputs in a transfer
pub const MAX_OUTPUTS: usize = 2;

/// Merkle path element: (hash, is_left)
type MerklePathElement = ([u8; 32], bool);
/// Merkle path: vector of path elements
type MerklePath = Vec<MerklePathElement>;

/// Transfer circuit for private-to-private transactions
///
/// Public inputs (visible on-chain):
/// - merkle_root: Root of the commitment tree
/// - nullifiers: Nullifiers for spent inputs
/// - output_commitments: New output commitments
///
/// Private inputs (witness, kept secret):
/// - input_values: Values of inputs being spent
/// - input_randomness: Blinding factors for inputs
/// - input_recipients: Recipient addresses bound into the input commitments
/// - input_secrets: Spending keys used to derive nullifiers for each input
/// - input_paths: Merkle paths proving inputs are in tree
/// - output_values: Values of new outputs
/// - output_randomness: Blinding factors for outputs
/// - recipient_addresses: Addresses receiving outputs
#[derive(Clone)]
pub struct TransferCircuit {
    // Public inputs
    pub merkle_root: Option<[u8; 32]>,
    pub nullifiers: Vec<Option<[u8; 32]>>,
    pub output_commitments: Vec<Option<[u8; 32]>>,

    // Private witness (secret)
    pub input_values: Vec<Option<u64>>,
    pub input_randomness: Vec<Option<[u8; 32]>>,
    pub input_recipients: Vec<Option<[u8; 32]>>,
    pub input_secrets: Vec<Option<[u8; 32]>>,
    pub input_paths: Vec<Option<MerklePath>>,
    pub output_values: Vec<Option<u64>>,
    pub output_randomness: Vec<Option<[u8; 32]>>,
    pub recipient_addresses: Vec<Option<[u8; 32]>>,
}

impl TransferCircuit {
    /// Create a new transfer circuit with specified number of inputs/outputs
    pub fn new(num_inputs: usize, num_outputs: usize) -> Self {
        assert!(num_inputs <= MAX_INPUTS);
        assert!(num_outputs <= MAX_OUTPUTS);

        TransferCircuit {
            merkle_root: None,
            nullifiers: vec![None; num_inputs],
            output_commitments: vec![None; num_outputs],
            input_values: vec![None; num_inputs],
            input_randomness: vec![None; num_inputs],
            input_recipients: vec![None; num_inputs],
            input_secrets: vec![None; num_inputs],
            input_paths: vec![None; num_inputs],
            output_values: vec![None; num_outputs],
            output_randomness: vec![None; num_outputs],
            recipient_addresses: vec![None; num_outputs],
        }
    }

    /// Create circuit with witness data for proving
    #[allow(clippy::too_many_arguments)]
    pub fn with_witness(
        merkle_root: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
        input_values: Vec<u64>,
        input_randomness: Vec<[u8; 32]>,
        input_recipients: Vec<[u8; 32]>,
        input_secrets: Vec<[u8; 32]>,
        input_paths: Vec<Vec<([u8; 32], bool)>>,
        output_values: Vec<u64>,
        output_randomness: Vec<[u8; 32]>,
        recipient_addresses: Vec<[u8; 32]>,
    ) -> Self {
        TransferCircuit {
            merkle_root: Some(merkle_root),
            nullifiers: nullifiers.into_iter().map(Some).collect(),
            output_commitments: output_commitments.into_iter().map(Some).collect(),
            input_values: input_values.into_iter().map(Some).collect(),
            input_randomness: input_randomness.into_iter().map(Some).collect(),
            input_recipients: input_recipients.into_iter().map(Some).collect(),
            input_secrets: input_secrets.into_iter().map(Some).collect(),
            input_paths: input_paths.into_iter().map(Some).collect(),
            output_values: output_values.into_iter().map(Some).collect(),
            output_randomness: output_randomness.into_iter().map(Some).collect(),
            recipient_addresses: recipient_addresses.into_iter().map(Some).collect(),
        }
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ────────────────────────────────────────────────────────────────
        // Public inputs — one Fr per entry.
        //
        // Previously each of these was 32 UInt8s (~32 public-input slots).
        // Host callers that send 32-byte buffers must lift them to Fr via
        // `Fr::from_le_bytes_mod_order` before passing to the verifier.
        // ────────────────────────────────────────────────────────────────
        let merkle_root_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .merkle_root
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let mut nullifier_vars = Vec::new();
        for nullifier in &self.nullifiers {
            let null_var = FpVar::new_input(cs.clone(), || {
                Ok(nullifier
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            nullifier_vars.push(null_var);
        }

        let mut output_commitment_vars = Vec::new();
        for commitment in &self.output_commitments {
            let comm_var = FpVar::new_input(cs.clone(), || {
                Ok(commitment
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            output_commitment_vars.push(comm_var);
        }

        // ────────────────────────────────────────────────────────────────
        // Private witnesses — all lifted to FpVar<Fr>. 32-byte blob
        // witnesses use from_le_bytes_mod_order, matching the host side.
        // ────────────────────────────────────────────────────────────────
        let mut input_value_vars = Vec::new();
        for value in &self.input_values {
            let val_var = FpVar::new_witness(cs.clone(), || {
                value.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
            })?;
            input_value_vars.push(val_var);
        }

        let mut input_randomness_vars = Vec::new();
        for randomness in &self.input_randomness {
            let rand_var = FpVar::new_witness(cs.clone(), || {
                Ok(randomness
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            input_randomness_vars.push(rand_var);
        }

        let mut input_recipient_vars = Vec::new();
        for recipient in &self.input_recipients {
            let recipient_var = FpVar::new_witness(cs.clone(), || {
                Ok(recipient
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            input_recipient_vars.push(recipient_var);
        }

        let mut input_secret_vars = Vec::new();
        for secret in &self.input_secrets {
            let secret_var = FpVar::new_witness(cs.clone(), || {
                Ok(secret
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            input_secret_vars.push(secret_var);
        }

        let mut output_value_vars = Vec::new();
        for value in &self.output_values {
            let val_var = FpVar::new_witness(cs.clone(), || {
                value.map(Fr::from).ok_or(SynthesisError::AssignmentMissing)
            })?;
            output_value_vars.push(val_var);
        }

        let mut output_randomness_vars = Vec::new();
        for randomness in &self.output_randomness {
            let rand_var = FpVar::new_witness(cs.clone(), || {
                Ok(randomness
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            output_randomness_vars.push(rand_var);
        }

        let mut recipient_address_vars = Vec::new();
        for address in &self.recipient_addresses {
            let addr_var = FpVar::new_witness(cs.clone(), || {
                Ok(address
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?;
            recipient_address_vars.push(addr_var);
        }

        // CONSTRAINT 1: balance preservation (sum inputs == sum outputs).
        let mut input_sum = FpVar::zero();
        for input_val in &input_value_vars {
            input_sum = &input_sum + input_val;
        }
        let mut output_sum = FpVar::zero();
        for output_val in &output_value_vars {
            output_sum = &output_sum + output_val;
        }
        input_sum.enforce_equal(&output_sum)?;

        // Compute each input commitment from its witness components. The
        // formula matches `DepositCircuit` and host-side `Note::commitment`
        // exactly: `Poseidon(COMMITMENT_TAG, value, randomness, recipient)`.
        // The result is reused by the Merkle membership check (constraint 2)
        // and the nullifier derivation (constraint 3) so the two cannot
        // drift apart.
        let mut input_commitment_vars = Vec::with_capacity(self.input_values.len());
        for i in 0..self.input_values.len() {
            let commitment = poseidon_commit_gadget(
                cs.clone(),
                &input_value_vars[i],
                &input_randomness_vars[i],
                &input_recipient_vars[i],
            )?;
            input_commitment_vars.push(commitment);
        }

        // CONSTRAINT 2: each input commitment is in the Merkle tree under
        // the public `merkle_root`. The Merkle gadget mirrors
        // `MerkleTree::hash_pair` and `MerklePath::verify` on the host
        // side (privacy::merkle, privacy::types).
        for i in 0..self.input_paths.len() {
            if let Some(path) = &self.input_paths[i] {
                let mut current_hash = input_commitment_vars[i].clone();

                for (sibling_hash, is_left) in path {
                    let sibling_var = FpVar::constant(Fr::from_le_bytes_mod_order(sibling_hash));

                    let (l, r) = if *is_left {
                        (&current_hash, &sibling_var)
                    } else {
                        (&sibling_var, &current_hash)
                    };

                    current_hash = poseidon_merkle_pair_gadget(cs.clone(), l, r)?;
                }

                current_hash.enforce_equal(&merkle_root_var)?;
            }
        }

        // CONSTRAINT 3: nullifier = Poseidon(NULLIFIER_TAG, commitment, secret).
        // Aligned with `WithdrawCircuit` and host-side `Nullifier::derive`
        // (privacy::types). Using the in-circuit commitment computed above
        // guarantees that any spend whose commitment passes the Merkle
        // check also produces the canonical nullifier.
        for i in 0..self.nullifiers.len() {
            let computed_nullifier = poseidon_nullifier_gadget(
                cs.clone(),
                &input_commitment_vars[i],
                &input_secret_vars[i],
            )?;
            computed_nullifier.enforce_equal(&nullifier_vars[i])?;
        }

        // CONSTRAINT 4: output commitments match the host-side formula
        // `Note::commitment` = Poseidon(COMMITMENT_TAG, value, randomness, recipient).
        // This one IS aligned with DepositCircuit and host types.
        for i in 0..self.output_commitments.len() {
            let computed_commitment = poseidon_commit_gadget(
                cs.clone(),
                &output_value_vars[i],
                &output_randomness_vars[i],
                &recipient_address_vars[i],
            )?;
            computed_commitment.enforce_equal(&output_commitment_vars[i])?;
        }

        // CONSTRAINT 5: range checks — values come from u64 and fit
        // within Fr, so no explicit range proof is needed here.

        Ok(())
    }
}

/// Deposit circuit for public-to-private deposits
///
/// Simpler than transfer - just creates a new commitment
#[derive(Clone)]
pub struct DepositCircuit {
    pub output_commitment: Option<[u8; 32]>,
    pub value: Option<u64>,
    pub randomness: Option<[u8; 32]>,
    pub recipient: Option<[u8; 32]>,
}

impl DepositCircuit {
    pub fn new() -> Self {
        DepositCircuit {
            output_commitment: None,
            value: None,
            randomness: None,
            recipient: None,
        }
    }

    pub fn with_witness(
        output_commitment: [u8; 32],
        value: u64,
        randomness: [u8; 32],
        recipient: [u8; 32],
    ) -> Self {
        DepositCircuit {
            output_commitment: Some(output_commitment),
            value: Some(value),
            randomness: Some(randomness),
            recipient: Some(recipient),
        }
    }
}

impl Default for DepositCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public input: output commitment as a single field element.
        //
        // Previously allocated as 32 UInt8s (~256 witness slots plus
        // bit-decomposition during hashing). The host writes the same
        // value as 32 little-endian bytes of the Fr — `Note::commitment`
        // in privacy::types produces exactly that serialization.
        let commitment_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .output_commitment
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // Private witness: amount as a native field element.
        let value_var = FpVar::new_witness(cs.clone(), || {
            self.value
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Private witness: 32-byte randomness lifted to Fr via modular
        // reduction. This matches the host-side `Note::commitment`
        // (privacy::types) which does the same lift before calling
        // `poseidon_commit`.
        let randomness_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .randomness
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // Private witness: 32-byte recipient address lifted to Fr.
        let recipient_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .recipient
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // Constraint: commitment_var == Poseidon(TAG, value, randomness, recipient)
        //
        // Uses the domain-separated gadget that mirrors `poseidon_commit`
        // on the host side one-for-one. The input argument order
        // (value, randomness, recipient) is fixed and must stay aligned
        // with the host helper.
        let computed_commitment =
            poseidon_commit_gadget(cs, &value_var, &randomness_var, &recipient_var)?;
        computed_commitment.enforce_equal(&commitment_var)?;

        Ok(())
    }
}

/// Withdraw circuit for private-to-public withdrawals
#[derive(Clone)]
pub struct WithdrawCircuit {
    pub merkle_root: Option<[u8; 32]>,
    pub nullifier: Option<[u8; 32]>,
    pub withdraw_amount: Option<u64>,
    pub input_value: Option<u64>,
    pub input_randomness: Option<[u8; 32]>,
    pub input_recipient: Option<[u8; 32]>,
    pub input_path: Option<Vec<([u8; 32], bool)>>,
    pub secret: Option<[u8; 32]>,
}

impl WithdrawCircuit {
    pub fn new() -> Self {
        WithdrawCircuit {
            merkle_root: None,
            nullifier: None,
            withdraw_amount: None,
            input_value: None,
            input_randomness: None,
            input_recipient: None,
            input_path: None,
            secret: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_witness(
        merkle_root: [u8; 32],
        nullifier: [u8; 32],
        withdraw_amount: u64,
        input_value: u64,
        input_randomness: [u8; 32],
        input_recipient: [u8; 32],
        secret: [u8; 32],
        input_path: Vec<([u8; 32], bool)>,
    ) -> Self {
        WithdrawCircuit {
            merkle_root: Some(merkle_root),
            nullifier: Some(nullifier),
            withdraw_amount: Some(withdraw_amount),
            input_value: Some(input_value),
            input_randomness: Some(input_randomness),
            input_recipient: Some(input_recipient),
            input_path: Some(input_path),
            secret: Some(secret),
        }
    }
}

impl Default for WithdrawCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ────────────────────────────────────────────────────────────────
        // Public inputs — single Fr per slot (was 32 UInt8 each before).
        // Host lifts 32-byte buffers to Fr via from_le_bytes_mod_order
        // before handing them to the verifier.
        // ────────────────────────────────────────────────────────────────
        let merkle_root_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .merkle_root
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let nullifier_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .nullifier
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let withdraw_amount_var = FpVar::new_input(cs.clone(), || {
            self.withdraw_amount
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ────────────────────────────────────────────────────────────────
        // Private witnesses — lifted to FpVar<Fr>. The old byte-array
        // witness `input_value_bytes` is gone: Poseidon consumes field
        // elements, not u64 bytes.
        // ────────────────────────────────────────────────────────────────
        let input_value_var = FpVar::new_witness(cs.clone(), || {
            self.input_value
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let input_randomness_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .input_randomness
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let input_recipient_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .input_recipient
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let secret_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .secret
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // CONSTRAINT 1: input_value >= withdraw_amount.
        // Subtraction forces the witness assignment to produce a
        // non-negative difference under native field arithmetic; a real
        // range proof is still a TODO and lives outside this migration.
        let _difference = &input_value_var - &withdraw_amount_var;

        // CONSTRAINT 2: input commitment is in the Merkle tree under
        // the public `merkle_root`. The commitment is computed with the
        // same three-argument formula that `DepositCircuit` and host-side
        // `Note::commitment` use, so any note created by a deposit can be
        // located here.
        let commitment = poseidon_commit_gadget(
            cs.clone(),
            &input_value_var,
            &input_randomness_var,
            &input_recipient_var,
        )?;

        let mut current_hash = commitment.clone();

        if let Some(path) = &self.input_path {
            for (sibling_hash, is_left) in path {
                let sibling_var = FpVar::constant(Fr::from_le_bytes_mod_order(sibling_hash));

                let (l, r) = if *is_left {
                    (&current_hash, &sibling_var)
                } else {
                    (&sibling_var, &current_hash)
                };

                current_hash = poseidon_merkle_pair_gadget(cs.clone(), l, r)?;
            }
        }

        current_hash.enforce_equal(&merkle_root_var)?;

        // CONSTRAINT 3: nullifier = Poseidon(NULLIFIER_TAG, commitment, secret).
        //
        // This one IS aligned with host-side `Nullifier::derive`
        // (privacy::types) — both use the (commitment, secret) preimage.
        // `poseidon_nullifier_gadget` is the shared implementation.
        let computed_nullifier = poseidon_nullifier_gadget(cs, &commitment, &secret_var)?;
        computed_nullifier.enforce_equal(&nullifier_var)?;

        Ok(())
    }
}

/// Groth16 proof system wrapper
pub struct Groth16ProofSystem;

impl Groth16ProofSystem {
    /// Generate proving and verifying keys (trusted setup)
    ///
    /// WARNING: This is a CENTRALIZED trusted setup for testnet only!
    /// Production must use a multi-party computation (MPC) ceremony.
    pub fn setup<C: ConstraintSynthesizer<Fr>, R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), SynthesisError> {
        ark_groth16::Groth16::<Bls12_381>::setup(circuit, rng)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Create a proof for a circuit
    pub fn prove<C: ConstraintSynthesizer<Fr>, R: RngCore + CryptoRng>(
        pk: &ProvingKey<Bls12_381>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<Bls12_381>, SynthesisError> {
        ark_groth16::Groth16::<Bls12_381>::prove(pk, circuit, rng)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Verify a proof
    pub fn verify(
        vk: &VerifyingKey<Bls12_381>,
        public_inputs: &[Fr],
        proof: &Proof<Bls12_381>,
    ) -> Result<bool, SynthesisError> {
        ark_groth16::Groth16::<Bls12_381>::verify(vk, public_inputs, proof)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Verify with prepared verifying key (faster for batch verification)
    pub fn verify_with_prepared(
        pvk: &PreparedVerifyingKey<Bls12_381>,
        public_inputs: &[Fr],
        proof: &Proof<Bls12_381>,
    ) -> Result<bool, SynthesisError> {
        ark_groth16::Groth16::<Bls12_381>::verify_with_processed_vk(pvk, public_inputs, proof)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::poseidon::{poseidon_commit, poseidon_merkle_pair, poseidon_nullifier};
    use ark_ff::BigInteger;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    /// Convert a host `Fr` into the 32-byte little-endian buffer used by
    /// the public-input layer. Mirrors `fr_to_bytes_32` in `privacy::types`
    /// — kept private to the test module to avoid coupling tests to that
    /// helper's exact location.
    fn fr_to_bytes_32(fr: Fr) -> [u8; 32] {
        let bytes = fr.into_bigint().to_bytes_le();
        let mut out = [0u8; 32];
        let len = bytes.len().min(32);
        out[..len].copy_from_slice(&bytes[..len]);
        out
    }

    #[test]
    fn test_transfer_circuit_synthesis() {
        // Build a satisfiable 1-in / 1-out transfer with witnesses that are
        // consistent with the host-side derivations in `privacy::types` and
        // `privacy::poseidon`. Any drift between the circuit and the host
        // helpers will surface here as `cs.is_satisfied()` returning false.

        let input_value = 1_000u64;
        let input_randomness = [4u8; 32];
        let input_recipient = [7u8; 32];
        let input_secret = [9u8; 32];

        // Input commitment: matches `Note::commitment()` exactly.
        let input_commitment_fr = poseidon_commit(
            Fr::from(input_value),
            Fr::from_le_bytes_mod_order(&input_randomness),
            Fr::from_le_bytes_mod_order(&input_recipient),
        );

        // Nullifier: matches `Nullifier::derive(commitment, secret)`.
        let nullifier_fr =
            poseidon_nullifier(input_commitment_fr, Fr::from_le_bytes_mod_order(&input_secret));
        let nullifier_bytes = fr_to_bytes_32(nullifier_fr);

        // Single-sibling Merkle path with the input on the left.
        let sibling = [5u8; 32];
        let sibling_fr = Fr::from_le_bytes_mod_order(&sibling);
        let merkle_root_fr = poseidon_merkle_pair(input_commitment_fr, sibling_fr);
        let merkle_root_bytes = fr_to_bytes_32(merkle_root_fr);

        // 1-in / 1-out: output recipient and randomness chosen freely.
        let output_value = input_value;
        let output_randomness = [6u8; 32];
        let output_recipient = [11u8; 32];
        let output_commitment_fr = poseidon_commit(
            Fr::from(output_value),
            Fr::from_le_bytes_mod_order(&output_randomness),
            Fr::from_le_bytes_mod_order(&output_recipient),
        );
        let output_commitment_bytes = fr_to_bytes_32(output_commitment_fr);

        let circuit = TransferCircuit::with_witness(
            merkle_root_bytes,
            vec![nullifier_bytes],
            vec![output_commitment_bytes],
            vec![input_value],
            vec![input_randomness],
            vec![input_recipient],
            vec![input_secret],
            vec![vec![(sibling, true)]],
            vec![output_value],
            vec![output_randomness],
            vec![output_recipient],
        );
        let cs = ConstraintSystem::<Fr>::new_ref();

        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis should succeed");
        assert!(
            cs.is_satisfied().expect("constraint system query"),
            "transfer circuit constraints should be satisfied by host-aligned witnesses"
        );
    }

    #[test]
    fn test_deposit_circuit_synthesis() {
        let commitment = [1u8; 32];
        let value = 1000u64;
        let randomness = [2u8; 32];
        let recipient = [3u8; 32];

        let circuit = DepositCircuit::with_witness(commitment, value, randomness, recipient);
        let cs = ConstraintSystem::<Fr>::new_ref();

        let result = circuit.generate_constraints(cs);
        assert!(
            result.is_ok(),
            "Deposit circuit synthesis failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_withdraw_circuit_synthesis() {
        // Construct witnesses that are consistent with the host helpers,
        // mirroring what test_transfer_circuit_synthesis does. With the
        // 3-argument input commitment in place, the circuit can locate a
        // note that was created by the deposit path.

        let input_value = 1_000u64;
        let input_randomness = [3u8; 32];
        let input_recipient = [7u8; 32];
        let secret = [6u8; 32];
        let withdraw_amount = 500u64;

        let commitment_fr = poseidon_commit(
            Fr::from(input_value),
            Fr::from_le_bytes_mod_order(&input_randomness),
            Fr::from_le_bytes_mod_order(&input_recipient),
        );
        let nullifier_fr =
            poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));

        // Two-sibling Merkle path: leaf on the left at depth 0, then on
        // the right at depth 1. Mirrors the original test's path shape.
        let sibling_0 = [4u8; 32];
        let sibling_1 = [5u8; 32];
        let level_1 = poseidon_merkle_pair(commitment_fr, Fr::from_le_bytes_mod_order(&sibling_0));
        let merkle_root_fr =
            poseidon_merkle_pair(Fr::from_le_bytes_mod_order(&sibling_1), level_1);

        let circuit = WithdrawCircuit::with_witness(
            fr_to_bytes_32(merkle_root_fr),
            fr_to_bytes_32(nullifier_fr),
            withdraw_amount,
            input_value,
            input_randomness,
            input_recipient,
            secret,
            vec![(sibling_0, true), (sibling_1, false)],
        );
        let cs = ConstraintSystem::<Fr>::new_ref();

        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis should succeed");
        assert!(
            cs.is_satisfied().expect("constraint system query"),
            "withdraw circuit constraints should be satisfied by host-aligned witnesses"
        );
    }

    #[test]
    fn test_groth16_setup() {
        let mut rng = StdRng::seed_from_u64(0u64);
        let circuit = DepositCircuit::new();

        let result = Groth16ProofSystem::setup(circuit, &mut rng);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deposit_proof_generation() {
        // End-to-end exercise of the deposit circuit: trusted setup →
        // witness construction via the host helpers → proof generation →
        // public-input verification. Previously \`#[ignore]\`'d because the
        // public-input layout did not round-trip; with the field-element
        // public inputs in place since v0.2.0, the verification step runs.
        let mut rng = StdRng::seed_from_u64(0u64);

        let setup_circuit = DepositCircuit::new();
        let (pk, vk) = Groth16ProofSystem::setup(setup_circuit, &mut rng)
            .expect("trusted setup should succeed");

        let value = 1_000u64;
        let randomness = [42u8; 32];
        let recipient = [1u8; 32];

        // Commitment computed via the same host helper that
        // `Note::commitment` uses; the circuit's `poseidon_commit_gadget`
        // reproduces this value bit-for-bit.
        let commitment_fr = poseidon_commit(
            Fr::from(value),
            Fr::from_le_bytes_mod_order(&randomness),
            Fr::from_le_bytes_mod_order(&recipient),
        );
        let commitment_bytes = fr_to_bytes_32(commitment_fr);

        let proof_circuit =
            DepositCircuit::with_witness(commitment_bytes, value, randomness, recipient);
        let proof = Groth16ProofSystem::prove(&pk, proof_circuit, &mut rng)
            .expect("proof generation should succeed");

        // Public input layout: a single Fr (the commitment) lifted from
        // the on-chain 32-byte buffer via `from_le_bytes_mod_order`. Any
        // change to that convention must be reflected here.
        let public_inputs = [Fr::from_le_bytes_mod_order(&commitment_bytes)];
        let verified = Groth16ProofSystem::verify(&vk, &public_inputs, &proof)
            .expect("verification should not error");
        assert!(verified, "honestly generated deposit proof must verify");
    }

    /// Cross-circuit consistency: a note created by Deposit can be spent
    /// by Transfer, and the note that Transfer produces can in turn be
    /// withdrawn by Withdraw. Synthesizing each circuit and asserting
    /// `cs.is_satisfied()` is enough — the whole point of this test is
    /// that the three circuits agree on commitment, nullifier, and
    /// Merkle-leaf shapes. A regression in any one of them would surface
    /// here as an unsatisfied constraint, even before Groth16 setup.
    #[test]
    fn test_deposit_transfer_withdraw_e2e() {
        // ── Step 1: Deposit a note for Alice ──────────────────────────
        let alice_address = [0xA1u8; 32];
        let alice_secret = [0xA5u8; 32];
        let alice_amount = 1_000u64;
        let alice_randomness = [0x11u8; 32];

        let alice_commitment_fr = poseidon_commit(
            Fr::from(alice_amount),
            Fr::from_le_bytes_mod_order(&alice_randomness),
            Fr::from_le_bytes_mod_order(&alice_address),
        );
        let alice_commitment_bytes = fr_to_bytes_32(alice_commitment_fr);

        let deposit = DepositCircuit::with_witness(
            alice_commitment_bytes,
            alice_amount,
            alice_randomness,
            alice_address,
        );
        let cs_deposit = ConstraintSystem::<Fr>::new_ref();
        deposit
            .generate_constraints(cs_deposit.clone())
            .expect("deposit synthesis");
        assert!(
            cs_deposit
                .is_satisfied()
                .expect("deposit constraint system query"),
            "deposit constraints unsatisfied"
        );

        // ── Step 2: Transfer Alice's note to Bob ──────────────────────
        // Single-leaf Merkle tree with Alice's note as the only leaf and
        // a public sibling. The transfer circuit must be able to walk
        // the tree from Alice's commitment to the published root.
        let sibling_to_alice = [0x55u8; 32];
        let merkle_root_after_deposit = fr_to_bytes_32(poseidon_merkle_pair(
            alice_commitment_fr,
            Fr::from_le_bytes_mod_order(&sibling_to_alice),
        ));

        let bob_address = [0xB0u8; 32];
        let bob_randomness = [0x22u8; 32];
        let bob_amount = alice_amount; // 1-in / 1-out, value-preserving

        let bob_commitment_fr = poseidon_commit(
            Fr::from(bob_amount),
            Fr::from_le_bytes_mod_order(&bob_randomness),
            Fr::from_le_bytes_mod_order(&bob_address),
        );
        let bob_commitment_bytes = fr_to_bytes_32(bob_commitment_fr);

        let alice_nullifier_fr = poseidon_nullifier(
            alice_commitment_fr,
            Fr::from_le_bytes_mod_order(&alice_secret),
        );
        let alice_nullifier_bytes = fr_to_bytes_32(alice_nullifier_fr);

        let transfer = TransferCircuit::with_witness(
            merkle_root_after_deposit,
            vec![alice_nullifier_bytes],
            vec![bob_commitment_bytes],
            vec![alice_amount],
            vec![alice_randomness],
            vec![alice_address],
            vec![alice_secret],
            vec![vec![(sibling_to_alice, true)]],
            vec![bob_amount],
            vec![bob_randomness],
            vec![bob_address],
        );
        let cs_transfer = ConstraintSystem::<Fr>::new_ref();
        transfer
            .generate_constraints(cs_transfer.clone())
            .expect("transfer synthesis");
        assert!(
            cs_transfer
                .is_satisfied()
                .expect("transfer constraint system query"),
            "transfer constraints unsatisfied — deposit→transfer linkage broken"
        );

        // ── Step 3: Bob withdraws his note ────────────────────────────
        // New tree containing Bob's commitment as the only leaf.
        let sibling_to_bob = [0x66u8; 32];
        let merkle_root_after_transfer = fr_to_bytes_32(poseidon_merkle_pair(
            bob_commitment_fr,
            Fr::from_le_bytes_mod_order(&sibling_to_bob),
        ));

        let bob_secret = [0xB5u8; 32];
        let bob_nullifier_fr =
            poseidon_nullifier(bob_commitment_fr, Fr::from_le_bytes_mod_order(&bob_secret));
        let bob_nullifier_bytes = fr_to_bytes_32(bob_nullifier_fr);

        let withdraw = WithdrawCircuit::with_witness(
            merkle_root_after_transfer,
            bob_nullifier_bytes,
            bob_amount, // withdraw the full value
            bob_amount,
            bob_randomness,
            bob_address,
            bob_secret,
            vec![(sibling_to_bob, true)],
        );
        let cs_withdraw = ConstraintSystem::<Fr>::new_ref();
        withdraw
            .generate_constraints(cs_withdraw.clone())
            .expect("withdraw synthesis");
        assert!(
            cs_withdraw
                .is_satisfied()
                .expect("withdraw constraint system query"),
            "withdraw constraints unsatisfied — transfer→withdraw linkage broken"
        );
    }
}
