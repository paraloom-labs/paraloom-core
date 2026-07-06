//! zkSNARK circuits for shielded transactions
//!
//! Implements zero-knowledge proof circuits using Groth16 on BN254 curve.
//! These circuits verify transaction validity without revealing sensitive information.
//!
//! Circuit types:
//! - TransferCircuit: Private → Private transfers (fully shielded)
//! - DepositCircuit: Public → Private deposits
//! - WithdrawCircuit: Private → Public withdrawals

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    uint32::UInt32, uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{CryptoRng, RngCore};

use crate::privacy::poseidon::{
    poseidon_commit_gadget, poseidon_commit_spend_gadget, poseidon_merkle_pair_gadget,
    poseidon_nullifier_gadget, poseidon_nullifier_spend_gadget, poseidon_pubkey_gadget,
    poseidon_signature_gadget,
};
use crate::privacy::poseidon_circom::{
    v3_commit_gadget, v3_merkle_pair_gadget, v3_nullifier_gadget, v3_pubkey_gadget,
    v3_signature_gadget,
};

/// Allocate a private witness `u64` and return both the bit-decomposed
/// `UInt64` (which carries the range constraint as a side effect of
/// allocation — every bit is enforced to be `{0,1}`) and an `FpVar`
/// view suitable for use in Poseidon hashes and field arithmetic.
///
/// The `FpVar` view is a free linear combination of the bits, so it
/// adds no extra constraints beyond the 64 boolean constraints UInt64
/// itself produces. This is the building block that gives every
/// circuit's value witnesses a hard `[0, 2^64)` upper bound — without
/// it, a malicious prover can assign `value` to a near-field-prime
/// integer and forge withdrawals that exceed the deposited supply.
fn alloc_u64_witness(
    cs: ConstraintSystemRef<Fr>,
    value: Option<u64>,
) -> Result<(UInt64<Fr>, FpVar<Fr>), SynthesisError> {
    let uint = UInt64::new_witness(cs, || value.ok_or(SynthesisError::AssignmentMissing))?;
    let fp = Boolean::le_bits_to_fp_var(&uint.to_bits_le())?;
    Ok((uint, fp))
}

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
    /// Asset id bound into every input AND output commitment as a single
    /// shared witness (#235). One value across both sides means the
    /// `sum_inputs == sum_outputs` constraint is automatically per-asset:
    /// you cannot consume asset A and mint asset B. Native SOL uses
    /// `NATIVE_SOL_ASSET` (all-zero).
    pub asset_id: Option<[u8; 32]>,
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
            asset_id: None,
        }
    }

    /// Create a native-SOL transfer circuit with witness data for proving.
    /// Binds `asset_id = NATIVE_SOL_ASSET` (all-zero) into every commitment,
    /// preserving the pre-multi-asset call signature.
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
        Self::with_witness_asset(
            merkle_root,
            nullifiers,
            output_commitments,
            input_values,
            input_randomness,
            input_recipients,
            input_secrets,
            input_paths,
            output_values,
            output_randomness,
            recipient_addresses,
            crate::privacy::types::NATIVE_SOL_ASSET,
        )
    }

    /// Create a transfer circuit bound to a specific `asset_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn with_witness_asset(
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
        asset_id: [u8; 32],
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
            asset_id: Some(asset_id),
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
        // Range-constrain every input value to `[0, 2^64)` via bit
        // decomposition. Together with the matching output range and
        // the value-conservation check below, this prevents a prover
        // from inflating a transfer with a near-field-prime "input"
        // that wraps mod p — the unbounded-mint vector flagged in #60.
        let mut input_value_vars = Vec::new();
        for value in &self.input_values {
            let (_bits, val_var) = alloc_u64_witness(cs.clone(), *value)?;
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

        // Single shared asset_id witness, fed into every input AND output
        // commitment below. Because it is the same variable on both sides,
        // the `sum_inputs == sum_outputs` balance check (CONSTRAINT 1) is
        // automatically per-asset: a prover cannot satisfy the input
        // commitments with asset A and the output commitments with asset B,
        // so asset A can never be transmuted into asset B (#235).
        let asset_id_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .asset_id
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // Range-constrain every output value to `[0, 2^64)`. With
        // both sides bounded, the existing `sum_inputs == sum_outputs`
        // equality holds in the integers as well as in the field —
        // 2 inputs + 2 outputs at u64 max are still well below the
        // BN254 scalar prime, so the field equality cannot be
        // gamed by a sum that wraps mod p.
        let mut output_value_vars = Vec::new();
        for value in &self.output_values {
            let (_bits, val_var) = alloc_u64_witness(cs.clone(), *value)?;
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
        let mut input_commitment_vars = Vec::with_capacity(input_value_vars.len());
        for ((value_var, randomness_var), recipient_var) in input_value_vars
            .iter()
            .zip(input_randomness_vars.iter())
            .zip(input_recipient_vars.iter())
        {
            let commitment = poseidon_commit_gadget(
                cs.clone(),
                value_var,
                randomness_var,
                recipient_var,
                &asset_id_var,
            )?;
            input_commitment_vars.push(commitment);
        }

        // CONSTRAINT 2: each input commitment is in the Merkle tree under
        // the public `merkle_root`. The Merkle gadget mirrors
        // `MerkleTree::hash_pair` and `MerklePath::verify` on the host
        // side (privacy::merkle, privacy::types).
        // The sibling is a witness (not an `FpVar::constant`) and the
        // direction is chosen with a constraint-level `select`, so the R1CS
        // shape is identical for every path pattern — a single ceremony key
        // verifies any leaf. This mirrors the `WithdrawCircuit` fix (#184); the
        // earlier `FpVar::constant` + Rust `if *is_left` baked the path into
        // the R1CS, so a key from the all-`false` dummy setup only verified the
        // degenerate path and rejected real mixed-direction proofs.
        for (path_slot, commitment_var) in self.input_paths.iter().zip(input_commitment_vars.iter())
        {
            let mut current_hash = commitment_var.clone();

            if let Some(path) = path_slot {
                for (sibling_hash, is_left) in path {
                    let sibling_var = FpVar::new_witness(cs.clone(), || {
                        Ok(Fr::from_le_bytes_mod_order(sibling_hash))
                    })?;
                    let is_left_var = Boolean::new_witness(cs.clone(), || Ok(*is_left))?;

                    let l = is_left_var.select(&current_hash, &sibling_var)?;
                    let r = is_left_var.select(&sibling_var, &current_hash)?;

                    current_hash = poseidon_merkle_pair_gadget(cs.clone(), &l, &r)?;
                }
            }

            // Enforce membership UNCONDITIONALLY (mirrors WithdrawCircuit). A
            // `None` path leaves `current_hash = commitment` and forces
            // `commitment == merkle_root`, which fails closed for any real
            // (multi-level) tree. Previously this `enforce_equal` sat inside
            // the `if let Some(path)`, so a `None` path silently skipped the
            // membership check — an input could then be spent without proving
            // it exists in the tree. The R1CS shape is unchanged for the
            // production path (setup and prover both pass full-depth `Some`
            // paths), so this only closes the `None` footgun.
            current_hash.enforce_equal(&merkle_root_var)?;
        }

        // CONSTRAINT 3: nullifier = Poseidon(NULLIFIER_TAG, commitment, secret).
        // Aligned with `WithdrawCircuit` and host-side `Nullifier::derive`
        // (privacy::types). Using the in-circuit commitment computed above
        // guarantees that any spend whose commitment passes the Merkle
        // check also produces the canonical nullifier.
        for ((commitment_var, secret_var), nullifier_var) in input_commitment_vars
            .iter()
            .zip(input_secret_vars.iter())
            .zip(nullifier_vars.iter())
        {
            let computed_nullifier =
                poseidon_nullifier_gadget(cs.clone(), commitment_var, secret_var)?;
            computed_nullifier.enforce_equal(nullifier_var)?;
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
                &asset_id_var,
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

        // Private witness: amount, range-constrained to `[0, 2^64)` via
        // bit decomposition. Without this, a malicious prover could
        // assign `value` to a near-field-prime integer and produce a
        // commitment whose stored value vastly exceeds the deposited
        // SOL — the foundation of the unbounded-mint attack the audit
        // (#60) flagged. The `FpVar` view is the same as before so all
        // downstream Poseidon hashing and arithmetic is unchanged.
        let (_value_bits, value_var) = alloc_u64_witness(cs.clone(), self.value)?;

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

        // Constraint: commitment_var == Poseidon(TAG, value, randomness, recipient, asset_id)
        //
        // Uses the domain-separated gadget that mirrors `poseidon_commit`
        // on the host side one-for-one. The input argument order
        // (value, randomness, recipient, asset_id) is fixed and must stay
        // aligned with the host helper. Deposits bind the native-SOL
        // sentinel asset_id (all-zero); promoting deposit asset_id to a
        // public input + on-chain vault enforcement is #237's scope.
        let asset_id_var = FpVar::constant(Fr::from(0u64));
        let computed_commitment = poseidon_commit_gadget(
            cs,
            &value_var,
            &randomness_var,
            &recipient_var,
            &asset_id_var,
        )?;
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

        // Range-constrain the withdraw amount to `[0, 2^64)`. Public
        // inputs cannot be range-constrained at allocation, so we
        // commit to a private \`UInt64\` mirror and enforce equality
        // between the public-input \`FpVar\` and the bit-derived view.
        // The prover must therefore choose a u64-shaped withdraw amount
        // before producing a proof; a near-field-prime amount fails
        // the equality check inside the circuit.
        let (_withdraw_bits, withdraw_amount_range_var) =
            alloc_u64_witness(cs.clone(), self.withdraw_amount)?;
        withdraw_amount_var.enforce_equal(&withdraw_amount_range_var)?;

        // ────────────────────────────────────────────────────────────────
        // Private witnesses — lifted to FpVar<Fr>. The old byte-array
        // witness `input_value_bytes` is gone: Poseidon consumes field
        // elements, not u64 bytes.
        // ────────────────────────────────────────────────────────────────
        let (_input_value_bits, input_value_var) = alloc_u64_witness(cs.clone(), self.input_value)?;

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

        // CONSTRAINT 1: input_value >= withdraw_amount, enforced by
        // committing to a u64-bounded \`change\` witness and binding it
        // to the field-level subtraction.
        //
        // If \`withdraw_amount\` exceeds \`input_value\`, the field
        // subtraction \`input_value - withdraw_amount\` wraps mod p to
        // a near-field-prime value far outside \`[0, 2^64)\`, and the
        // \`change\` u64 cannot satisfy the equality. The circuit
        // therefore rejects underflow by construction — the
        // pre-#60 version of this constraint was a no-op that only
        // ever computed the difference without enforcing anything.
        let change_value = match (self.input_value, self.withdraw_amount) {
            (Some(input), Some(withdraw)) => Some(input.saturating_sub(withdraw)),
            _ => None,
        };
        let (_change_bits, change_var) = alloc_u64_witness(cs.clone(), change_value)?;
        let computed_change = &input_value_var - &withdraw_amount_var;
        change_var.enforce_equal(&computed_change)?;

        // CONSTRAINT 2: input commitment is in the Merkle tree under
        // the public `merkle_root`. The commitment is computed with the
        // same three-argument formula that `DepositCircuit` and host-side
        // `Note::commitment` use, so any note created by a deposit can be
        // located here.
        // Withdrawals bind the native-SOL sentinel asset_id (all-zero),
        // matching how deposits mint native notes. Per-asset withdrawal
        // (promoting asset_id to a public input + on-chain vault check) is
        // #237's scope.
        let asset_id_var = FpVar::constant(Fr::from(0u64));
        let commitment = poseidon_commit_gadget(
            cs.clone(),
            &input_value_var,
            &input_randomness_var,
            &input_recipient_var,
            &asset_id_var,
        )?;

        let mut current_hash = commitment.clone();

        // Walk the authentication path to the root. The sibling at each level
        // and the direction are *witnesses*, not circuit constants, so a
        // single proving/verifying key pair verifies a membership proof for
        // any leaf and reveals neither the path nor which leaf is spent.
        // (An earlier version allocated the sibling as `FpVar::constant` and
        // branched on the direction with a Rust `if`, which baked the path
        // into the R1CS — the keys then fit one fixed path and only the
        // degenerate single-leaf, empty-path case ever verified.)
        if let Some(path) = &self.input_path {
            for (sibling_hash, is_left) in path {
                let sibling_var = FpVar::new_witness(cs.clone(), || {
                    Ok(Fr::from_le_bytes_mod_order(sibling_hash))
                })?;
                let is_left_var = Boolean::new_witness(cs.clone(), || Ok(*is_left))?;

                // `is_left` = the current node is the left child, so it pairs
                // as (current, sibling); otherwise (sibling, current). Use a
                // constraint-level select so the R1CS shape is the same for
                // every direction pattern.
                let l = is_left_var.select(&current_hash, &sibling_var)?;
                let r = is_left_var.select(&sibling_var, &current_hash)?;

                current_hash = poseidon_merkle_pair_gadget(cs.clone(), &l, &r)?;
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

/// Withdraw circuit, spend-key construction (circuit v2, #293).
///
/// The successor to [`WithdrawCircuit`]: spend authority is a private key, not a
/// free `secret` witness. The note binds `pubkey = Poseidon(privkey)` in its
/// commitment, and the nullifier folds in a signature over
/// `(commitment, leaf_index)` that requires the private key — so a note at a
/// given tree position yields exactly one nullifier and only its key-holder can
/// produce it. `leaf_index` is derived in-circuit from the Merkle path's
/// direction bits, so the prover cannot pick an index inconsistent with the
/// path. Lives alongside the v1 circuit until the prover, on-chain verifier and
/// keys cut over together.
pub struct WithdrawCircuitV2 {
    // Public inputs. Order here is also the Groth16 public-input slice order:
    // [merkle_root, nullifier, withdraw_amount, ext_data_hash, asset_id].
    pub merkle_root: Option<[u8; 32]>,
    pub nullifier: Option<[u8; 32]>,
    pub withdraw_amount: Option<u64>,
    /// Hash of the external withdrawal data (recipient, fee, relayer, …) that
    /// the on-chain program computes and supplies as a public input (finding D).
    /// The circuit does not constrain it against anything internal — its binding
    /// is the Groth16 public-input equation: a proof is valid for exactly one
    /// `ext_data_hash`, so a relayer or front-runner cannot redirect the funds
    /// to a different recipient without invalidating it.
    pub ext_data_hash: Option<[u8; 32]>,
    // Private witnesses.
    pub input_value: Option<u64>,
    pub blinding: Option<[u8; 32]>,
    pub privkey: Option<[u8; 32]>,
    pub asset_id: Option<[u8; 32]>,
    pub input_path: Option<Vec<([u8; 32], bool)>>,
}

impl WithdrawCircuitV2 {
    pub fn new() -> Self {
        WithdrawCircuitV2 {
            merkle_root: None,
            nullifier: None,
            withdraw_amount: None,
            ext_data_hash: None,
            input_value: None,
            blinding: None,
            privkey: None,
            asset_id: None,
            input_path: None,
        }
    }
}

impl Default for WithdrawCircuitV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuitV2 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- Public inputs ---
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
        let (_withdraw_bits, withdraw_amount_range_var) =
            alloc_u64_witness(cs.clone(), self.withdraw_amount)?;
        withdraw_amount_var.enforce_equal(&withdraw_amount_range_var)?;

        // CONSTRAINT 0: bind the external withdrawal data (finding D). The
        // on-chain program computes ext_data_hash = H(recipient, fee, relayer, …)
        // and passes it as this public input, so a valid proof commits to exactly
        // one destination — a relayer or front-runner cannot redirect the
        // withdrawal to another recipient without invalidating the proof. The
        // hash is not constrained against anything in-circuit; its binding is the
        // Groth16 public-input equation. We still square it into a witness so the
        // variable is wired into the R1CS and cannot be optimised away (the
        // Tornado-Nova `extDataHash` pattern).
        let ext_data_hash_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .ext_data_hash
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        let _ext_data_hash_sq = &ext_data_hash_var * &ext_data_hash_var;

        // --- Private witnesses ---
        let (_input_value_bits, input_value_var) = alloc_u64_witness(cs.clone(), self.input_value)?;
        let blinding_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .blinding
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        let privkey_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .privkey
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        // asset_id is a PUBLIC input (#293 finding A): exposing it lets the
        // on-chain program bind the released vault's mint to the proven asset,
        // so an asset-blind proof cannot drain a different asset's vault. It is
        // bound into the commitment below, so the value proven also matches the
        // committed asset.
        let asset_id_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .asset_id
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // CONSTRAINT 1: input_value >= withdraw_amount (change is u64-bounded).
        let change_value = match (self.input_value, self.withdraw_amount) {
            (Some(input), Some(withdraw)) => Some(input.saturating_sub(withdraw)),
            _ => None,
        };
        let (_change_bits, change_var) = alloc_u64_witness(cs.clone(), change_value)?;
        let computed_change = &input_value_var - &withdraw_amount_var;
        change_var.enforce_equal(&computed_change)?;

        // CONSTRAINT 2: the note commitment binds the spend public key.
        let pubkey_var = poseidon_pubkey_gadget(cs.clone(), &privkey_var)?;
        let commitment = poseidon_commit_spend_gadget(
            cs.clone(),
            &input_value_var,
            &pubkey_var,
            &blinding_var,
            &asset_id_var,
        )?;

        // CONSTRAINT 3: the commitment is in the tree, and `leaf_index` is the
        // path's position — derived from the direction bits so it cannot be
        // chosen inconsistently with the path. `is_left` = current node is the
        // left child, so the index bit at that level is `!is_left`.
        let mut current_hash = commitment.clone();
        let mut leaf_index = FpVar::<Fr>::zero();
        let mut place = Fr::from(1u64);
        if let Some(path) = &self.input_path {
            for (sibling_hash, is_left) in path {
                let sibling_var = FpVar::new_witness(cs.clone(), || {
                    Ok(Fr::from_le_bytes_mod_order(sibling_hash))
                })?;
                let is_left_var = Boolean::new_witness(cs.clone(), || Ok(*is_left))?;

                let l = is_left_var.select(&current_hash, &sibling_var)?;
                let r = is_left_var.select(&sibling_var, &current_hash)?;
                current_hash = poseidon_merkle_pair_gadget(cs.clone(), &l, &r)?;

                // Add `place` to the index iff this node is the right child.
                let bit_contrib = is_left_var
                    .not()
                    .select(&FpVar::constant(place), &FpVar::<Fr>::zero())?;
                leaf_index += &bit_contrib;
                place = place + place;
            }
        }
        current_hash.enforce_equal(&merkle_root_var)?;

        // CONSTRAINT 4: nullifier binds the signature, which requires the key.
        let signature =
            poseidon_signature_gadget(cs.clone(), &privkey_var, &commitment, &leaf_index)?;
        let computed_nullifier =
            poseidon_nullifier_spend_gadget(cs, &commitment, &leaf_index, &signature)?;
        computed_nullifier.enforce_equal(&nullifier_var)?;

        Ok(())
    }
}

/// Transfer circuit, spend-key construction (circuit v2, #293).
///
/// The shielded→shielded successor to [`TransferCircuit`]. Each input note binds
/// `pubkey = Poseidon(privkey)` and is spent by proving knowledge of its key
/// (folded into the nullifier through a signature over `(commitment,
/// leaf_index)`), with `leaf_index` derived in-circuit from the Merkle path.
/// Output notes bind the recipients' spend public keys. On top of the per-input
/// spend authorization it enforces (1) value conservation across all asset-bound
/// commitments and (2) input-nullifier distinctness, so the same note cannot be
/// presented as two inputs. Additive — alongside v1 until cutover.
pub struct TransferCircuitV2 {
    // Public inputs.
    pub merkle_root: Option<[u8; 32]>,
    pub nullifiers: Vec<Option<[u8; 32]>>,
    pub output_commitments: Vec<Option<[u8; 32]>>,
    // Private witnesses.
    pub input_values: Vec<Option<u64>>,
    pub input_blindings: Vec<Option<[u8; 32]>>,
    pub input_privkeys: Vec<Option<[u8; 32]>>,
    pub input_paths: Vec<Option<MerklePath>>,
    pub output_values: Vec<Option<u64>>,
    pub output_blindings: Vec<Option<[u8; 32]>>,
    pub output_pubkeys: Vec<Option<[u8; 32]>>,
    pub asset_id: Option<[u8; 32]>,
}

impl TransferCircuitV2 {
    pub fn new(num_inputs: usize, num_outputs: usize) -> Self {
        TransferCircuitV2 {
            merkle_root: None,
            nullifiers: vec![None; num_inputs],
            output_commitments: vec![None; num_outputs],
            input_values: vec![None; num_inputs],
            input_blindings: vec![None; num_inputs],
            input_privkeys: vec![None; num_inputs],
            input_paths: vec![None; num_inputs],
            output_values: vec![None; num_outputs],
            output_blindings: vec![None; num_outputs],
            output_pubkeys: vec![None; num_outputs],
            asset_id: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_witness(
        merkle_root: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
        input_values: Vec<u64>,
        input_blindings: Vec<[u8; 32]>,
        input_privkeys: Vec<[u8; 32]>,
        input_paths: Vec<Vec<([u8; 32], bool)>>,
        output_values: Vec<u64>,
        output_blindings: Vec<[u8; 32]>,
        output_pubkeys: Vec<[u8; 32]>,
        asset_id: [u8; 32],
    ) -> Self {
        TransferCircuitV2 {
            merkle_root: Some(merkle_root),
            nullifiers: nullifiers.into_iter().map(Some).collect(),
            output_commitments: output_commitments.into_iter().map(Some).collect(),
            input_values: input_values.into_iter().map(Some).collect(),
            input_blindings: input_blindings.into_iter().map(Some).collect(),
            input_privkeys: input_privkeys.into_iter().map(Some).collect(),
            input_paths: input_paths.into_iter().map(Some).collect(),
            output_values: output_values.into_iter().map(Some).collect(),
            output_blindings: output_blindings.into_iter().map(Some).collect(),
            output_pubkeys: output_pubkeys.into_iter().map(Some).collect(),
            asset_id: Some(asset_id),
        }
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuitV2 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // --- Public inputs ---
        let merkle_root_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .merkle_root
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        let mut nullifier_vars = Vec::new();
        for nullifier in &self.nullifiers {
            nullifier_vars.push(FpVar::new_input(cs.clone(), || {
                Ok(nullifier
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?);
        }
        let mut output_commitment_vars = Vec::new();
        for commitment in &self.output_commitments {
            output_commitment_vars.push(FpVar::new_input(cs.clone(), || {
                Ok(commitment
                    .map(|b| Fr::from_le_bytes_mod_order(&b))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?);
        }

        // --- Private witnesses ---
        let mut input_value_vars = Vec::new();
        for value in &self.input_values {
            let (_bits, v) = alloc_u64_witness(cs.clone(), *value)?;
            input_value_vars.push(v);
        }
        let mut input_blinding_vars = Vec::new();
        for b in &self.input_blindings {
            input_blinding_vars.push(FpVar::new_witness(cs.clone(), || {
                Ok(b.map(|x| Fr::from_le_bytes_mod_order(&x))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?);
        }
        let mut input_privkey_vars = Vec::new();
        for k in &self.input_privkeys {
            input_privkey_vars.push(FpVar::new_witness(cs.clone(), || {
                Ok(k.map(|x| Fr::from_le_bytes_mod_order(&x))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?);
        }
        // Single shared asset_id, a PUBLIC input (#293 finding A), bound into
        // every input AND output commitment — so the balance check below is
        // automatically per-asset, and the on-chain program can bind the proven
        // asset to the mint it settles.
        let asset_id_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .asset_id
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        let mut output_value_vars = Vec::new();
        for value in &self.output_values {
            let (_bits, v) = alloc_u64_witness(cs.clone(), *value)?;
            output_value_vars.push(v);
        }
        let mut output_blinding_vars = Vec::new();
        for b in &self.output_blindings {
            output_blinding_vars.push(FpVar::new_witness(cs.clone(), || {
                Ok(b.map(|x| Fr::from_le_bytes_mod_order(&x))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?);
        }
        let mut output_pubkey_vars = Vec::new();
        for p in &self.output_pubkeys {
            output_pubkey_vars.push(FpVar::new_witness(cs.clone(), || {
                Ok(p.map(|x| Fr::from_le_bytes_mod_order(&x))
                    .unwrap_or_else(|| Fr::from(0u64)))
            })?);
        }

        // CONSTRAINT 1: value conservation (sum inputs == sum outputs).
        let mut input_sum = FpVar::zero();
        for v in &input_value_vars {
            input_sum += v;
        }
        let mut output_sum = FpVar::zero();
        for v in &output_value_vars {
            output_sum += v;
        }
        input_sum.enforce_equal(&output_sum)?;

        // CONSTRAINT 2: each input is a spend-authorized note in the tree, and
        // its nullifier binds the key and the (path-derived) leaf index.
        for i in 0..input_value_vars.len() {
            let pubkey = poseidon_pubkey_gadget(cs.clone(), &input_privkey_vars[i])?;
            let commitment = poseidon_commit_spend_gadget(
                cs.clone(),
                &input_value_vars[i],
                &pubkey,
                &input_blinding_vars[i],
                &asset_id_var,
            )?;

            let mut current_hash = commitment.clone();
            let mut leaf_index = FpVar::<Fr>::zero();
            let mut place = Fr::from(1u64);
            if let Some(path) = &self.input_paths[i] {
                for (sibling_hash, is_left) in path {
                    let sibling_var = FpVar::new_witness(cs.clone(), || {
                        Ok(Fr::from_le_bytes_mod_order(sibling_hash))
                    })?;
                    let is_left_var = Boolean::new_witness(cs.clone(), || Ok(*is_left))?;
                    let l = is_left_var.select(&current_hash, &sibling_var)?;
                    let r = is_left_var.select(&sibling_var, &current_hash)?;
                    current_hash = poseidon_merkle_pair_gadget(cs.clone(), &l, &r)?;
                    let bit_contrib = is_left_var
                        .not()
                        .select(&FpVar::constant(place), &FpVar::<Fr>::zero())?;
                    leaf_index += &bit_contrib;
                    place = place + place;
                }
            }
            current_hash.enforce_equal(&merkle_root_var)?;

            let signature = poseidon_signature_gadget(
                cs.clone(),
                &input_privkey_vars[i],
                &commitment,
                &leaf_index,
            )?;
            let computed_nullifier =
                poseidon_nullifier_spend_gadget(cs.clone(), &commitment, &leaf_index, &signature)?;
            computed_nullifier.enforce_equal(&nullifier_vars[i])?;
        }

        // CONSTRAINT 3: input nullifiers are pairwise distinct, so the same note
        // cannot be presented as two inputs (the reuse-one-note value forgery).
        for i in 0..nullifier_vars.len() {
            for j in (i + 1)..nullifier_vars.len() {
                nullifier_vars[i].enforce_not_equal(&nullifier_vars[j])?;
            }
        }

        // CONSTRAINT 4: output commitments bind the recipients' spend pubkeys.
        for j in 0..output_value_vars.len() {
            let computed = poseidon_commit_spend_gadget(
                cs.clone(),
                &output_value_vars[j],
                &output_pubkey_vars[j],
                &output_blinding_vars[j],
                &asset_id_var,
            )?;
            computed.enforce_equal(&output_commitment_vars[j])?;
        }

        Ok(())
    }
}

/// Deposit circuit, spend-key construction (circuit v2, #293).
///
/// The public→shielded successor to [`DepositCircuit`]: it proves the output
/// note's commitment is a well-formed spend-key commitment binding the
/// recipient's spend public key. A deposit creates a note rather than spending
/// one, so there is no nullifier, Merkle path or signature — the depositor only
/// needs the recipient's *public* key (only the recipient, holding the matching
/// private key, can later spend it). Additive — alongside v1 until cutover.
pub struct DepositCircuitV2 {
    // Public input.
    pub output_commitment: Option<[u8; 32]>,
    // Private witnesses.
    pub value: Option<u64>,
    pub blinding: Option<[u8; 32]>,
    pub recipient_pubkey: Option<[u8; 32]>,
    pub asset_id: Option<[u8; 32]>,
}

impl DepositCircuitV2 {
    pub fn new() -> Self {
        DepositCircuitV2 {
            output_commitment: None,
            value: None,
            blinding: None,
            recipient_pubkey: None,
            asset_id: None,
        }
    }

    pub fn with_witness(
        output_commitment: [u8; 32],
        value: u64,
        blinding: [u8; 32],
        recipient_pubkey: [u8; 32],
        asset_id: [u8; 32],
    ) -> Self {
        DepositCircuitV2 {
            output_commitment: Some(output_commitment),
            value: Some(value),
            blinding: Some(blinding),
            recipient_pubkey: Some(recipient_pubkey),
            asset_id: Some(asset_id),
        }
    }
}

impl Default for DepositCircuitV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuitV2 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let commitment_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .output_commitment
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        // Amount is range-constrained to [0, 2^64) so a near-field-prime value
        // cannot be committed (the unbounded-mint vector, #60).
        let (_value_bits, value_var) = alloc_u64_witness(cs.clone(), self.value)?;
        let blinding_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .blinding
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        let recipient_pubkey_var = FpVar::new_witness(cs.clone(), || {
            Ok(self
                .recipient_pubkey
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;
        // asset_id is a PUBLIC input (#293 finding A): the on-chain deposit
        // handler binds the credited mint to this proven asset.
        let asset_id_var = FpVar::new_input(cs.clone(), || {
            Ok(self
                .asset_id
                .map(|b| Fr::from_le_bytes_mod_order(&b))
                .unwrap_or_else(|| Fr::from(0u64)))
        })?;

        let computed = poseidon_commit_spend_gadget(
            cs,
            &value_var,
            &recipient_pubkey_var,
            &blinding_var,
            &asset_id_var,
        )?;
        computed.enforce_equal(&commitment_var)?;

        Ok(())
    }
}

/// Merkle tree depth for the v3 transact circuit — matches the on-chain
/// incremental tree (`programs/paraloom/merkle_tree::TREE_DEPTH`).
pub const TX_LEVELS: usize = 32;
/// Fixed inputs / outputs of the v3 UTXO transaction (2-in / 2-out).
pub const TX_NINS: usize = 2;
pub const TX_NOUTS: usize = 2;

/// Unified UTXO transaction circuit (circuit v3, #350).
///
/// A single circuit for deposit / withdraw / transfer, the audited Tornado-Nova
/// / privacy-cash construction reimplemented on our circom Poseidon. `n` inputs
/// are spent and `n` outputs created; the signed `public_amount` (`> 0` deposit,
/// `< 0` withdraw as the field element `p − x`, `0` internal transfer) balances
/// the two: `Σ in + public_amount = Σ out`. The program owns the tree and
/// appends the output commitments, so this circuit never names a post-insert
/// root — it only proves membership of the spent notes against a known `root`.
///
/// Per input: the note commitment `Poseidon(4)([amount, pubkey, blinding,
/// asset_id])` (with `pubkey = Poseidon(1)([privkey])`) is a member of `root`
/// (checked only when `amount ≠ 0`, so a deposit or single-input spend can use
/// zero-amount dummies), and the revealed nullifier `Poseidon(3)([commitment,
/// leaf_index, Poseidon(3)([privkey, commitment, leaf_index])])` binds the
/// note's position and requires its private key. Per output: the commitment is
/// re-derived and the amount range-bound to `u64`. The two input nullifiers
/// must differ; `ext_data_hash` (the recipient/fee binding) is constrained so
/// it cannot be swapped.
///
/// Public inputs, in Groth16 slice order:
/// `[root, public_amount, ext_data_hash, asset_id, nullifier0, nullifier1,
///   out_commitment0, out_commitment1]`.
#[derive(Clone)]
pub struct TransactCircuitV3 {
    // Public inputs.
    pub root: Option<[u8; 32]>,
    pub public_amount: Option<[u8; 32]>,
    pub ext_data_hash: Option<[u8; 32]>,
    pub asset_id: Option<[u8; 32]>,
    pub input_nullifiers: Vec<Option<[u8; 32]>>,
    pub output_commitments: Vec<Option<[u8; 32]>>,
    // Private input-note witnesses (length TX_NINS).
    pub in_amounts: Vec<Option<u64>>,
    pub in_privkeys: Vec<Option<[u8; 32]>>,
    pub in_blindings: Vec<Option<[u8; 32]>>,
    pub in_leaf_indices: Vec<Option<u64>>,
    /// `in_paths[tx][i]` = the sibling at level `i`; the direction comes from
    /// bit `i` of `leaf_index`, so no separate direction witness is needed.
    pub in_paths: Vec<Option<Vec<[u8; 32]>>>,
    // Private output-note witnesses (length TX_NOUTS).
    pub out_amounts: Vec<Option<u64>>,
    pub out_pubkeys: Vec<Option<[u8; 32]>>,
    pub out_blindings: Vec<Option<[u8; 32]>>,
}

impl TransactCircuitV3 {
    /// Blank instance for `setup` (fixes the R1CS shape; carries no values).
    pub fn blank() -> Self {
        TransactCircuitV3 {
            root: None,
            public_amount: None,
            ext_data_hash: None,
            asset_id: None,
            input_nullifiers: vec![None; TX_NINS],
            output_commitments: vec![None; TX_NOUTS],
            in_amounts: vec![None; TX_NINS],
            in_privkeys: vec![None; TX_NINS],
            in_blindings: vec![None; TX_NINS],
            in_leaf_indices: vec![None; TX_NINS],
            in_paths: vec![None; TX_NINS],
            out_amounts: vec![None; TX_NOUTS],
            out_pubkeys: vec![None; TX_NOUTS],
            out_blindings: vec![None; TX_NOUTS],
        }
    }
}

impl Default for TransactCircuitV3 {
    fn default() -> Self {
        Self::blank()
    }
}

impl ConstraintSynthesizer<Fr> for TransactCircuitV3 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Field-element public input from optional LE bytes.
        let input_fe = |cs: ConstraintSystemRef<Fr>, v: Option<[u8; 32]>| {
            FpVar::new_input(cs, || {
                v.map(|b| Fr::from_le_bytes_mod_order(&b))
                    .ok_or(SynthesisError::AssignmentMissing)
            })
        };
        let witness_fe = |cs: ConstraintSystemRef<Fr>, v: Option<[u8; 32]>| {
            FpVar::new_witness(cs, || {
                v.map(|b| Fr::from_le_bytes_mod_order(&b))
                    .ok_or(SynthesisError::AssignmentMissing)
            })
        };

        // --- Public inputs (order = Groth16 public-input slice order) ---
        let root_var = input_fe(cs.clone(), self.root)?;
        let public_amount_var = input_fe(cs.clone(), self.public_amount)?;
        let ext_data_hash_var = input_fe(cs.clone(), self.ext_data_hash)?;
        let asset_id_var = input_fe(cs.clone(), self.asset_id)?;
        let mut nullifier_pub = Vec::with_capacity(TX_NINS);
        for tx in 0..TX_NINS {
            nullifier_pub.push(input_fe(cs.clone(), self.input_nullifiers[tx])?);
        }
        let mut commitment_pub = Vec::with_capacity(TX_NOUTS);
        for tx in 0..TX_NOUTS {
            commitment_pub.push(input_fe(cs.clone(), self.output_commitments[tx])?);
        }

        // Bind ext_data_hash into a real constraint so a valid proof cannot be
        // replayed against a different one (it is otherwise unreferenced).
        let _ext_data_square = &ext_data_hash_var * &ext_data_hash_var;

        let zero = FpVar::constant(Fr::from(0u64));
        let mut sum_ins = zero.clone();

        // --- Inputs ---
        // `tx` indexes several parallel witness vectors plus `nullifier_pub`.
        #[allow(clippy::needless_range_loop)]
        for tx in 0..TX_NINS {
            let amount_var = FpVar::new_witness(cs.clone(), || {
                self.in_amounts[tx]
                    .map(Fr::from)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let privkey_var = witness_fe(cs.clone(), self.in_privkeys[tx])?;
            let blinding_var = witness_fe(cs.clone(), self.in_blindings[tx])?;

            // leaf_index as 32 bits: gives both the field element (bound into the
            // signature/nullifier) and the per-level direction selectors.
            let idx_u32 = UInt32::new_witness(cs.clone(), || {
                self.in_leaf_indices[tx]
                    .map(|i| i as u32)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let idx_bits = idx_u32.to_bits_le();
            let leaf_index_var = Boolean::le_bits_to_fp_var(&idx_bits)?;

            let pubkey_var = v3_pubkey_gadget(cs.clone(), &privkey_var)?;
            let commitment_var = v3_commit_gadget(
                cs.clone(),
                &amount_var,
                &pubkey_var,
                &blinding_var,
                &asset_id_var,
            )?;
            let signature_var =
                v3_signature_gadget(cs.clone(), &privkey_var, &commitment_var, &leaf_index_var)?;
            let nullifier_var =
                v3_nullifier_gadget(cs.clone(), &commitment_var, &leaf_index_var, &signature_var)?;
            nullifier_var.enforce_equal(&nullifier_pub[tx])?;

            // Membership fold: direction bit `i` picks (current,sibling) order.
            let mut current = commitment_var;
            for (i, bit) in idx_bits.iter().enumerate() {
                let sibling = FpVar::new_witness(cs.clone(), || {
                    self.in_paths[tx]
                        .as_ref()
                        .and_then(|p| p.get(i))
                        .map(|b| Fr::from_le_bytes_mod_order(b))
                        .ok_or(SynthesisError::AssignmentMissing)
                })?;
                let left = bit.select(&sibling, &current)?;
                let right = bit.select(&current, &sibling)?;
                current = v3_merkle_pair_gadget(cs.clone(), &left, &right)?;
            }
            // Membership is enforced only for non-zero-amount inputs:
            // `(folded_root − root) · amount = 0`.
            let diff = &current - &root_var;
            (&diff * &amount_var).enforce_equal(&zero)?;

            sum_ins = &sum_ins + &amount_var;
        }

        // --- Outputs ---
        let mut sum_outs = zero.clone();
        // `tx` indexes several parallel witness vectors plus `commitment_pub`.
        #[allow(clippy::needless_range_loop)]
        for tx in 0..TX_NOUTS {
            // Range-bound the output amount to u64 (prevents supply forgery).
            let (_bits, amount_var) = alloc_u64_witness(cs.clone(), self.out_amounts[tx])?;
            let pubkey_var = witness_fe(cs.clone(), self.out_pubkeys[tx])?;
            let blinding_var = witness_fe(cs.clone(), self.out_blindings[tx])?;

            let commitment_var = v3_commit_gadget(
                cs.clone(),
                &amount_var,
                &pubkey_var,
                &blinding_var,
                &asset_id_var,
            )?;
            commitment_var.enforce_equal(&commitment_pub[tx])?;

            sum_outs = &sum_outs + &amount_var;
        }

        // The two input nullifiers must differ (no double-spend within a tx):
        // enforce `nullifier0 − nullifier1` is invertible (i.e. non-zero).
        let ndiff = &nullifier_pub[0] - &nullifier_pub[1];
        // `inverse()` constrains `ndiff` to be non-zero (an inverse exists only
        // for a non-zero element), i.e. the two nullifiers differ.
        let _ndiff_inv = ndiff.inverse()?;

        // Value invariant: Σ in + public_amount = Σ out.
        (&sum_ins + &public_amount_var).enforce_equal(&sum_outs)?;

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
    ) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
        ark_groth16::Groth16::<Bn254>::setup(circuit, rng)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Create a proof for a circuit
    pub fn prove<C: ConstraintSynthesizer<Fr>, R: RngCore + CryptoRng>(
        pk: &ProvingKey<Bn254>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<Bn254>, SynthesisError> {
        ark_groth16::Groth16::<Bn254>::prove(pk, circuit, rng)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Verify a proof
    pub fn verify(
        vk: &VerifyingKey<Bn254>,
        public_inputs: &[Fr],
        proof: &Proof<Bn254>,
    ) -> Result<bool, SynthesisError> {
        ark_groth16::Groth16::<Bn254>::verify(vk, public_inputs, proof)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }

    /// Verify with prepared verifying key (faster for batch verification)
    pub fn verify_with_prepared(
        pvk: &PreparedVerifyingKey<Bn254>,
        public_inputs: &[Fr],
        proof: &Proof<Bn254>,
    ) -> Result<bool, SynthesisError> {
        ark_groth16::Groth16::<Bn254>::verify_with_processed_vk(pvk, public_inputs, proof)
            .map_err(|_| SynthesisError::Unsatisfiable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::poseidon::{
        poseidon_commit, poseidon_commit_spend, poseidon_merkle_pair, poseidon_nullifier,
        poseidon_nullifier_spend, poseidon_pubkey, poseidon_signature,
    };
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
            Fr::from(0u64),
        );

        // Nullifier: matches `Nullifier::derive(commitment, secret)`.
        let nullifier_fr = poseidon_nullifier(
            input_commitment_fr,
            Fr::from_le_bytes_mod_order(&input_secret),
        );
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
            Fr::from(0u64),
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

    /// Cross-asset transfers must be unsatisfiable (#235). The transfer
    /// circuit binds ONE shared `asset_id` witness into both the input and
    /// output commitments, so a prover who consumes a note of asset A cannot
    /// mint a note of asset B: no single asset_id value can simultaneously
    /// reproduce an input commitment built under A and an output commitment
    /// built under B. This is what makes value conservation per-asset rather
    /// than global.
    #[test]
    fn transfer_cross_asset_is_unsatisfiable() {
        let asset_a = [0xAAu8; 32];
        let asset_b = [0xBBu8; 32];

        let input_value = 1_000u64;
        let input_randomness = [4u8; 32];
        let input_recipient = [7u8; 32];
        let input_secret = [9u8; 32];

        // Input commitment is built under asset A.
        let input_commitment_fr = poseidon_commit(
            Fr::from(input_value),
            Fr::from_le_bytes_mod_order(&input_randomness),
            Fr::from_le_bytes_mod_order(&input_recipient),
            Fr::from_le_bytes_mod_order(&asset_a),
        );
        let nullifier_fr = poseidon_nullifier(
            input_commitment_fr,
            Fr::from_le_bytes_mod_order(&input_secret),
        );

        let sibling = [5u8; 32];
        let sibling_fr = Fr::from_le_bytes_mod_order(&sibling);
        let merkle_root_fr = poseidon_merkle_pair(input_commitment_fr, sibling_fr);

        // Output commitment is built under asset B — the cross-asset attempt.
        let output_value = input_value; // balance-preserving, only asset differs
        let output_randomness = [6u8; 32];
        let output_recipient = [11u8; 32];
        let output_commitment_fr = poseidon_commit(
            Fr::from(output_value),
            Fr::from_le_bytes_mod_order(&output_randomness),
            Fr::from_le_bytes_mod_order(&output_recipient),
            Fr::from_le_bytes_mod_order(&asset_b),
        );

        // The circuit binds a single shared asset_id. Pick asset A so the
        // input commitment is reproducible; the asset-B output commitment then
        // cannot be reproduced, so the circuit is unsatisfiable.
        let circuit = TransferCircuit::with_witness_asset(
            fr_to_bytes_32(merkle_root_fr),
            vec![fr_to_bytes_32(nullifier_fr)],
            vec![fr_to_bytes_32(output_commitment_fr)],
            vec![input_value],
            vec![input_randomness],
            vec![input_recipient],
            vec![input_secret],
            vec![vec![(sibling, true)]],
            vec![output_value],
            vec![output_randomness],
            vec![output_recipient],
            asset_a,
        );
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis should succeed");
        assert!(
            !cs.is_satisfied().expect("constraint system query"),
            "a cross-asset transfer (input asset != output asset) must not satisfy the circuit"
        );
    }

    /// A `None` input path must NOT bypass the Merkle membership check.
    /// With the fail-closed fix, a `None` path forces `commitment == root`,
    /// which fails for any real tree (root != bare leaf). Pre-fix this
    /// silently passed, letting a prover spend a note not in the tree.
    #[test]
    fn transfer_none_path_does_not_bypass_membership() {
        let input_value = 1_000u64;
        let input_randomness = [4u8; 32];
        let input_recipient = [7u8; 32];
        let input_secret = [9u8; 32];

        let input_commitment_fr = poseidon_commit(
            Fr::from(input_value),
            Fr::from_le_bytes_mod_order(&input_randomness),
            Fr::from_le_bytes_mod_order(&input_recipient),
            Fr::from(0u64),
        );
        let nullifier_fr = poseidon_nullifier(
            input_commitment_fr,
            Fr::from_le_bytes_mod_order(&input_secret),
        );
        // A real root: the pair of the commitment and a sibling, so it is
        // NOT equal to the bare commitment.
        let sibling = [5u8; 32];
        let merkle_root_fr =
            poseidon_merkle_pair(input_commitment_fr, Fr::from_le_bytes_mod_order(&sibling));

        let output_value = input_value;
        let output_randomness = [6u8; 32];
        let output_recipient = [11u8; 32];
        let output_commitment_fr = poseidon_commit(
            Fr::from(output_value),
            Fr::from_le_bytes_mod_order(&output_randomness),
            Fr::from_le_bytes_mod_order(&output_recipient),
            Fr::from(0u64),
        );

        // Build the circuit directly with a `None` input path — the footgun.
        let circuit = TransferCircuit {
            merkle_root: Some(fr_to_bytes_32(merkle_root_fr)),
            nullifiers: vec![Some(fr_to_bytes_32(nullifier_fr))],
            output_commitments: vec![Some(fr_to_bytes_32(output_commitment_fr))],
            input_values: vec![Some(input_value)],
            input_randomness: vec![Some(input_randomness)],
            input_recipients: vec![Some(input_recipient)],
            input_secrets: vec![Some(input_secret)],
            input_paths: vec![None],
            output_values: vec![Some(output_value)],
            output_randomness: vec![Some(output_randomness)],
            recipient_addresses: vec![Some(output_recipient)],
            asset_id: Some(crate::privacy::types::NATIVE_SOL_ASSET),
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis should succeed");
        assert!(
            !cs.is_satisfied().expect("constraint system query"),
            "a None input path must not bypass Merkle membership"
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
            Fr::from(0u64),
        );
        let nullifier_fr = poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));

        // Two-sibling Merkle path: leaf on the left at depth 0, then on
        // the right at depth 1. Mirrors the original test's path shape.
        let sibling_0 = [4u8; 32];
        let sibling_1 = [5u8; 32];
        let level_1 = poseidon_merkle_pair(commitment_fr, Fr::from_le_bytes_mod_order(&sibling_0));
        let merkle_root_fr = poseidon_merkle_pair(Fr::from_le_bytes_mod_order(&sibling_1), level_1);

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

    /// The post-#60 withdraw circuit must reject \`withdraw > input\`.
    /// Before this fix the field-level subtraction wrapped to a huge
    /// value and the circuit silently accepted the underflow; the
    /// range constraint on \`change\` now traps it.
    #[test]
    fn test_withdraw_circuit_rejects_underflow() {
        let input_value = 500u64;
        let withdraw_amount = 1_000u64; // strictly greater than input
        let input_randomness = [3u8; 32];
        let input_recipient = [7u8; 32];
        let secret = [6u8; 32];

        let commitment_fr = poseidon_commit(
            Fr::from(input_value),
            Fr::from_le_bytes_mod_order(&input_randomness),
            Fr::from_le_bytes_mod_order(&input_recipient),
            Fr::from(0u64),
        );
        let nullifier_fr = poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));
        let sibling = [4u8; 32];
        let merkle_root_fr =
            poseidon_merkle_pair(commitment_fr, Fr::from_le_bytes_mod_order(&sibling));

        let circuit = WithdrawCircuit::with_witness(
            fr_to_bytes_32(merkle_root_fr),
            fr_to_bytes_32(nullifier_fr),
            withdraw_amount,
            input_value,
            input_randomness,
            input_recipient,
            secret,
            vec![(sibling, true)],
        );
        let cs = ConstraintSystem::<Fr>::new_ref();

        circuit
            .generate_constraints(cs.clone())
            .expect("constraint synthesis should still succeed structurally");
        assert!(
            !cs.is_satisfied().expect("constraint system query"),
            "withdraw circuit must reject withdraw_amount > input_value"
        );
    }

    /// Property check: every honest \`change\` value in \`[0, input]\`
    /// produces a satisfiable withdraw circuit. Walks through a fixed
    /// set of representative values rather than truly randomising —
    /// this is enough to catch obvious off-by-one and edge regressions
    /// (zero withdraw, full withdraw, large input near u64::MAX).
    #[test]
    fn test_withdraw_circuit_accepts_in_range_values() {
        let input_randomness = [3u8; 32];
        let input_recipient = [7u8; 32];
        let secret = [6u8; 32];
        let sibling = [4u8; 32];

        let cases: &[(u64, u64)] = &[
            (1, 0),
            (1, 1),
            (1_000, 1),
            (1_000, 999),
            (1_000, 1_000),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX - 1),
        ];

        for &(input_value, withdraw_amount) in cases {
            let commitment_fr = poseidon_commit(
                Fr::from(input_value),
                Fr::from_le_bytes_mod_order(&input_randomness),
                Fr::from_le_bytes_mod_order(&input_recipient),
                Fr::from(0u64),
            );
            let nullifier_fr =
                poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));
            let merkle_root_fr =
                poseidon_merkle_pair(commitment_fr, Fr::from_le_bytes_mod_order(&sibling));

            let circuit = WithdrawCircuit::with_witness(
                fr_to_bytes_32(merkle_root_fr),
                fr_to_bytes_32(nullifier_fr),
                withdraw_amount,
                input_value,
                input_randomness,
                input_recipient,
                secret,
                vec![(sibling, true)],
            );
            let cs = ConstraintSystem::<Fr>::new_ref();
            circuit
                .generate_constraints(cs.clone())
                .expect("constraint synthesis should succeed");
            assert!(
                cs.is_satisfied().expect("constraint system query"),
                "withdraw circuit must accept input={} withdraw={}",
                input_value,
                withdraw_amount
            );
        }
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
            Fr::from(0u64),
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
            Fr::from(0u64),
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
            Fr::from(0u64),
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

    // --- WithdrawCircuitV2 (spend-key construction, #293) ---

    /// A consistent v2 withdraw witness set: a note owned by `privkey` at tree
    /// position 2 (path = left@0, right@1), withdrawing 500 of 1000. Returns the
    /// pieces so tests can tamper individually.
    #[allow(clippy::type_complexity)]
    fn v2_withdraw_parts() -> (
        [u8; 32],
        [u8; 32],
        u64,
        u64,
        [u8; 32],
        [u8; 32],
        [u8; 32],
        Vec<([u8; 32], bool)>,
    ) {
        let privkey = [6u8; 32];
        let blinding = [3u8; 32];
        let asset = [0u8; 32];
        let input_value = 1_000u64;
        let withdraw_amount = 500u64;

        let sk = Fr::from_le_bytes_mod_order(&privkey);
        let pubkey = poseidon_pubkey(sk);
        let commitment_fr = poseidon_commit_spend(
            Fr::from(input_value),
            pubkey,
            Fr::from_le_bytes_mod_order(&blinding),
            Fr::from_le_bytes_mod_order(&asset),
        );

        // Path: leaf is the left child at depth 0, then the right child at
        // depth 1 → leaf_index = 0b10 = 2.
        let sibling_0 = [4u8; 32];
        let sibling_1 = [5u8; 32];
        let level_1 = poseidon_merkle_pair(commitment_fr, Fr::from_le_bytes_mod_order(&sibling_0));
        let merkle_root_fr = poseidon_merkle_pair(Fr::from_le_bytes_mod_order(&sibling_1), level_1);
        let path = vec![(sibling_0, true), (sibling_1, false)];
        let leaf_index = 2u64;

        let signature = poseidon_signature(sk, commitment_fr, Fr::from(leaf_index));
        let nullifier_fr = poseidon_nullifier_spend(commitment_fr, Fr::from(leaf_index), signature);

        (
            fr_to_bytes_32(merkle_root_fr),
            fr_to_bytes_32(nullifier_fr),
            withdraw_amount,
            input_value,
            blinding,
            privkey,
            asset,
            path,
        )
    }

    // A circuit *accepts* a witness only if it both synthesises and is
    // satisfied. A synthesis error (e.g. an `enforce_not_equal` whose operands
    // are actually equal, so the inverse witness does not exist) is itself a
    // rejection — the prover cannot even build a proof — so it counts as `false`.
    fn synth_v2(c: WithdrawCircuitV2) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match c.generate_constraints(cs.clone()) {
            Ok(()) => cs.is_satisfied().expect("constraint system query"),
            Err(_) => false,
        }
    }

    #[test]
    fn withdraw_v2_valid_witnesses_satisfy() {
        let (root, nf, wd, val, bl, pk, asset, path) = v2_withdraw_parts();
        assert!(synth_v2(WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(nf),
            withdraw_amount: Some(wd),
            ext_data_hash: Some([7u8; 32]),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some(pk),
            asset_id: Some(asset),
            input_path: Some(path),
        }));
    }

    #[test]
    fn withdraw_v2_rejects_tampered_nullifier() {
        let (root, _nf, wd, val, bl, pk, asset, path) = v2_withdraw_parts();
        assert!(!synth_v2(WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some([0xABu8; 32]), // not the real nullifier
            withdraw_amount: Some(wd),
            ext_data_hash: Some([7u8; 32]),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some(pk),
            asset_id: Some(asset),
            input_path: Some(path),
        }));
    }

    #[test]
    fn withdraw_v2_rejects_wrong_privkey() {
        // A different key derives a different pubkey, so the commitment it forms
        // is not the one in the tree — membership (and the nullifier) fail. This
        // is the spend-authorization property: knowing the note's value/blinding
        // is not enough, you need its private key.
        let (root, nf, wd, val, bl, _pk, asset, path) = v2_withdraw_parts();
        assert!(!synth_v2(WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(nf),
            withdraw_amount: Some(wd),
            ext_data_hash: Some([7u8; 32]),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some([0x99u8; 32]), // not the owner's key
            asset_id: Some(asset),
            input_path: Some(path),
        }));
    }

    #[test]
    fn withdraw_v2_rejects_underflow() {
        // withdraw_amount > input_value; the commitment/nullifier are unchanged
        // (they don't depend on the withdraw amount), so only the change range
        // constraint traps it.
        let (root, nf, _wd, val, bl, pk, asset, path) = v2_withdraw_parts();
        assert!(!synth_v2(WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(nf),
            withdraw_amount: Some(2_000), // > input_value (1000)
            ext_data_hash: Some([7u8; 32]),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some(pk),
            asset_id: Some(asset),
            input_path: Some(path),
        }));
    }

    #[test]
    fn withdraw_v2_binds_the_leaf_index_into_the_nullifier() {
        // The nullifier is computed by the host at the WRONG leaf index (3); the
        // circuit derives the index (2) from the path's direction bits, so the
        // rebuilt nullifier does not match the public one. This is what makes a
        // note at a given position yield exactly one nullifier.
        let (root, _nf, wd, val, bl, pk, asset, path) = v2_withdraw_parts();
        let sk = Fr::from_le_bytes_mod_order(&pk);
        let commitment_fr = poseidon_commit_spend(
            Fr::from(val),
            poseidon_pubkey(sk),
            Fr::from_le_bytes_mod_order(&bl),
            Fr::from_le_bytes_mod_order(&asset),
        );
        let wrong_index = 3u64;
        let sig = poseidon_signature(sk, commitment_fr, Fr::from(wrong_index));
        let nf_wrong = poseidon_nullifier_spend(commitment_fr, Fr::from(wrong_index), sig);

        assert!(!synth_v2(WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(fr_to_bytes_32(nf_wrong)),
            withdraw_amount: Some(wd),
            ext_data_hash: Some([7u8; 32]),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some(pk),
            asset_id: Some(asset),
            input_path: Some(path),
        }));
    }

    #[test]
    fn withdraw_v2_binds_the_public_asset_id() {
        // The note was committed under the native asset (all-zero). Claiming a
        // different public asset_id makes the in-circuit commitment differ from
        // the one in the tree, so membership fails — the proof is bound to its
        // asset (the circuit half of finding A; the on-chain mint check is the
        // other half).
        let (root, nf, wd, val, bl, pk, _asset, path) = v2_withdraw_parts();
        assert!(!synth_v2(WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(nf),
            withdraw_amount: Some(wd),
            ext_data_hash: Some([7u8; 32]),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some(pk),
            asset_id: Some([0xCCu8; 32]), // not the asset the note commits to
            input_path: Some(path),
        }));
    }

    #[test]
    fn withdraw_v2_proof_is_bound_to_the_ext_data_hash() {
        // Finding D: the withdrawal destination is bound through the
        // ext_data_hash public input. A proof generated for one ext_data_hash
        // verifies only against that exact value, so a relayer cannot take a
        // valid proof and redirect the funds by swapping in a different
        // recipient bundle. This is a Groth16 public-input property, so it only
        // shows under a real prove/verify (satisfaction alone never sees it).
        let mut rng = StdRng::seed_from_u64(0xD_u64);
        let (root, nf, wd, val, bl, pk, asset, path) = v2_withdraw_parts();
        let ext_data_hash = [0x42u8; 32];

        let mk = |edh: [u8; 32], p: Vec<([u8; 32], bool)>| WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(nf),
            withdraw_amount: Some(wd),
            ext_data_hash: Some(edh),
            input_value: Some(val),
            blinding: Some(bl),
            privkey: Some(pk),
            asset_id: Some(asset),
            input_path: Some(p),
        };

        let (gpk, vk) = Groth16ProofSystem::setup(mk(ext_data_hash, path.clone()), &mut rng)
            .expect("trusted setup should succeed");
        let proof = Groth16ProofSystem::prove(&gpk, mk(ext_data_hash, path.clone()), &mut rng)
            .expect("proof generation should succeed");

        // Public-input slice order matches the new_input order in
        // generate_constraints: [root, nullifier, amount, ext_data_hash, asset].
        let inputs = |edh: [u8; 32]| {
            [
                Fr::from_le_bytes_mod_order(&root),
                Fr::from_le_bytes_mod_order(&nf),
                Fr::from(wd),
                Fr::from_le_bytes_mod_order(&edh),
                Fr::from_le_bytes_mod_order(&asset),
            ]
        };

        assert!(
            Groth16ProofSystem::verify(&vk, &inputs(ext_data_hash), &proof)
                .expect("verification should not error"),
            "the proof verifies against the destination it was bound to"
        );
        assert!(
            !Groth16ProofSystem::verify(&vk, &inputs([0x43u8; 32]), &proof)
                .expect("verification should not error"),
            "a redirected destination (different ext_data_hash) must not verify"
        );
    }

    // --- TransferCircuitV2 (spend-key construction, #293) ---

    /// Native commitment + nullifier for a v2 input note owned by `sk` at
    /// `leaf_index` (native SOL asset). Returns `(commitment_fr, nullifier_bytes)`.
    fn v2_in_note(sk_bytes: [u8; 32], v: u64, b: [u8; 32], leaf_index: u64) -> (Fr, [u8; 32]) {
        let sk = Fr::from_le_bytes_mod_order(&sk_bytes);
        let c = poseidon_commit_spend(
            Fr::from(v),
            poseidon_pubkey(sk),
            Fr::from_le_bytes_mod_order(&b),
            Fr::from(0u64),
        );
        let sig = poseidon_signature(sk, c, Fr::from(leaf_index));
        let nf = poseidon_nullifier_spend(c, Fr::from(leaf_index), sig);
        (c, fr_to_bytes_32(nf))
    }

    /// Native output commitment bound to recipient pubkey `opk`.
    fn v2_out_commit(opk: [u8; 32], v: u64, b: [u8; 32]) -> [u8; 32] {
        fr_to_bytes_32(poseidon_commit_spend(
            Fr::from(v),
            Fr::from_le_bytes_mod_order(&opk),
            Fr::from_le_bytes_mod_order(&b),
            Fr::from(0u64),
        ))
    }

    fn synth_v2_transfer(c: TransferCircuitV2) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match c.generate_constraints(cs.clone()) {
            Ok(()) => cs.is_satisfied().expect("constraint system query"),
            Err(_) => false,
        }
    }

    /// Two input notes at positions 0 and 1 (a 2-leaf tree), 600 + 400.
    #[allow(clippy::type_complexity)]
    fn two_input_tree() -> (
        [u8; 32],
        Vec<[u8; 32]>,
        Vec<u64>,
        Vec<[u8; 32]>,
        Vec<[u8; 32]>,
        Vec<Vec<([u8; 32], bool)>>,
    ) {
        let (sk0, sk1) = ([6u8; 32], [7u8; 32]);
        let (b0, b1) = ([3u8; 32], [4u8; 32]);
        let (v0, v1) = (600u64, 400u64);
        let (c0, nf0) = v2_in_note(sk0, v0, b0, 0);
        let (c1, nf1) = v2_in_note(sk1, v1, b1, 1);
        let root = fr_to_bytes_32(poseidon_merkle_pair(c0, c1));
        // input0 is the left child (sibling c1); input1 is the right child (sibling c0).
        let path0 = vec![(fr_to_bytes_32(c1), true)];
        let path1 = vec![(fr_to_bytes_32(c0), false)];
        (
            root,
            vec![nf0, nf1],
            vec![v0, v1],
            vec![b0, b1],
            vec![sk0, sk1],
            vec![path0, path1],
        )
    }

    #[test]
    fn transfer_v2_valid_two_in_two_out_satisfies() {
        let (root, nfs, vals, blinds, sks, paths) = two_input_tree();
        // Outputs: 500 + 500 = 1000 = 600 + 400.
        let (opk0, opk1) = ([8u8; 32], [9u8; 32]);
        let (ob0, ob1) = ([10u8; 32], [11u8; 32]);
        let (ov0, ov1) = (500u64, 500u64);
        let ocs = vec![v2_out_commit(opk0, ov0, ob0), v2_out_commit(opk1, ov1, ob1)];
        assert!(synth_v2_transfer(TransferCircuitV2::with_witness(
            root,
            nfs,
            ocs,
            vals,
            blinds,
            sks,
            paths,
            vec![ov0, ov1],
            vec![ob0, ob1],
            vec![opk0, opk1],
            [0u8; 32],
        )));
    }

    #[test]
    fn transfer_v2_rejects_balance_violation() {
        let (root, nfs, vals, blinds, sks, paths) = two_input_tree();
        // Outputs sum 900 != inputs sum 1000.
        let (opk0, opk1) = ([8u8; 32], [9u8; 32]);
        let (ob0, ob1) = ([10u8; 32], [11u8; 32]);
        let (ov0, ov1) = (500u64, 400u64);
        let ocs = vec![v2_out_commit(opk0, ov0, ob0), v2_out_commit(opk1, ov1, ob1)];
        assert!(!synth_v2_transfer(TransferCircuitV2::with_witness(
            root,
            nfs,
            ocs,
            vals,
            blinds,
            sks,
            paths,
            vec![ov0, ov1],
            vec![ob0, ob1],
            vec![opk0, opk1],
            [0u8; 32],
        )));
    }

    #[test]
    fn transfer_v2_rejects_the_same_note_used_twice() {
        // Present input note 0 as BOTH inputs: both produce the same nullifier,
        // so the pairwise-distinctness constraint traps the reuse-one-note value
        // forgery (#293 C). Balance is satisfied (1200 in, 1200 out) so only the
        // distinctness check can fail.
        let (sk0, b0, v0) = ([6u8; 32], [3u8; 32], 600u64);
        let (c0, nf0) = v2_in_note(sk0, v0, b0, 0);
        let c1 = poseidon_commit_spend(
            Fr::from(400u64),
            poseidon_pubkey(Fr::from_le_bytes_mod_order(&[7u8; 32])),
            Fr::from_le_bytes_mod_order(&[4u8; 32]),
            Fr::from(0u64),
        );
        let root = fr_to_bytes_32(poseidon_merkle_pair(c0, c1));
        let path0 = vec![(fr_to_bytes_32(c1), true)];

        let (opk0, opk1) = ([8u8; 32], [9u8; 32]);
        let (ob0, ob1) = ([10u8; 32], [11u8; 32]);
        assert!(!synth_v2_transfer(TransferCircuitV2::with_witness(
            root,
            vec![nf0, nf0], // same note → same nullifier twice
            vec![v2_out_commit(opk0, 600, ob0), v2_out_commit(opk1, 600, ob1)],
            vec![v0, v0],
            vec![b0, b0],
            vec![sk0, sk0],
            vec![path0.clone(), path0],
            vec![600, 600],
            vec![ob0, ob1],
            vec![opk0, opk1],
            [0u8; 32],
        )));
    }

    #[test]
    fn transfer_v2_rejects_wrong_input_key() {
        let (root, nfs, vals, blinds, _sks, paths) = two_input_tree();
        // Replace input 0's key: its commitment no longer matches the tree.
        let bad_sks = vec![[0x99u8; 32], [7u8; 32]];
        let (opk0, opk1) = ([8u8; 32], [9u8; 32]);
        let (ob0, ob1) = ([10u8; 32], [11u8; 32]);
        let ocs = vec![v2_out_commit(opk0, 500, ob0), v2_out_commit(opk1, 500, ob1)];
        assert!(!synth_v2_transfer(TransferCircuitV2::with_witness(
            root,
            nfs,
            ocs,
            vals,
            blinds,
            bad_sks,
            paths,
            vec![500, 500],
            vec![ob0, ob1],
            vec![opk0, opk1],
            [0u8; 32],
        )));
    }

    // --- DepositCircuitV2 (spend-key construction, #293) ---

    fn synth_v2_deposit(c: DepositCircuitV2) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        match c.generate_constraints(cs.clone()) {
            Ok(()) => cs.is_satisfied().expect("constraint system query"),
            Err(_) => false,
        }
    }

    fn v2_deposit_commitment(
        value: u64,
        recipient_pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> [u8; 32] {
        fr_to_bytes_32(poseidon_commit_spend(
            Fr::from(value),
            Fr::from_le_bytes_mod_order(&recipient_pubkey),
            Fr::from_le_bytes_mod_order(&blinding),
            Fr::from(0u64),
        ))
    }

    #[test]
    fn deposit_v2_valid_commitment_satisfies() {
        let (value, opk, blinding) = (1_000u64, [8u8; 32], [3u8; 32]);
        let commitment = v2_deposit_commitment(value, opk, blinding);
        assert!(synth_v2_deposit(DepositCircuitV2::with_witness(
            commitment, value, blinding, opk, [0u8; 32],
        )));
    }

    #[test]
    fn deposit_v2_rejects_tampered_commitment() {
        assert!(!synth_v2_deposit(DepositCircuitV2::with_witness(
            [0xABu8; 32], // not the commitment of these witnesses
            1_000,
            [3u8; 32],
            [8u8; 32],
            [0u8; 32],
        )));
    }

    #[test]
    fn deposit_v2_rejects_value_not_matching_commitment() {
        // A commitment formed for value 1000, but the witness claims 2000 — the
        // recomputed commitment differs, so the note cannot be minted at an
        // amount other than the one it commits to.
        let (opk, blinding) = ([8u8; 32], [3u8; 32]);
        let commitment = v2_deposit_commitment(1_000, opk, blinding);
        assert!(!synth_v2_deposit(DepositCircuitV2::with_witness(
            commitment, 2_000, // wrong amount
            blinding, opk, [0u8; 32],
        )));
    }

    // ── TransactCircuitV3 (unified UTXO, circuit v3, #350) ──────────────────

    mod v3 {
        use super::*;
        use crate::privacy::poseidon_circom::{
            v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
        };
        use ark_ff::{BigInteger, PrimeField};

        fn fr_le(f: Fr) -> [u8; 32] {
            let mut out = [0u8; 32];
            let b = f.into_bigint().to_bytes_le();
            out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
            out
        }

        /// Empty-subtree hashes under the v3 Merkle hash: `z[0] = 0`,
        /// `z[k+1] = Poseidon(z[k], z[k])`.
        fn zeros() -> Vec<Fr> {
            let mut z = vec![Fr::from(0u64)];
            for k in 0..TX_LEVELS {
                z.push(v3_merkle_pair(z[k], z[k]));
            }
            z
        }

        /// Root and path for `leaf` placed at `index` in an otherwise-empty
        /// tree: every sibling on the path is a zero-subtree hash.
        fn member_root_and_path(leaf: Fr, index: u64) -> ([u8; 32], Vec<[u8; 32]>) {
            let z = zeros();
            let mut current = leaf;
            for (i, zi) in z.iter().enumerate().take(TX_LEVELS) {
                let bit = (index >> i) & 1;
                current = if bit == 0 {
                    v3_merkle_pair(current, *zi)
                } else {
                    v3_merkle_pair(*zi, current)
                };
            }
            let path = z[..TX_LEVELS].iter().map(|f| fr_le(*f)).collect();
            (fr_le(current), path)
        }

        struct InNote {
            amount: u64,
            privkey: Fr,
            blinding: Fr,
            index: u64,
        }
        struct OutNote {
            amount: u64,
            pubkey: Fr,
            blinding: Fr,
        }

        /// Build a valid circuit from input/output notes over one asset. Inputs
        /// with `amount == 0` are dummies (membership skipped); a single real
        /// input is placed in a fresh tree and `root` is its membership root.
        fn build(
            ins: [InNote; 2],
            outs: [OutNote; 2],
            asset: Fr,
            ext_data_hash: [u8; 32],
        ) -> TransactCircuitV3 {
            // Root: from the first real (non-zero) input, else an empty tree.
            let mut root = fr_le(*zeros().last().unwrap());
            let mut paths: Vec<Vec<[u8; 32]>> = Vec::new();
            let mut nullifiers = Vec::new();
            let mut sum_in = 0u128;
            for n in &ins {
                let pk = v3_pubkey(n.privkey);
                let c = v3_commit(Fr::from(n.amount), pk, n.blinding, asset);
                let sig = v3_signature(n.privkey, c, Fr::from(n.index));
                nullifiers.push(fr_le(v3_nullifier(c, Fr::from(n.index), sig)));
                if n.amount != 0 {
                    let (r, p) = member_root_and_path(c, n.index);
                    root = r;
                    paths.push(p);
                } else {
                    // Dummy: path is irrelevant (membership disabled); use zeros.
                    paths.push(zeros()[..TX_LEVELS].iter().map(|f| fr_le(*f)).collect());
                }
                sum_in += n.amount as u128;
            }
            let mut commitments = Vec::new();
            let mut sum_out = 0u128;
            for n in &outs {
                commitments.push(fr_le(v3_commit(
                    Fr::from(n.amount),
                    n.pubkey,
                    n.blinding,
                    asset,
                )));
                sum_out += n.amount as u128;
            }
            // public_amount = Σout − Σin (as a field element; negative wraps).
            let public_amount = Fr::from(sum_out) - Fr::from(sum_in);

            TransactCircuitV3 {
                root: Some(root),
                public_amount: Some(fr_le(public_amount)),
                ext_data_hash: Some(ext_data_hash),
                asset_id: Some(fr_le(asset)),
                input_nullifiers: nullifiers.into_iter().map(Some).collect(),
                output_commitments: commitments.into_iter().map(Some).collect(),
                in_amounts: ins.iter().map(|n| Some(n.amount)).collect(),
                in_privkeys: ins.iter().map(|n| Some(fr_le(n.privkey))).collect(),
                in_blindings: ins.iter().map(|n| Some(fr_le(n.blinding))).collect(),
                in_leaf_indices: ins.iter().map(|n| Some(n.index)).collect(),
                in_paths: paths.into_iter().map(Some).collect(),
                out_amounts: outs.iter().map(|n| Some(n.amount)).collect(),
                out_pubkeys: outs.iter().map(|n| Some(fr_le(n.pubkey))).collect(),
                out_blindings: outs.iter().map(|n| Some(fr_le(n.blinding))).collect(),
            }
        }

        fn synth(c: TransactCircuitV3) -> bool {
            let cs = ConstraintSystem::<Fr>::new_ref();
            match c.generate_constraints(cs.clone()) {
                Ok(()) => cs.is_satisfied().expect("cs query"),
                Err(_) => false,
            }
        }

        fn asset() -> Fr {
            Fr::from(0u64) // NATIVE_SOL
        }

        /// Deposit: two zero-amount dummy inputs, two real outputs summing to
        /// the deposit; `public_amount = +deposit`.
        #[test]
        fn deposit_satisfies() {
            let ins = [
                InNote {
                    amount: 0,
                    privkey: Fr::from(11u64),
                    blinding: Fr::from(1u64),
                    index: 0,
                },
                InNote {
                    amount: 0,
                    privkey: Fr::from(12u64),
                    blinding: Fr::from(2u64),
                    index: 0,
                },
            ];
            let outs = [
                OutNote {
                    amount: 700,
                    pubkey: v3_pubkey(Fr::from(21u64)),
                    blinding: Fr::from(5u64),
                },
                OutNote {
                    amount: 300,
                    pubkey: v3_pubkey(Fr::from(22u64)),
                    blinding: Fr::from(6u64),
                },
            ];
            assert!(synth(build(ins, outs, asset(), [7u8; 32])));
        }

        /// Withdrawal/transfer: one real input (member of a tree) + one dummy;
        /// outputs sum to less than the input, the rest withdrawn via a negative
        /// `public_amount`.
        #[test]
        fn spend_satisfies() {
            let ins = [
                InNote {
                    amount: 1000,
                    privkey: Fr::from(31u64),
                    blinding: Fr::from(3u64),
                    index: 5,
                },
                InNote {
                    amount: 0,
                    privkey: Fr::from(32u64),
                    blinding: Fr::from(4u64),
                    index: 0,
                },
            ];
            let outs = [
                OutNote {
                    amount: 250,
                    pubkey: v3_pubkey(Fr::from(41u64)),
                    blinding: Fr::from(7u64),
                },
                OutNote {
                    amount: 0,
                    pubkey: v3_pubkey(Fr::from(42u64)),
                    blinding: Fr::from(8u64),
                },
            ];
            // Σout = 250, Σin = 1000 → public_amount = −750 (withdraw 750).
            assert!(synth(build(ins, outs, asset(), [9u8; 32])));
        }

        /// An unbalanced transaction (outputs don't match inputs + public_amount)
        /// is rejected.
        #[test]
        fn rejects_unbalanced() {
            let mut c = build(
                [
                    InNote {
                        amount: 0,
                        privkey: Fr::from(1u64),
                        blinding: Fr::from(1u64),
                        index: 0,
                    },
                    InNote {
                        amount: 0,
                        privkey: Fr::from(2u64),
                        blinding: Fr::from(2u64),
                        index: 0,
                    },
                ],
                [
                    OutNote {
                        amount: 500,
                        pubkey: v3_pubkey(Fr::from(3u64)),
                        blinding: Fr::from(3u64),
                    },
                    OutNote {
                        amount: 500,
                        pubkey: v3_pubkey(Fr::from(4u64)),
                        blinding: Fr::from(4u64),
                    },
                ],
                asset(),
                [1u8; 32],
            );
            // Corrupt public_amount so Σin + public_amount ≠ Σout.
            c.public_amount = Some(fr_le(Fr::from(999u64)));
            assert!(!synth(c));
        }

        /// A tampered nullifier (not the one the note derives) is rejected.
        #[test]
        fn rejects_tampered_nullifier() {
            let mut c = build(
                [
                    InNote {
                        amount: 1000,
                        privkey: Fr::from(5u64),
                        blinding: Fr::from(5u64),
                        index: 2,
                    },
                    InNote {
                        amount: 0,
                        privkey: Fr::from(6u64),
                        blinding: Fr::from(6u64),
                        index: 0,
                    },
                ],
                [
                    OutNote {
                        amount: 1000,
                        pubkey: v3_pubkey(Fr::from(7u64)),
                        blinding: Fr::from(7u64),
                    },
                    OutNote {
                        amount: 0,
                        pubkey: v3_pubkey(Fr::from(8u64)),
                        blinding: Fr::from(8u64),
                    },
                ],
                asset(),
                [2u8; 32],
            );
            c.input_nullifiers[0] = Some([0xABu8; 32]);
            assert!(!synth(c));
        }

        /// Two identical input notes yield the same nullifier; the uniqueness
        /// constraint rejects the transaction (in-tx double spend).
        #[test]
        fn rejects_duplicate_nullifiers() {
            // Both inputs are the SAME note (same key/blinding/index) → identical
            // nullifiers. Build manually so both are real and equal.
            let sk = Fr::from(9u64);
            let bl = Fr::from(9u64);
            let a = asset();
            let pk = v3_pubkey(sk);
            let c0 = v3_commit(Fr::from(1000u64), pk, bl, a);
            let sig = v3_signature(sk, c0, Fr::from(3u64));
            let nf = fr_le(v3_nullifier(c0, Fr::from(3u64), sig));
            let (root, path) = member_root_and_path(c0, 3);
            let opk = v3_pubkey(Fr::from(10u64));
            let circuit = TransactCircuitV3 {
                root: Some(root),
                public_amount: Some(fr_le(Fr::from(0u64))), // Σin(2000) + pa = Σout(2000)
                ext_data_hash: Some([3u8; 32]),
                asset_id: Some(fr_le(a)),
                input_nullifiers: vec![Some(nf), Some(nf)],
                output_commitments: vec![
                    Some(fr_le(v3_commit(Fr::from(2000u64), opk, Fr::from(1u64), a))),
                    Some(fr_le(v3_commit(Fr::from(0u64), opk, Fr::from(2u64), a))),
                ],
                in_amounts: vec![Some(1000), Some(1000)],
                in_privkeys: vec![Some(fr_le(sk)), Some(fr_le(sk))],
                in_blindings: vec![Some(fr_le(bl)), Some(fr_le(bl))],
                in_leaf_indices: vec![Some(3), Some(3)],
                in_paths: vec![Some(path.clone()), Some(path)],
                out_amounts: vec![Some(2000), Some(0)],
                out_pubkeys: vec![Some(fr_le(opk)), Some(fr_le(opk))],
                out_blindings: vec![Some(fr_le(Fr::from(1u64))), Some(fr_le(Fr::from(2u64)))],
            };
            assert!(!synth(circuit));
        }

        /// A real input whose commitment is not in the tree (wrong root) fails
        /// membership.
        #[test]
        fn rejects_non_member() {
            let mut c = build(
                [
                    InNote {
                        amount: 1000,
                        privkey: Fr::from(13u64),
                        blinding: Fr::from(13u64),
                        index: 1,
                    },
                    InNote {
                        amount: 0,
                        privkey: Fr::from(14u64),
                        blinding: Fr::from(14u64),
                        index: 0,
                    },
                ],
                [
                    OutNote {
                        amount: 1000,
                        pubkey: v3_pubkey(Fr::from(15u64)),
                        blinding: Fr::from(9u64),
                    },
                    OutNote {
                        amount: 0,
                        pubkey: v3_pubkey(Fr::from(16u64)),
                        blinding: Fr::from(10u64),
                    },
                ],
                asset(),
                [4u8; 32],
            );
            c.root = Some([0x55u8; 32]); // not the real membership root
            assert!(!synth(c));
        }

        /// Full Groth16 setup → prove → verify with the public-input vector in
        /// slice order, confirming the public wiring end to end.
        #[test]
        fn full_groth16_roundtrip() {
            use ark_std::rand::{rngs::StdRng, SeedableRng};
            let mut rng = StdRng::seed_from_u64(0x7A3C);

            let circuit = build(
                [
                    InNote {
                        amount: 1000,
                        privkey: Fr::from(51u64),
                        blinding: Fr::from(5u64),
                        index: 7,
                    },
                    InNote {
                        amount: 0,
                        privkey: Fr::from(52u64),
                        blinding: Fr::from(6u64),
                        index: 0,
                    },
                ],
                [
                    OutNote {
                        amount: 400,
                        pubkey: v3_pubkey(Fr::from(61u64)),
                        blinding: Fr::from(1u64),
                    },
                    OutNote {
                        amount: 100,
                        pubkey: v3_pubkey(Fr::from(62u64)),
                        blinding: Fr::from(2u64),
                    },
                ],
                asset(),
                [7u8; 32],
            );

            let (pk, vk) =
                Groth16ProofSystem::setup(TransactCircuitV3::blank(), &mut rng).expect("setup");
            let proof = Groth16ProofSystem::prove(&pk, circuit.clone(), &mut rng).expect("prove");

            let to_fr = |b: [u8; 32]| Fr::from_le_bytes_mod_order(&b);
            let public_inputs: Vec<Fr> = vec![
                to_fr(circuit.root.unwrap()),
                to_fr(circuit.public_amount.unwrap()),
                to_fr(circuit.ext_data_hash.unwrap()),
                to_fr(circuit.asset_id.unwrap()),
                to_fr(circuit.input_nullifiers[0].unwrap()),
                to_fr(circuit.input_nullifiers[1].unwrap()),
                to_fr(circuit.output_commitments[0].unwrap()),
                to_fr(circuit.output_commitments[1].unwrap()),
            ];
            assert!(Groth16ProofSystem::verify(&vk, &public_inputs, &proof).expect("verify"));

            // A wrong public input (tampered root) must fail verification.
            let mut bad = public_inputs.clone();
            bad[0] = Fr::from(123u64);
            assert!(!Groth16ProofSystem::verify(&vk, &bad, &proof).expect("verify"));
        }
    }
}
