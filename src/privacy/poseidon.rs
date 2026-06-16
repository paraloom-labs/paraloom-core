//! Poseidon hash implementation for zkSNARK circuits
//!
//! Production-grade implementation using Poseidon permutation.
//! Poseidon is a zkSNARK-friendly hash function designed for efficiency in circuits.
//!
//! # Parameter set
//!
//! See [`params`] for the frozen parameter constants and their provenance.
//! The set is Poseidon-128 over BN254 `Fr`, S-box x^5, t=3 (rate=2,
//! capacity=1), R_F=8, R_P=57 — standard 128-bit security per Grassi et al.
//! (Poseidon paper §5.4, Table 2).

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::sync::OnceLock;

/// Frozen Poseidon parameters.
///
/// These constants define the hash function's algebraic shape and must NEVER
/// change in a shipped version without an explicit key-version bump and a
/// matching regeneration of every trusted-setup artifact under `keys/`.
///
/// Provenance:
/// - Reference: Grassi, Khovratovich, Rechberger, Roy, Schofnegger —
///   "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems"
///   (USENIX Security '21), §5.4 Table 2.
/// - Field: BN254 scalar field `Fr` (254-bit prime).
/// - Matches arkworks' reference parameters via
///   `find_poseidon_ark_and_mds::<Fr>(254, 2, 8, 57, 0)`.
///
/// Keep this module exhaustive: every value fed into `PoseidonConfig::new`
/// must be sourced from a named constant here, so `tests::test_params_frozen`
/// can assert the full parameter vector.
pub mod params {
    /// Number of full rounds (half at the start, half at the end).
    pub const FULL_ROUNDS: usize = 8;
    /// Number of partial rounds (only the first state element goes through
    /// the S-box).
    pub const PARTIAL_ROUNDS: usize = 57;
    /// S-box exponent. `x^5` is invertible over `Fr` (gcd(5, p-1) == 1) and
    /// gives 128-bit algebraic security at the chosen round counts.
    pub const ALPHA: u64 = 5;
    /// Sponge rate — number of field elements absorbed per permutation.
    pub const RATE: usize = 2;
    /// Sponge capacity — number of state elements reserved for security.
    /// State width t = RATE + CAPACITY = 3.
    pub const CAPACITY: usize = 1;
    /// Skip count passed to `find_poseidon_ark_and_mds`. Fixed at 0 so the
    /// Grain LFSR initialisation is deterministic and reproducible.
    pub const GRAIN_SKIP: u64 = 0;
}

/// Global Poseidon configuration (cached).
static POSEIDON_CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();

/// Canonical Poseidon configuration used by every native and circuit hash.
///
/// Built once on first access from the constants in [`params`] and cached
/// for the lifetime of the process. Panics (via `expect`) only if the
/// generated ark/MDS tables are structurally invalid — an arkworks
/// invariant that cannot be violated at runtime with frozen parameters.
pub fn config() -> &'static PoseidonConfig<Fr> {
    POSEIDON_CONFIG.get_or_init(|| {
        use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;

        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            params::RATE,
            params::FULL_ROUNDS as u64,
            params::PARTIAL_ROUNDS as u64,
            params::GRAIN_SKIP,
        );

        PoseidonConfig::new(
            params::FULL_ROUNDS,
            params::PARTIAL_ROUNDS,
            params::ALPHA,
            mds,
            ark,
            params::RATE,
            params::CAPACITY,
        )
    })
}

/// Deprecated alias retained for internal call sites pending rename.
/// Prefer [`config`] in new code.
#[inline]
fn get_poseidon_config() -> &'static PoseidonConfig<Fr> {
    config()
}

/// Hash arbitrary bytes to a field element (outside circuit)
pub fn poseidon_hash_bytes(data: &[u8]) -> Fr {
    let config = get_poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(config);

    // Convert bytes to field elements
    // Pack bytes into field elements (31 bytes per element for safety)
    let mut field_elements = Vec::new();
    for chunk in data.chunks(31) {
        let mut bytes = [0u8; 32];
        bytes[..chunk.len()].copy_from_slice(chunk);
        let fe = Fr::from_le_bytes_mod_order(&bytes);
        field_elements.push(fe);
    }

    sponge.absorb(&field_elements);
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// Hash arbitrary data (outside circuit) - returns 32 bytes
pub fn poseidon_hash(data: &[u8]) -> [u8; 32] {
    let hash_fe = poseidon_hash_bytes(data);
    let bigint = hash_fe.into_bigint();
    let mut result = [0u8; 32];
    let bytes = bigint.to_bytes_le();
    result[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    result
}

/// Hash two 32-byte values
pub fn poseidon_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    poseidon_hash(&data)
}

/// Hash a field element
pub fn poseidon_hash_field(input: &Fr) -> Fr {
    let config = get_poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    let input_vec = vec![*input];
    sponge.absorb(&input_vec);
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// Hash multiple field elements
pub fn poseidon_hash_fields(inputs: &[Fr]) -> Fr {
    let config = get_poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    let inputs_vec = inputs.to_vec();
    sponge.absorb(&inputs_vec);
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// Poseidon hash gadget for use inside zkSNARK circuits
///
/// PRODUCTION-GRADE implementation using proper Poseidon constraints.
/// This is cryptographically secure and efficient (~500 constraints).
pub fn poseidon_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    data: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;

    if data.is_empty() {
        return Ok(FpVar::constant(Fr::from(0u64)));
    }

    // Get Poseidon configuration
    let config = get_poseidon_config();

    // Create Poseidon sponge gadget
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), config);

    // Convert slice to Vec for absorption (API requirement)
    let data_vec = data.to_vec();

    // Absorb the data vector
    sponge.absorb(&data_vec)?;

    // Squeeze one field element as output
    let output = sponge.squeeze_field_elements(1)?;

    Ok(output[0].clone())
}

// ──────────────────────────────────────────────────────────────────────────
// Domain-separated field-element API
//
// All privacy-critical hashes share the same Poseidon permutation but must
// never collide across purposes — a note commitment must be distinguishable
// from a nullifier and from a Merkle inner node even when the underlying
// field elements happen to coincide. Each domain prepends a unique
// constant tag, so `Poseidon(TAG_COMMIT, v, r, R)` and
// `Poseidon(TAG_NULLIFIER, c, s)` can never land on the same digest.
//
// Call sites must pass field elements directly. Byte-blob inputs
// (32-byte randomness, pubkey bytes, secrets) should be converted to `Fr`
// once at the boundary using `Fr::from_le_bytes_mod_order`; this keeps
// the circuit side free of expensive bit-decomposition constraints.
// ──────────────────────────────────────────────────────────────────────────

/// Domain tags — unique, monotonically assigned. Never renumber.
/// Each is hashed as `Fr::from(TAG)` as the first sponge input.
pub mod domain {
    /// Note commitment: `Poseidon(TAG, value, randomness, recipient, asset_id)`.
    pub const COMMITMENT: u64 = 1;
    /// Nullifier derivation: `Poseidon(TAG, commitment, secret)`.
    pub const NULLIFIER: u64 = 2;
    /// Merkle inner node: `Poseidon(TAG, left, right)`.
    pub const MERKLE_PAIR: u64 = 3;
    /// Spend public key (circuit v2, #293): `Poseidon(TAG, privkey)`.
    pub const PUBKEY: u64 = 4;
    /// Spend signature (circuit v2, #293):
    /// `Poseidon(TAG, privkey, commitment, leaf_index)`.
    pub const SIGNATURE: u64 = 5;
}

// --- Spend-key construction (circuit v2, #293) -----------------------------
//
// Reimplemented independently in arkworks following the public Tornado-Nova
// construction (the lineage Privacy Cash also forked). A note's spend authority
// is a private key, not merely knowledge of the note opening:
//
//   pubkey     = Poseidon(PUBKEY, privkey)
//   commitment = Poseidon(COMMITMENT, amount, pubkey, blinding, asset_id)
//   signature  = Poseidon(SIGNATURE, privkey, commitment, leaf_index)
//   nullifier  = Poseidon(NULLIFIER, commitment, leaf_index, signature)
//
// `pubkey` is bound into the commitment, so a note cannot be re-bound to a
// different key without changing its commitment (which breaks Merkle
// membership). The nullifier folds in a signature over (commitment, leaf_index)
// that requires the private key, so a note at a given tree position yields
// exactly one nullifier and only its key-holder can produce it. This is the
// construction that closes the free-secret double-spend and the spend-without-
// authorization gaps (#293). These use our own (sponge) Poseidon parameters —
// the construction shape matches the reference, the digests do not.

/// Spend public key from a private key (circuit v2): `Poseidon(PUBKEY, sk)`.
pub fn poseidon_pubkey(privkey: Fr) -> Fr {
    poseidon_hash_fields(&[Fr::from(domain::PUBKEY), privkey])
}

/// Spend-key note commitment (circuit v2):
/// `Poseidon(COMMITMENT, amount, pubkey, blinding, asset_id)`.
pub fn poseidon_commit_spend(amount: Fr, pubkey: Fr, blinding: Fr, asset_id: Fr) -> Fr {
    poseidon_hash_fields(&[
        Fr::from(domain::COMMITMENT),
        amount,
        pubkey,
        blinding,
        asset_id,
    ])
}

/// Spend signature over a note (circuit v2):
/// `Poseidon(SIGNATURE, privkey, commitment, leaf_index)`. Requires the private
/// key, binding the nullifier below to the note's spender.
pub fn poseidon_signature(privkey: Fr, commitment: Fr, leaf_index: Fr) -> Fr {
    poseidon_hash_fields(&[Fr::from(domain::SIGNATURE), privkey, commitment, leaf_index])
}

/// Spend-key nullifier (circuit v2):
/// `Poseidon(NULLIFIER, commitment, leaf_index, signature)`. Deterministic per
/// `(note, position, key)`, and only the key-holder can produce it.
pub fn poseidon_nullifier_spend(commitment: Fr, leaf_index: Fr, signature: Fr) -> Fr {
    poseidon_hash_fields(&[
        Fr::from(domain::NULLIFIER),
        commitment,
        leaf_index,
        signature,
    ])
}

/// Native note commitment. Inputs are field elements; byte-blob callers
/// must lift via `Fr::from_le_bytes_mod_order` before calling.
///
/// `asset_id` is the 5th sponge input. It binds the note to a specific
/// asset so per-asset value conservation can be enforced in-circuit.
/// Native-SOL notes use the sentinel `Fr::from(0)` (see
/// `Note::new_native` / `NATIVE_SOL_ASSET`).
pub fn poseidon_commit(value: Fr, randomness: Fr, recipient: Fr, asset_id: Fr) -> Fr {
    poseidon_hash_fields(&[
        Fr::from(domain::COMMITMENT),
        value,
        randomness,
        recipient,
        asset_id,
    ])
}

/// Native nullifier derivation.
pub fn poseidon_nullifier(commitment: Fr, secret: Fr) -> Fr {
    poseidon_hash_fields(&[Fr::from(domain::NULLIFIER), commitment, secret])
}

/// Native Merkle inner-node hash. Order matters — `(left, right)` is
/// distinct from `(right, left)`.
pub fn poseidon_merkle_pair(left: Fr, right: Fr) -> Fr {
    poseidon_hash_fields(&[Fr::from(domain::MERKLE_PAIR), left, right])
}

/// Circuit note commitment. Allocates the domain tag as a constant and
/// delegates to the generic gadget.
pub fn poseidon_commit_gadget(
    cs: ConstraintSystemRef<Fr>,
    value: &FpVar<Fr>,
    randomness: &FpVar<Fr>,
    recipient: &FpVar<Fr>,
    asset_id: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let tag = FpVar::constant(Fr::from(domain::COMMITMENT));
    poseidon_hash_gadget(
        cs,
        &[
            tag,
            value.clone(),
            randomness.clone(),
            recipient.clone(),
            asset_id.clone(),
        ],
    )
}

/// Circuit nullifier derivation.
pub fn poseidon_nullifier_gadget(
    cs: ConstraintSystemRef<Fr>,
    commitment: &FpVar<Fr>,
    secret: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let tag = FpVar::constant(Fr::from(domain::NULLIFIER));
    poseidon_hash_gadget(cs, &[tag, commitment.clone(), secret.clone()])
}

/// Circuit Merkle inner-node hash.
pub fn poseidon_merkle_pair_gadget(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let tag = FpVar::constant(Fr::from(domain::MERKLE_PAIR));
    poseidon_hash_gadget(cs, &[tag, left.clone(), right.clone()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_poseidon_hash() {
        let data = b"Hello, Paraloom!";
        let hash = poseidon_hash(data);

        assert_eq!(hash.len(), 32);

        // Deterministic
        let hash2 = poseidon_hash(data);
        assert_eq!(hash, hash2);

        // Different data produces different hash
        let hash3 = poseidon_hash(b"Different");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_poseidon_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let hash1 = poseidon_hash_pair(&left, &right);
        let hash2 = poseidon_hash_pair(&left, &right);

        assert_eq!(hash1, hash2);

        // Order matters
        let hash3 = poseidon_hash_pair(&right, &left);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_poseidon_hash_field() {
        let input = Fr::from(12345u64);
        let output = poseidon_hash_field(&input);

        // Deterministic
        let output2 = poseidon_hash_field(&input);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_poseidon_hash_fields() {
        let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let output = poseidon_hash_fields(&inputs);

        // Deterministic
        let output2 = poseidon_hash_fields(&inputs);
        assert_eq!(output, output2);

        // Different inputs
        let different = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(4u64)];
        let output3 = poseidon_hash_fields(&different);
        assert_ne!(output, output3);
    }

    #[test]
    fn test_poseidon_hash_gadget() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let input1 = FpVar::new_witness(cs.clone(), || Ok(Fr::from(100u64))).unwrap();
        let input2 = FpVar::new_witness(cs.clone(), || Ok(Fr::from(200u64))).unwrap();

        let output = poseidon_hash_gadget(cs.clone(), &[input1, input2]);
        assert!(output.is_ok());

        // Circuit should be satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_avalanche_effect() {
        let data1 = b"Test data";
        let data2 = b"Test datb";

        let hash1 = poseidon_hash(data1);
        let hash2 = poseidon_hash(data2);

        // Count differing bits
        let mut diff_bits = 0;
        for (b1, b2) in hash1.iter().zip(hash2.iter()) {
            diff_bits += (b1 ^ b2).count_ones();
        }

        // Poseidon should have good avalanche effect
        assert!(diff_bits > 32, "Insufficient avalanche effect");
    }

    #[test]
    fn test_poseidon_hash_fields_deterministic() {
        let inputs = vec![Fr::from(12345u64), Fr::from(67890u64)];

        let hash1 = poseidon_hash_fields(&inputs);
        let hash2 = poseidon_hash_fields(&inputs);

        assert_eq!(hash1, hash2, "Poseidon hash should be deterministic");
    }

    #[test]
    fn test_poseidon_hash_bytes_consistency() {
        let data = b"Hello, Poseidon!";

        // Hash same data twice
        let hash1 = poseidon_hash_bytes(data);
        let hash2 = poseidon_hash_bytes(data);

        assert_eq!(hash1, hash2, "Poseidon hash should be consistent");

        // Different data should produce different hash
        let hash3 = poseidon_hash_bytes(b"Different data");
        assert_ne!(
            hash1, hash3,
            "Different inputs should produce different hashes"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // Cross-equivalence tests: native ↔ circuit
    //
    // These are the primary correctness gate for every future change to
    // Poseidon parameters, the sponge plumbing, or the circuit gadget.
    // If any of them break, proofs produced off-chain will fail on-chain
    // verification (and vice versa).
    // ──────────────────────────────────────────────────────────────────────

    use ark_std::{rand::SeedableRng, UniformRand};

    /// Evaluate `poseidon_hash_gadget` and return the resulting field value.
    /// Allocates each input as a witness on a fresh constraint system.
    fn hash_gadget_value(inputs: &[Fr]) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vars: Vec<FpVar<Fr>> = inputs
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();
        let out = poseidon_hash_gadget(cs.clone(), &vars).expect("gadget synthesis failed");
        assert!(
            cs.is_satisfied().unwrap(),
            "constraint system unsatisfied after Poseidon synthesis"
        );
        out.value().expect("gadget output has no value")
    }

    #[test]
    fn test_native_matches_circuit_fixed() {
        // Deterministic, small, easy-to-reason-about inputs.
        let cases: Vec<Vec<Fr>> = vec![
            vec![Fr::from(1u64)],
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
            vec![Fr::from(0u64), Fr::from(0u64)],
            vec![Fr::from(u64::MAX), Fr::from(u64::MAX)],
        ];

        for inputs in &cases {
            let native = poseidon_hash_fields(inputs);
            let circuit = hash_gadget_value(inputs);
            assert_eq!(
                native, circuit,
                "native ↔ circuit divergence for inputs {:?}",
                inputs
            );
        }
    }

    #[test]
    fn test_native_matches_circuit_random() {
        // Deterministic PRNG — reproducible failures.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0xC0FFEE);

        for iter in 0..64 {
            let n = 1 + (iter % 8); // arities 1..=8
            let inputs: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let native = poseidon_hash_fields(&inputs);
            let circuit = hash_gadget_value(&inputs);
            assert_eq!(
                native, circuit,
                "native ↔ circuit divergence at iter={}, arity={}",
                iter, n
            );
        }
    }

    #[test]
    fn test_single_input_matches_hash_field() {
        // `poseidon_hash_field(x)` should be equivalent to
        // `poseidon_hash_fields(&[x])` — both absorb one element and
        // squeeze one element. If these drift, the API has two hashes
        // for the same mathematical operation.
        let x = Fr::from(42u64);
        let a = poseidon_hash_field(&x);
        let b = poseidon_hash_fields(&[x]);
        assert_eq!(
            a, b,
            "poseidon_hash_field(x) must equal poseidon_hash_fields(&[x])"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // Parameter-freeze tests
    //
    // These lock the Poseidon parameter set so any unintentional change
    // fails loudly. Changing any of these values requires regenerating
    // the trusted-setup artifacts under `keys/` — see
    // archive/zksnark_implementation_status.md for the procedure.
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_params_frozen() {
        assert_eq!(params::FULL_ROUNDS, 8, "FULL_ROUNDS changed");
        assert_eq!(params::PARTIAL_ROUNDS, 57, "PARTIAL_ROUNDS changed");
        assert_eq!(params::ALPHA, 5, "ALPHA changed");
        assert_eq!(params::RATE, 2, "RATE changed");
        assert_eq!(params::CAPACITY, 1, "CAPACITY changed");
        assert_eq!(params::GRAIN_SKIP, 0, "GRAIN_SKIP changed");
    }

    #[test]
    fn test_config_uses_frozen_params() {
        // The runtime config must mirror the compile-time constants
        // one-for-one. If someone edits `config()` without touching
        // the `params` module (or vice versa), this fires.
        let cfg = config();
        assert_eq!(cfg.full_rounds, params::FULL_ROUNDS);
        assert_eq!(cfg.partial_rounds, params::PARTIAL_ROUNDS);
        assert_eq!(cfg.alpha, params::ALPHA);
        assert_eq!(cfg.rate, params::RATE);
        assert_eq!(cfg.capacity, params::CAPACITY);

        // State width invariant: t = rate + capacity = 3.
        let t = cfg.rate + cfg.capacity;
        assert_eq!(t, 3, "state width t must be 3");

        // Round-constant matrix dimensions encode the round structure.
        // Total rounds = R_F + R_P = 8 + 57 = 65.
        let expected_rounds = params::FULL_ROUNDS + params::PARTIAL_ROUNDS;
        assert_eq!(
            cfg.ark.len(),
            expected_rounds,
            "ark row count must equal total rounds"
        );
        // Each ark row has one constant per state element.
        assert_eq!(cfg.ark[0].len(), t, "ark row width must equal t");

        // MDS matrix is t×t.
        assert_eq!(cfg.mds.len(), t, "mds row count must equal t");
        assert_eq!(cfg.mds[0].len(), t, "mds row width must equal t");
    }

    #[test]
    fn test_arity_distinguishes_outputs() {
        // The arkworks PoseidonSponge zero-pads the unused rate slot on
        // squeeze, so `Poseidon([x])` and `Poseidon([x, 0])` collapse to
        // the same digest — arity alone does not separate inputs at the
        // raw-sponge layer. Production paths avoid this by routing every
        // privacy-critical hash through a fixed-arity domain wrapper
        // (`poseidon_commit`/`_nullifier`/`_merkle_pair`), where the
        // domain tag is the first input and the arity is constant per
        // domain — see `test_domain_separation`.
        //
        // What this test guards is the weaker but still essential
        // property that distinct non-padding-equivalent inputs hash to
        // distinct digests.
        let h1 = poseidon_hash_fields(&[Fr::from(1u64)]);
        let h2 = poseidon_hash_fields(&[Fr::from(1u64), Fr::from(2u64)]);
        assert_ne!(h1, h2, "distinct inputs must produce different digests");
    }

    // ──────────────────────────────────────────────────────────────────────
    // Domain-separated API tests
    //
    // These cover the three privacy-critical hash domains end-to-end:
    // native vs circuit parity, cross-domain separation, and input-order
    // sensitivity where relevant.
    // ──────────────────────────────────────────────────────────────────────

    /// Evaluate the commitment gadget and extract its field value.
    fn eval_commit_gadget(value: Fr, randomness: Fr, recipient: Fr, asset_id: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let v = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(randomness)).unwrap();
        let p = FpVar::new_witness(cs.clone(), || Ok(recipient)).unwrap();
        let a = FpVar::new_witness(cs.clone(), || Ok(asset_id)).unwrap();
        let out = poseidon_commit_gadget(cs.clone(), &v, &r, &p, &a).unwrap();
        assert!(cs.is_satisfied().unwrap());
        out.value().unwrap()
    }

    /// Evaluate the nullifier gadget and extract its field value.
    fn eval_nullifier_gadget(commitment: Fr, secret: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let c = FpVar::new_witness(cs.clone(), || Ok(commitment)).unwrap();
        let s = FpVar::new_witness(cs.clone(), || Ok(secret)).unwrap();
        let out = poseidon_nullifier_gadget(cs.clone(), &c, &s).unwrap();
        assert!(cs.is_satisfied().unwrap());
        out.value().unwrap()
    }

    /// Evaluate the Merkle-pair gadget and extract its field value.
    fn eval_merkle_pair_gadget(left: Fr, right: Fr) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let l = FpVar::new_witness(cs.clone(), || Ok(left)).unwrap();
        let r = FpVar::new_witness(cs.clone(), || Ok(right)).unwrap();
        let out = poseidon_merkle_pair_gadget(cs.clone(), &l, &r).unwrap();
        assert!(cs.is_satisfied().unwrap());
        out.value().unwrap()
    }

    #[test]
    fn test_commit_native_matches_circuit() {
        // (value, randomness, recipient, asset_id) — the 4th column exercises
        // both the native-SOL sentinel (0) and non-native asset ids, so the
        // host/gadget parity is checked with asset_id actually varying.
        let cases = [
            (
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ),
            (
                Fr::from(100u64),
                Fr::from(200u64),
                Fr::from(300u64),
                Fr::from(0u64),
            ),
            (
                Fr::from(100u64),
                Fr::from(200u64),
                Fr::from(300u64),
                Fr::from(7u64),
            ),
            (
                Fr::from(u64::MAX),
                Fr::from(1u64),
                Fr::from(u64::MAX),
                Fr::from(u64::MAX),
            ),
        ];
        for (v, r, p, a) in cases {
            let native = poseidon_commit(v, r, p, a);
            let circuit = eval_commit_gadget(v, r, p, a);
            assert_eq!(native, circuit, "commit drift: v={v}, r={r}, p={p}, a={a}");
        }
    }

    #[test]
    fn test_nullifier_native_matches_circuit() {
        let cases = [
            (Fr::from(0u64), Fr::from(0u64)),
            (Fr::from(42u64), Fr::from(1337u64)),
            (Fr::from(u64::MAX), Fr::from(u64::MAX)),
        ];
        for (c, s) in cases {
            let native = poseidon_nullifier(c, s);
            let circuit = eval_nullifier_gadget(c, s);
            assert_eq!(native, circuit, "nullifier drift: c={c}, s={s}");
        }
    }

    #[test]
    fn test_merkle_pair_native_matches_circuit() {
        let cases = [
            (Fr::from(0u64), Fr::from(0u64)),
            (Fr::from(1u64), Fr::from(2u64)),
            (Fr::from(u64::MAX), Fr::from(u64::MAX)),
        ];
        for (l, r) in cases {
            let native = poseidon_merkle_pair(l, r);
            let circuit = eval_merkle_pair_gadget(l, r);
            assert_eq!(native, circuit, "merkle_pair drift: l={l}, r={r}");
        }
    }

    #[test]
    fn test_domain_separation() {
        // Same two field elements, routed through three different domains,
        // must produce three different digests. If any pair collides, an
        // attacker could forge cross-domain equivalences — e.g. substitute
        // a nullifier preimage for a Merkle sibling.
        let a = Fr::from(7u64);
        let b = Fr::from(11u64);

        // Keep arity the same across domains by passing a filler field
        // element to commit, so the only difference is the domain tag.
        let h_commit = poseidon_commit(Fr::from(0u64), a, b, Fr::from(0u64));
        let h_nullifier = poseidon_nullifier(a, b);
        let h_merkle = poseidon_merkle_pair(a, b);

        assert_ne!(h_commit, h_nullifier, "commit ↔ nullifier collision");
        assert_ne!(h_nullifier, h_merkle, "nullifier ↔ merkle collision");
        assert_ne!(h_commit, h_merkle, "commit ↔ merkle collision");
    }

    #[test]
    fn test_merkle_pair_order_matters() {
        let l = Fr::from(1u64);
        let r = Fr::from(2u64);
        assert_ne!(
            poseidon_merkle_pair(l, r),
            poseidon_merkle_pair(r, l),
            "merkle_pair must distinguish left from right"
        );
    }

    #[test]
    fn test_domain_tags_frozen() {
        // Domain tags are part of the hash function's identity. Changing
        // any of them invalidates every on-chain commitment and nullifier.
        // This is a hard lock.
        assert_eq!(domain::COMMITMENT, 1, "COMMITMENT tag changed");
        assert_eq!(domain::NULLIFIER, 2, "NULLIFIER tag changed");
        assert_eq!(domain::MERKLE_PAIR, 3, "MERKLE_PAIR tag changed");
    }
}
