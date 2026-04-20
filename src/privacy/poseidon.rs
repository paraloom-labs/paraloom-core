//! Poseidon hash implementation for zkSNARK circuits
//!
//! Production-grade implementation using Poseidon permutation.
//! Poseidon is a zkSNARK-friendly hash function designed for efficiency in circuits.
//!
//! # Parameter set
//!
//! See [`params`] for the frozen parameter constants and their provenance.
//! The set is Poseidon-128 over BLS12-381 `Fr`, S-box x^5, t=3 (rate=2,
//! capacity=1), R_F=8, R_P=57 — standard 128-bit security per Grassi et al.
//! (Poseidon paper §5.4, Table 2).

use ark_bls12_381::Fr;
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
/// - Field: BLS12-381 scalar field `Fr` (255-bit prime).
/// - Matches arkworks' reference parameters via
///   `find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 57, 0)`.
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
        let out = poseidon_hash_gadget(cs.clone(), &vars)
            .expect("gadget synthesis failed");
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
        // `Poseidon([1, 0])` must not equal `Poseidon([1])` — the
        // sponge capacity separates arities. This is a sanity check
        // against accidental padding that collapses distinct inputs.
        let h1 = poseidon_hash_fields(&[Fr::from(1u64)]);
        let h2 = poseidon_hash_fields(&[Fr::from(1u64), Fr::from(0u64)]);
        assert_ne!(
            h1, h2,
            "different arities must produce different digests"
        );
    }
}
