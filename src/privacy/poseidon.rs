//! Poseidon-style hash implementation for zkSNARK circuits
//!
//! Current implementation uses SHA-256 based hashing for MVP/testnet.
//! Production version will use proper Poseidon zkSNARK-friendly hash.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use sha2::{Digest, Sha256};

/// Hash arbitrary data (outside circuit)
pub fn poseidon_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
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
    let mut bytes = vec![0u8; 32];
    let bigint = input.into_bigint();
    for (i, byte) in bigint.to_bytes_le().iter().enumerate() {
        if i < 32 {
            bytes[i] = *byte;
        }
    }

    let hash = poseidon_hash(&bytes);
    Fr::from_le_bytes_mod_order(&hash)
}

/// Hash multiple field elements
pub fn poseidon_hash_fields(inputs: &[Fr]) -> Fr {
    let mut hasher = Sha256::new();
    for input in inputs {
        let bigint = input.into_bigint();
        hasher.update(bigint.to_bytes_le());
    }
    let hash = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash[..])
}

/// Poseidon hash gadget for use inside zkSNARK circuits
pub fn poseidon_hash_gadget(
    _cs: ConstraintSystemRef<Fr>,
    data: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    // Simplified hash for circuits: linear combination
    // This is NOT cryptographically secure but allows testing
    // Production MUST use proper Poseidon permutation

    if data.is_empty() {
        return Ok(FpVar::constant(Fr::from(0u64)));
    }

    let mut result = data[0].clone();
    for (i, var) in data.iter().enumerate().skip(1) {
        let coefficient = Fr::from((i + 1) as u64);
        result = &result + &(var * coefficient);
    }

    Ok(result)
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

        // SHA-256 has good avalanche effect
        assert!(diff_bits > 64, "Insufficient avalanche effect");
    }
}
