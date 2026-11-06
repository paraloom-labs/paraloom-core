//! Vendored Groth16 (BN254) verifier over Solana's `alt_bn128` syscalls.
//!
//! Source: <https://github.com/Lightprotocol/groth16-solana> (MIT), trimmed to
//! the verify path. Proofs are produced off-chain by the workspace prover in
//! the `alt_bn128` wire form (big-endian coordinates, G2 `c1`/`c0` ordering,
//! negated `proof_a`); this only checks them.
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};

#[derive(Debug, PartialEq, Eq)]
pub enum Groth16Error {
    InvalidPublicInputsLength,
    PublicInputGreaterThanFieldSize,
    PreparingInputsG1MulFailed,
    PreparingInputsG1AdditionFailed,
    ProofVerificationFailed,
}

pub struct Groth16Verifyingkey<'a> {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamme_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: &'a [[u8; 64]],
}

pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    public_inputs: &'a [[u8; 32]; NR_INPUTS],
    prepared_public_inputs: [u8; 64],
    verifyingkey: &'a Groth16Verifyingkey<'a>,
}

impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16Verifyingkey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        if verifyingkey.vk_ic.is_empty()
            || verifyingkey.nr_pubinputs != public_inputs.len()
            || public_inputs.len().checked_add(1) != Some(verifyingkey.vk_ic.len())
        {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }
        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
        })
    }

    fn prepare_inputs(&mut self) -> Result<(), Groth16Error> {
        let mut prepared = self.verifyingkey.vk_ic[0];
        for (i, input) in self.public_inputs.iter().enumerate() {
            if !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThanFieldSize);
            }
            let mul_res = alt_bn128_multiplication(
                &[&self.verifyingkey.vk_ic[i + 1][..], &input[..]].concat(),
            )
            .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
            prepared = alt_bn128_addition(&[&mul_res[..], &prepared[..]].concat())
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }
        self.prepared_public_inputs = prepared;
        Ok(())
    }

    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_inputs()?;
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifyingkey.vk_gamme_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifyingkey.vk_delta_g2.as_slice(),
            self.verifyingkey.vk_alpha_g1.as_slice(),
            self.verifyingkey.vk_beta_g2.as_slice(),
        ]
        .concat();
        let res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;
        if res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(true)
    }
}

fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    BigUint::from_bytes_be(bytes) < Fr::MODULUS.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groth16_verifier_new_rejects_empty_or_mismatched_vk_ic() {
        let proof_a = [0u8; 64];
        let proof_b = [0u8; 128];
        let proof_c = [0u8; 64];
        let public_inputs: [[u8; 32]; 2] = [[1u8; 32], [2u8; 32]];

        let empty_vk = Groth16Verifyingkey {
            nr_pubinputs: 2,
            vk_alpha_g1: [0u8; 64],
            vk_beta_g2: [0u8; 128],
            vk_gamme_g2: [0u8; 128],
            vk_delta_g2: [0u8; 128],
            vk_ic: &[],
        };
        assert_eq!(
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, &empty_vk).err(),
            Some(Groth16Error::InvalidPublicInputsLength)
        );

        let dummy_ic = [[0u8; 64]; 3];
        let mismatched_nr_vk = Groth16Verifyingkey {
            nr_pubinputs: 1,
            vk_alpha_g1: [0u8; 64],
            vk_beta_g2: [0u8; 128],
            vk_gamme_g2: [0u8; 128],
            vk_delta_g2: [0u8; 128],
            vk_ic: &dummy_ic,
        };
        assert_eq!(
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, &mismatched_nr_vk).err(),
            Some(Groth16Error::InvalidPublicInputsLength)
        );

        let wrong_ic_len = [[0u8; 64]; 2];
        let mismatched_ic_vk = Groth16Verifyingkey {
            nr_pubinputs: 2,
            vk_alpha_g1: [0u8; 64],
            vk_beta_g2: [0u8; 128],
            vk_gamme_g2: [0u8; 128],
            vk_delta_g2: [0u8; 128],
            vk_ic: &wrong_ic_len,
        };
        assert_eq!(
            Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, &mismatched_ic_vk).err(),
            Some(Groth16Error::InvalidPublicInputsLength)
        );

        let valid_vk = Groth16Verifyingkey {
            nr_pubinputs: 2,
            vk_alpha_g1: [0u8; 64],
            vk_beta_g2: [0u8; 128],
            vk_gamme_g2: [0u8; 128],
            vk_delta_g2: [0u8; 128],
            vk_ic: &dummy_ic,
        };
        assert!(Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, &valid_vk).is_ok());
    }
}
