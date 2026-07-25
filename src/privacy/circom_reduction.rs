//! The R1CS-to-QAP reduction snarkjs uses, needed to prove with a
//! ceremony-produced key.
//!
//! circom prepares the powers of tau in Lagrange basis rather than the
//! monomial basis arkworks assumes, so a key produced by `snarkjs groth16
//! setup` represents different values in the same struct. Proving with it
//! requires the matching witness map: arkworks computes `H` as the
//! coefficients of `(AB - C)/Z`, while snarkjs takes the odd coefficients of
//! `(AB - C)` in a domain twice as large, which serves as `HZ` in the `C`
//! proof element. Feeding a circom key to arkworks' default reduction yields
//! proofs that simply do not verify.
//!
//! Verification is unaffected — it is pairings against the verifying key and
//! knows nothing about how `H` was derived — so the on-chain verifier and
//! `transact_vk_data.rs` are untouched by which reduction the prover uses.
//!
//! Vendored from `worldcoin-ark-circom` (MIT OR Apache-2.0), the arkworks-0.4
//! line of `arkworks-rs/circom-compat`, rather than taken as a dependency:
//! the published crates target arkworks 0.5 or pull `wasmer` in
//! non-optionally for circom witness generation we do not use, and the wasm
//! prover cannot carry that.
//!
//! One deviation from the source: it drives its loops through ark-std's
//! `cfg_iter!` family, which switches on a `parallel` feature this crate does
//! not define, so they always expanded to the serial form and only served to
//! trip `unexpected_cfgs`. They are written out as plain iterators here — the
//! same code the macros produced.

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{evaluate_constraint, LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef, SynthesisError};

/// Witness map matching snarkjs, for keys produced by `snarkjs groth16 setup`.
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        a[..num_constraints]
            .iter_mut()
            .zip(b[..num_constraints].iter_mut())
            .zip(matrices.a.iter())
            .zip(matrices.b.iter())
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = evaluate_constraint(at_i, full_assignment);
                *b = evaluate_constraint(bt_i, full_assignment);
            });

        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        let mut c = vec![zero; domain_size];
        c[..num_constraints]
            .iter_mut()
            .zip(&a)
            .zip(&b)
            .for_each(|((c_i, &a), &b)| {
                *c_i = a * b;
            });

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        let root_of_unity = {
            let domain_size_double = 2 * domain_size;
            let domain_double =
                D::new(domain_size_double).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());

        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        ab.iter_mut().zip(c).for_each(|(ab_i, c_i)| *ab_i -= &c_i);

        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // The usual H query has domain-1 powers and Z has domain powers, so
        // HZ has 2*domain-1.
        let mut scalars = (0..2 * max_power + 1)
            .map(|i| delta_inverse * t.pow([i as u64]))
            .collect::<Vec<_>>();
        let domain_size = scalars.len();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        domain.ifft_in_place(&mut scalars);
        Ok(scalars.into_iter().skip(1).step_by(2).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::circuits::{TransactCircuitV3, TX_LEVELS};
    use crate::privacy::poseidon_circom::{
        v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
    };
    use ark_bn254::{Bn254, Fr};
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::{Groth16, ProvingKey};
    use ark_serialize::CanonicalDeserialize;
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn fr_to_le(f: &Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        let le = f.into_bigint().to_bytes_le();
        out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out
    }

    fn zeros() -> Vec<Fr> {
        let mut z = vec![Fr::from(0u64)];
        for k in 0..TX_LEVELS {
            z.push(v3_merkle_pair(z[k], z[k]));
        }
        z
    }

    fn ext_data_hash(recipient: &[u8; 32], ext_amount: i64) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(recipient);
        h.update(ext_amount.to_le_bytes());
        h.finalize().into()
    }

    /// A satisfying spend: one 1000-unit input at leaf 0 plus a zero dummy,
    /// outputs 400 and 100, so 500 leaves the pool. Mirrors the fixture the
    /// on-chain tests use.
    fn spend() -> (TransactCircuitV3, Vec<Fr>) {
        let asset = Fr::from(0u64);
        let edh = ext_data_hash(&[3u8; 32], -500);

        let (sk0, bl0) = (Fr::from(51u64), Fr::from(5u64));
        let c0 = v3_commit(Fr::from(1000u64), v3_pubkey(sk0), bl0, asset);
        let nf0 = v3_nullifier(c0, Fr::from(0u64), v3_signature(sk0, c0, Fr::from(0u64)));

        let z = zeros();
        let mut root = c0;
        for zi in z.iter().take(TX_LEVELS) {
            root = v3_merkle_pair(root, *zi);
        }
        let path: Vec<[u8; 32]> = z[..TX_LEVELS].iter().map(fr_to_le).collect();

        let (sk1, bl1) = (Fr::from(52u64), Fr::from(6u64));
        let c1 = v3_commit(Fr::from(0u64), v3_pubkey(sk1), bl1, asset);
        let nf1 = v3_nullifier(c1, Fr::from(0u64), v3_signature(sk1, c1, Fr::from(0u64)));

        let (opk0, opk1) = (v3_pubkey(Fr::from(61u64)), v3_pubkey(Fr::from(62u64)));
        let (obl0, obl1) = (Fr::from(1u64), Fr::from(2u64));
        let oc0 = v3_commit(Fr::from(400u64), opk0, obl0, asset);
        let oc1 = v3_commit(Fr::from(100u64), opk1, obl1, asset);
        let public_amount = Fr::from(500u64) - Fr::from(1000u64);

        let circuit = TransactCircuitV3 {
            root: Some(fr_to_le(&root)),
            public_amount: Some(fr_to_le(&public_amount)),
            ext_data_hash: Some(edh),
            asset_id: Some(fr_to_le(&asset)),
            input_nullifiers: vec![Some(fr_to_le(&nf0)), Some(fr_to_le(&nf1))],
            output_commitments: vec![Some(fr_to_le(&oc0)), Some(fr_to_le(&oc1))],
            in_amounts: vec![Some(1000), Some(0)],
            in_privkeys: vec![Some(fr_to_le(&sk0)), Some(fr_to_le(&sk1))],
            in_blindings: vec![Some(fr_to_le(&bl0)), Some(fr_to_le(&bl1))],
            in_leaf_indices: vec![Some(0), Some(0)],
            in_paths: vec![Some(path.clone()), Some(path)],
            out_amounts: vec![Some(400), Some(100)],
            out_pubkeys: vec![Some(fr_to_le(&opk0)), Some(fr_to_le(&opk1))],
            out_blindings: vec![Some(fr_to_le(&obl0)), Some(fr_to_le(&obl1))],
        };

        let inputs = vec![
            root,
            public_amount,
            Fr::from_le_bytes_mod_order(&edh),
            asset,
            nf0,
            nf1,
            oc0,
            oc1,
        ];
        (circuit, inputs)
    }

    /// Proves the ceremony path end to end against a key snarkjs produced from
    /// the public powers-of-tau transcript (#659), and shows why the reduction
    /// has to change with it.
    ///
    /// Needs a converted key on disk, so it is opt-in:
    ///
    /// ```text
    /// cargo run --release --bin export_transact_v3_r1cs
    /// snarkjs groth16 setup artifacts/transact_v3.r1cs <ptau> artifacts/x.zkey
    /// snarkjs zkey export json artifacts/x.zkey artifacts/x.json
    /// cargo run --release --bin zkey_json_to_arkworks -- artifacts/x.json \
    ///   artifacts/transact_v3_ceremony_dryrun.key
    /// cargo test --lib circom_reduction -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "needs a snarkjs-produced key converted to arkworks; see the doc comment"]
    fn ceremony_key_proves_and_verifies_under_the_circom_reduction() {
        let path = std::env::var("TRANSACT_V3_CEREMONY_KEY")
            .unwrap_or_else(|_| "artifacts/transact_v3_ceremony_dryrun.key".to_string());
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&bytes[..]).expect("deserialise key");

        // Shape check first: a circom key carries domain-many h_query points,
        // where an arkworks-native key carries domain-1.
        assert_eq!(pk.h_query.len(), 32_768, "expected a circom-convention key");
        assert_eq!(pk.vk.gamma_abc_g1.len(), 9);

        let (circuit, inputs) = spend();
        let mut rng = StdRng::seed_from_u64(7);

        // Control: arkworks' own reduction against this key produces a proof
        // that does not verify. This is the failure the cutover has to avoid,
        // and it is loud rather than silent.
        let wrong = Groth16::<Bn254, LibsnarkReduction>::prove(&pk, circuit.clone(), &mut rng);
        if let Ok(proof) = wrong {
            assert!(
                !Groth16::<Bn254, LibsnarkReduction>::verify(&pk.vk, &inputs, &proof)
                    .expect("verify runs"),
                "the default reduction must not produce a valid proof for a circom key"
            );
        }

        // The real thing.
        let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit, &mut rng)
            .expect("proving with the ceremony key");
        assert!(
            Groth16::<Bn254, CircomReduction>::verify(&pk.vk, &inputs, &proof)
                .expect("verify runs"),
            "a ceremony-produced key must prove and verify our circuit"
        );
    }
}
