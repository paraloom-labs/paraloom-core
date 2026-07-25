//! Demonstration: a phase-2 chain does not neutralise the phase-1 trapdoor.
//!
//! [`apply_contribution`](super::apply_contribution) re-randomises `δ` and
//! nothing else. `α`, `β` and every element derived from `τ` are carried
//! through untouched — [`verify_final_pk_consistency`](super::verify_final_pk_consistency)
//! in fact *requires* them to be byte-identical. That is exactly what phase 2
//! is, but it means a party holding the phase-1 trapdoor can still forge
//! proofs no matter how many contributors join the chain.
//!
//! The module states that as an executable fact rather than a claim: it runs
//! a setup while keeping the trapdoor, forges a proof for a statement with no
//! witness, applies three real contributions, and forges again — the second
//! time using only the phase-1 secrets and the contributed key, which is
//! public.
//!
//! ## Why no `δ_i` is needed
//!
//! Groth16 verification is
//!
//! ```text
//! e(A, B) = e(αG₁, βG₂) · e(IC, γG₂) · e(C, δG₂)
//! ```
//!
//! so for freely chosen `A = rG₁` and `B = sG₂` the proof verifies for *any*
//! public input as long as
//!
//! ```text
//! C = ((r·s − α·β − IC·γ) / δ) · G₁
//! ```
//!
//! `δ` is secret after the chain runs, but the proving key publishes
//! `h_query[0] = (t(τ)/δ)·G₁`. Scaling that single public point by
//! `(r·s − α·β − IC·γ) / t(τ)` lands exactly on `C`. Everything else the
//! forger needs — `α`, `β`, `γ`, and the QAP evaluations at `τ` — is phase-1
//! material that the contributions never touch.
//!
//! The conclusion is not that our chain was run badly. It is that a phase-2
//! chain is only worth what its initial SRS is worth, which is why the
//! mainnet ceremony has to start from a public powers-of-tau file rather than
//! from a key generated on one machine (#659).

use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::lc;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use super::apply_contribution;

/// `x · x = y`, with `y` the only public input. Small enough that the whole
/// demonstration runs in milliseconds; the property under test belongs to the
/// ceremony construction, not to any particular circuit.
#[derive(Clone)]
struct SquareCircuit {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + y)?;
        Ok(())
    }
}

/// What the initial-SRS producer learns and is trusted to destroy.
struct Phase1Trapdoor {
    alpha: Fr,
    beta: Fr,
    gamma: Fr,
    /// `u_i(τ)`, `v_i(τ)`, `w_i(τ)` — recoverable by anyone holding `τ`,
    /// since the circuit is public.
    u: Vec<Fr>,
    v: Vec<Fr>,
    w: Vec<Fr>,
    /// `t(τ)`, the vanishing polynomial at `τ`.
    zt: Fr,
}

/// Seed for the setup rng. `generate_parameters_with_qap` draws exactly one
/// value from it — `τ` — so replaying the seed against the same evaluation
/// domain recovers the trapdoor an honest operator would have destroyed.
const SETUP_SEED: u64 = 0xF00D;

fn setup_keeping_the_trapdoor() -> (ProvingKey<Bn254>, Phase1Trapdoor) {
    let mut waste = StdRng::seed_from_u64(1);
    let alpha = Fr::rand(&mut waste);
    let beta = Fr::rand(&mut waste);
    let gamma = Fr::rand(&mut waste);
    let delta = Fr::rand(&mut waste);

    // Synthesise the shape once to learn the domain the generator will build,
    // then recover τ from it.
    let shape = SquareCircuit { x: None, y: None };
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    shape
        .clone()
        .generate_constraints(cs.clone())
        .expect("shape synthesises");
    cs.finalize();
    let domain_size = cs.num_constraints() + cs.num_instance_variables();
    let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).expect("domain exists");
    let tau = domain.sample_element_outside_domain(&mut StdRng::seed_from_u64(SETUP_SEED));

    let (u, v, w, zt, _, _) = LibsnarkReduction::instance_map_with_evaluation::<
        Fr,
        GeneralEvaluationDomain<Fr>,
    >(cs, &tau)
    .expect("QAP instance map");

    let pk = Groth16::<Bn254>::generate_parameters_with_qap(
        shape,
        alpha,
        beta,
        gamma,
        delta,
        G1Projective::generator(),
        G2Projective::generator(),
        &mut StdRng::seed_from_u64(SETUP_SEED),
    )
    .expect("setup succeeds");

    (
        pk,
        Phase1Trapdoor {
            alpha,
            beta,
            gamma,
            u,
            v,
            w,
            zt,
        },
    )
}

/// Produce a verifying proof for `public_input` without a witness, using only
/// the phase-1 trapdoor and the (public) proving key.
fn forge(pk: &ProvingKey<Bn254>, public_input: Fr, td: &Phase1Trapdoor, seed: u64) -> Proof<Bn254> {
    let mut rng = StdRng::seed_from_u64(seed);
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // IC = Σ pubᵢ·(β·uᵢ(τ) + α·vᵢ(τ) + wᵢ(τ))/γ, with the constant-one wire
    // first — the same combination the verifier builds from gamma_abc_g1.
    let gamma_inv = td.gamma.inverse().expect("gamma is non-zero");
    let assignment = [Fr::one(), public_input];
    let mut ic = Fr::zero();
    for (i, value) in assignment.iter().enumerate() {
        ic += *value * ((td.beta * td.u[i] + td.alpha * td.v[i] + td.w[i]) * gamma_inv);
    }

    // The one term that involves δ, obtained from a public key element:
    // h_query[0] = (t(τ)/δ)·G₁, so scaling it by k/t(τ) yields (k/δ)·G₁.
    let k = r * s - td.alpha * td.beta - ic * td.gamma;
    let c = pk.h_query[0] * (k * td.zt.inverse().expect("t(τ) is non-zero"));

    Proof {
        a: (G1Projective::generator() * r).into_affine(),
        b: (G2Projective::generator() * s).into_affine(),
        c: c.into_affine(),
    }
}

fn contribute_n(pk: &mut ProvingKey<Bn254>, n: usize, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    for _ in 0..n {
        let delta_i = Fr::rand(&mut rng);
        apply_contribution(pk, delta_i, &mut rng).expect("contribution applies");
    }
}

#[test]
fn phase2_contributions_do_not_close_the_phase1_trapdoor() {
    let (initial_pk, trapdoor) = setup_keeping_the_trapdoor();

    // A statement with no witness at all: a quadratic non-residue has no
    // square root, so no `x` satisfies `x · x = y`.
    let false_y = (2u64..64)
        .map(Fr::from)
        .find(|y| y.sqrt().is_none())
        .expect("a small non-residue exists");

    let forged = forge(&initial_pk, false_y, &trapdoor, 42);
    assert!(
        Groth16::<Bn254>::verify(&initial_pk.vk, &[false_y], &forged).expect("verify runs"),
        "the trapdoor holder forges against the initial key"
    );

    // Three contributions, applied exactly the way a contributor applies one.
    let mut pk = initial_pk.clone();
    contribute_n(&mut pk, 3, 99);

    // The chain moved δ...
    assert_ne!(
        pk.vk.delta_g2, initial_pk.vk.delta_g2,
        "contributions must re-randomise delta"
    );
    // ...and left every element the phase-1 trapdoor produced untouched.
    assert_eq!(pk.vk.alpha_g1, initial_pk.vk.alpha_g1);
    assert_eq!(pk.vk.beta_g2, initial_pk.vk.beta_g2);
    assert_eq!(pk.vk.gamma_g2, initial_pk.vk.gamma_g2);
    assert_eq!(pk.vk.gamma_abc_g1, initial_pk.vk.gamma_abc_g1);
    assert_eq!(pk.a_query, initial_pk.a_query);
    assert_eq!(pk.b_g1_query, initial_pk.b_g1_query);
    assert_eq!(pk.b_g2_query, initial_pk.b_g2_query);

    // The same trapdoor forges against the contributed key. No δ_i was used
    // here — only phase-1 secrets and public key material.
    let forged_after = forge(&pk, false_y, &trapdoor, 43);
    assert!(
        Groth16::<Bn254>::verify(&pk.vk, &[false_y], &forged_after).expect("verify runs"),
        "three honest contributions did not close the phase-1 trapdoor"
    );
}

#[test]
fn contributed_key_still_proves_true_statements() {
    // Guards the demonstration itself: the forgery above must be a real
    // forgery against a working key, not an artefact of a key the
    // contributions broke.
    let (mut pk, _trapdoor) = setup_keeping_the_trapdoor();
    contribute_n(&mut pk, 3, 7);

    let x = Fr::from(9u64);
    let y = x * x;
    let mut rng = StdRng::seed_from_u64(5);
    let proof = Groth16::<Bn254>::prove(
        &pk,
        SquareCircuit {
            x: Some(x),
            y: Some(y),
        },
        &mut rng,
    )
    .expect("honest proving succeeds");

    assert!(
        Groth16::<Bn254>::verify(&pk.vk, &[y], &proof).expect("verify runs"),
        "the contributed key must still verify honest proofs"
    );
}
