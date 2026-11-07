//! Regression tests for #1277: Soundness and validation gaps in ceremony cutover pipeline.
//!
//! Validates:
//! 1. `r1cs_export::write_r1cs`: rejects instance wire count < 1, row mismatches, and out-of-bounds wire indices.
//! 2. `circom_reduction::CircomReduction`: enforces input length bounds, constraint matrix dimension consistency, and checked scalar powers.

use ark_bn254::Fr;
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, SynthesisError};
use paraloom::privacy::circom_reduction::CircomReduction;
use paraloom::privacy::r1cs_export::write_r1cs;
use std::io;

#[test]
fn test_write_r1cs_rejects_zero_instance_variables() {
    let matrices = ConstraintMatrices {
        num_instance_variables: 0,
        num_witness_variables: 1,
        num_constraints: 1,
        a_num_non_zero: 0,
        b_num_non_zero: 0,
        c_num_non_zero: 0,
        a: vec![vec![]],
        b: vec![vec![]],
        c: vec![vec![]],
    };
    let mut out = Vec::new();
    let err = write_r1cs(&mut out, &matrices).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err
        .to_string()
        .contains("num_instance_variables must be >= 1"));
}

#[test]
fn test_write_r1cs_rejects_out_of_bounds_wire_indices() {
    let matrices = ConstraintMatrices {
        num_instance_variables: 1,
        num_witness_variables: 1,
        num_constraints: 1,
        a_num_non_zero: 1,
        b_num_non_zero: 0,
        c_num_non_zero: 0,
        a: vec![vec![(Fr::from(1u64), 99)]], // wire 99 >= num_wires 2
        b: vec![vec![]],
        c: vec![vec![]],
    };
    let mut out = Vec::new();
    let err = write_r1cs(&mut out, &matrices).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("out of range"));
}

#[test]
fn test_circom_reduction_missing_assignment_returns_error() {
    let matrices = ConstraintMatrices {
        num_instance_variables: 3,
        num_witness_variables: 1,
        num_constraints: 1,
        a_num_non_zero: 0,
        b_num_non_zero: 0,
        c_num_non_zero: 0,
        a: vec![vec![]],
        b: vec![vec![]],
        c: vec![vec![]],
    };
    // full_assignment has only 1 element, but num_inputs is 3
    let res = CircomReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &matrices,
        3,
        1,
        &[Fr::from(1u64)],
    );
    match res {
        Err(SynthesisError::AssignmentMissing) => {}
        other => panic!("expected AssignmentMissing, got {:?}", other),
    }
}

#[test]
fn test_circom_reduction_matrix_dimension_mismatch_returns_unsatisfiable() {
    let matrices = ConstraintMatrices {
        num_instance_variables: 1,
        num_witness_variables: 1,
        num_constraints: 2,
        a_num_non_zero: 0,
        b_num_non_zero: 0,
        c_num_non_zero: 0,
        a: vec![vec![]], // len 1 != num_constraints 2
        b: vec![vec![], vec![]],
        c: vec![vec![], vec![]],
    };
    let res = CircomReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
        &matrices,
        1,
        2,
        &[Fr::from(1u64)],
    );
    match res {
        Err(SynthesisError::Unsatisfiable) => {}
        other => panic!("expected Unsatisfiable, got {:?}", other),
    }
}
