//! Write an arkworks constraint system out in circom's `.r1cs` binary format.
//!
//! The mainnet ceremony starts from a public powers-of-tau transcript, and the
//! tooling that turns one into a circuit-specific proving key — `snarkjs
//! groth16 setup`, `zkey contribute`, `zkey verify` — speaks circom's R1CS
//! format. Our circuits are arkworks, so this is the adapter. Exporting also
//! makes the result publicly checkable: anyone can run
//! `snarkjs zkey verify <r1cs> <ptau> <zkey>` and confirm the finalized key
//! derives from the public transcript and this exact constraint system.
//!
//! ## Wire numbering
//!
//! No renumbering is needed. arkworks maps `Variable::One` to index 0,
//! `Variable::Instance(i)` to `i`, and `Variable::Witness(i)` to
//! `num_instance_variables + i` (`ark_relations::r1cs::Variable::
//! get_index_unchecked`). circom numbers wire 0 as the constant one, then
//! public outputs, then public inputs, then private signals. With no public
//! outputs the two layouts coincide exactly, so matrix indices are written
//! through unchanged.
//!
//! ## Format
//!
//! Verified against a circom-produced file rather than from the spec alone:
//! magic `r1cs`, version 1, then `(type: u32, size: u64, body)` sections.
//! Everything is little-endian and field elements are plain integers in
//! `field_size` bytes — not Montgomery form.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_relations::r1cs::{ConstraintMatrices, Matrix};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// Bytes per field element for BN254's scalar field.
const FIELD_SIZE: u32 = 32;

const MAGIC: &[u8; 4] = b"r1cs";
const VERSION: u32 = 1;
const SECTION_HEADER: u32 = 1;
const SECTION_CONSTRAINTS: u32 = 2;
const SECTION_WIRE2LABEL: u32 = 3;

/// Serialise one linear combination: term count, then `(wire, coefficient)`
/// pairs ascending by wire.
///
/// The format requires ascending order, and arkworks makes no such promise.
/// Terms that repeat a wire are summed rather than emitted twice, and terms
/// that cancel to zero are dropped — a duplicate wire index is not something
/// the readers agree on how to handle.
fn write_lc(out: &mut Vec<u8>, row: &[(Fr, usize)]) {
    let mut terms: BTreeMap<usize, Fr> = BTreeMap::new();
    for (coeff, wire) in row {
        *terms.entry(*wire).or_insert_with(Fr::zero) += coeff;
    }
    terms.retain(|_, coeff| !coeff.is_zero());

    out.extend_from_slice(&(terms.len() as u32).to_le_bytes());
    for (wire, coeff) in terms {
        out.extend_from_slice(&(wire as u32).to_le_bytes());
        let mut bytes = coeff.into_bigint().to_bytes_le();
        bytes.resize(FIELD_SIZE as usize, 0);
        out.extend_from_slice(&bytes);
    }
}

fn section(out: &mut impl Write, kind: u32, body: &[u8]) -> io::Result<()> {
    out.write_all(&kind.to_le_bytes())?;
    out.write_all(&(body.len() as u64).to_le_bytes())?;
    out.write_all(body)
}

/// Write `matrices` to `out` as a circom `.r1cs` file.
pub fn write_r1cs(out: &mut impl Write, matrices: &ConstraintMatrices<Fr>) -> io::Result<()> {
    let num_instance = matrices.num_instance_variables;
    let num_witness = matrices.num_witness_variables;
    let num_wires = num_instance + num_witness;

    out.write_all(MAGIC)?;
    out.write_all(&VERSION.to_le_bytes())?;
    out.write_all(&3u32.to_le_bytes())?;

    // Header. `num_instance_variables` counts the constant-one wire, so the
    // public inputs are one fewer. Nothing in an arkworks circuit is a public
    // *output*, so that count is zero and the public inputs start at wire 1.
    let mut header = Vec::new();
    header.extend_from_slice(&FIELD_SIZE.to_le_bytes());
    let mut modulus = Fr::MODULUS.to_bytes_le();
    modulus.resize(FIELD_SIZE as usize, 0);
    header.extend_from_slice(&modulus);
    header.extend_from_slice(&(num_wires as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&((num_instance - 1) as u32).to_le_bytes());
    header.extend_from_slice(&(num_witness as u32).to_le_bytes());
    // Labels are a circom debugging aid mapping wires back to signal names in
    // the source. There is no source to map back to, so the map is the
    // identity and the count is simply the wire count.
    header.extend_from_slice(&(num_wires as u64).to_le_bytes());
    header.extend_from_slice(&(matrices.num_constraints as u32).to_le_bytes());
    section(out, SECTION_HEADER, &header)?;

    let mut constraints = Vec::new();
    let rows = |m: &Matrix<Fr>, i: usize| m.get(i).cloned().unwrap_or_default();
    for i in 0..matrices.num_constraints {
        write_lc(&mut constraints, &rows(&matrices.a, i));
        write_lc(&mut constraints, &rows(&matrices.b, i));
        write_lc(&mut constraints, &rows(&matrices.c, i));
    }
    section(out, SECTION_CONSTRAINTS, &constraints)?;

    let mut labels = Vec::with_capacity(num_wires * 8);
    for wire in 0..num_wires {
        labels.extend_from_slice(&(wire as u64).to_le_bytes());
    }
    section(out, SECTION_WIRE2LABEL, &labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::circuits::TransactCircuitV3;
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
    };

    /// Minimal reader, deliberately independent of the writer: it follows the
    /// format as observed in a circom-produced file, so a shared misreading
    /// cannot make a broken export look correct.
    struct Parsed {
        field_size: u32,
        prime: Vec<u8>,
        num_wires: u32,
        num_pub_out: u32,
        num_pub_in: u32,
        num_prv_in: u32,
        num_labels: u64,
        num_constraints: u32,
        /// `(wire, coefficient bytes)` per linear combination, in file order.
        lcs: Vec<Vec<(u32, Vec<u8>)>>,
    }

    fn parse(bytes: &[u8]) -> Parsed {
        let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());

        assert_eq!(&bytes[0..4], MAGIC);
        assert_eq!(u32_at(4), VERSION);
        let num_sections = u32_at(8);

        let mut offsets = std::collections::HashMap::new();
        let mut cursor = 12;
        for _ in 0..num_sections {
            let kind = u32_at(cursor);
            let size = u64_at(cursor + 4) as usize;
            offsets.insert(kind, (cursor + 12, size));
            cursor += 12 + size;
        }
        assert_eq!(cursor, bytes.len(), "sections must cover the file exactly");

        let (h, _) = offsets[&SECTION_HEADER];
        let field_size = u32_at(h);
        let fs = field_size as usize;
        let prime = bytes[h + 4..h + 4 + fs].to_vec();
        let after_prime = h + 4 + fs;

        let (c, c_size) = offsets[&SECTION_CONSTRAINTS];
        let mut lcs = Vec::new();
        let mut p = c;
        while p < c + c_size {
            let count = u32_at(p) as usize;
            p += 4;
            let mut terms = Vec::with_capacity(count);
            for _ in 0..count {
                let wire = u32_at(p);
                let coeff = bytes[p + 4..p + 4 + fs].to_vec();
                terms.push((wire, coeff));
                p += 4 + fs;
            }
            lcs.push(terms);
        }
        assert_eq!(p, c + c_size, "constraint section must parse exactly");

        Parsed {
            field_size,
            prime,
            num_wires: u32_at(after_prime),
            num_pub_out: u32_at(after_prime + 4),
            num_pub_in: u32_at(after_prime + 8),
            num_prv_in: u32_at(after_prime + 12),
            num_labels: u64_at(after_prime + 16),
            num_constraints: u32_at(after_prime + 24),
            lcs,
        }
    }

    fn transact_v3_matrices() -> ConstraintMatrices<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        TransactCircuitV3::blank()
            .generate_constraints(cs.clone())
            .expect("blank instance synthesises");
        cs.finalize();
        cs.to_matrices().expect("matrices")
    }

    #[test]
    fn export_matches_the_circuit_it_came_from() {
        let matrices = transact_v3_matrices();
        let mut bytes = Vec::new();
        write_r1cs(&mut bytes, &matrices).expect("write");
        let parsed = parse(&bytes);

        assert_eq!(parsed.field_size, 32);
        let mut expected_prime = Fr::MODULUS.to_bytes_le();
        expected_prime.resize(32, 0);
        assert_eq!(parsed.prime, expected_prime);

        // The shape `r1cs_shape::transact_v3_shape_is_pinned` locks, restated
        // in circom's terms: no public outputs, and the constant-one wire is
        // counted in wires but is not a public input.
        assert_eq!(parsed.num_constraints, 18_477);
        assert_eq!(parsed.num_pub_out, 0);
        assert_eq!(parsed.num_pub_in, 8);
        assert_eq!(parsed.num_prv_in, 18_542);
        assert_eq!(parsed.num_wires, 9 + 18_542);
        assert_eq!(parsed.num_labels, u64::from(parsed.num_wires));

        // Three linear combinations per constraint, in A, B, C order.
        assert_eq!(parsed.lcs.len(), 3 * 18_477);
    }

    #[test]
    fn every_term_is_in_range_and_ascending() {
        let matrices = transact_v3_matrices();
        let mut bytes = Vec::new();
        write_r1cs(&mut bytes, &matrices).expect("write");
        let parsed = parse(&bytes);

        for lc in &parsed.lcs {
            let mut previous: Option<u32> = None;
            for (wire, _) in lc {
                assert!(
                    *wire < parsed.num_wires,
                    "wire {} outside the declared {} wires",
                    wire,
                    parsed.num_wires
                );
                if let Some(prev) = previous {
                    assert!(prev < *wire, "terms must ascend and not repeat a wire");
                }
                previous = Some(*wire);
            }
        }
    }

    #[test]
    fn coefficients_survive_the_round_trip() {
        let matrices = transact_v3_matrices();
        let mut bytes = Vec::new();
        write_r1cs(&mut bytes, &matrices).expect("write");
        let parsed = parse(&bytes);

        // Read the file back into arkworks values and compare against the
        // matrices it was written from — catches an endianness or padding
        // slip that the structural checks above would let through.
        for (row, lc) in matrices.a.iter().enumerate() {
            let decoded = &parsed.lcs[row * 3];
            let mut expected: BTreeMap<usize, Fr> = BTreeMap::new();
            for (coeff, wire) in lc {
                *expected.entry(*wire).or_insert_with(Fr::zero) += coeff;
            }
            expected.retain(|_, c| !c.is_zero());

            assert_eq!(decoded.len(), expected.len(), "term count at row {}", row);
            for ((wire, coeff), (expected_wire, expected_coeff)) in decoded.iter().zip(&expected) {
                assert_eq!(*wire as usize, *expected_wire);
                assert_eq!(
                    Fr::from_le_bytes_mod_order(coeff),
                    *expected_coeff,
                    "coefficient at row {} wire {}",
                    row,
                    wire
                );
            }
        }
    }
}
