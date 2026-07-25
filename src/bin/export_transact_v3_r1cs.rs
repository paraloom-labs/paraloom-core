use ark_bn254::Fr;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use paraloom::privacy::circuits::TransactCircuitV3;
use paraloom::privacy::r1cs_export::write_r1cs;
use std::fs;
use std::path::Path;

// Export the v3 transact circuit as a circom `.r1cs` file, the input the
// powers-of-tau phase-2 tooling takes (#659).
//
// The file is a build artefact, not a secret: publishing it is what lets
// anyone re-run `snarkjs zkey verify <r1cs> <ptau> <zkey>` and confirm the
// ceremony's finalized key derives from the public transcript and this exact
// constraint system. It is reproducible from this binary, so a reviewer can
// regenerate it and compare hashes rather than trust the copy we ship.
const OUTPUT_PATH: &str = "artifacts/transact_v3.r1cs";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let path = std::env::var("TRANSACT_V3_R1CS").unwrap_or_else(|_| OUTPUT_PATH.to_string());

    println!("Synthesising the v3 transact circuit...");
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    TransactCircuitV3::blank().generate_constraints(cs.clone())?;
    cs.finalize();
    let matrices = cs
        .to_matrices()
        .ok_or("constraint system has no matrices")?;

    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = Vec::new();
    write_r1cs(&mut bytes, &matrices)?;
    fs::write(&path, &bytes)?;

    let num_wires = matrices.num_instance_variables + matrices.num_witness_variables;
    println!("\nWrote {} ({} bytes)\n", path, bytes.len());
    println!("Compare against `snarkjs r1cs info {}`:", path);
    println!("  Constraints:     {}", matrices.num_constraints);
    println!("  Wires:           {}", num_wires);
    println!("  Public Inputs:   {}", matrices.num_instance_variables - 1);
    println!("  Public Outputs:  0");
    println!("  Private Inputs:  {}", matrices.num_witness_variables);
    println!(
        "\nSmallest usable powers-of-tau: 2^{} (domain input {})",
        (matrices.num_constraints + matrices.num_instance_variables)
            .next_power_of_two()
            .trailing_zeros(),
        matrices.num_constraints + matrices.num_instance_variables
    );

    Ok(())
}
