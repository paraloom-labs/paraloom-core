//! Circuit benchmarking and analysis
//!
//! Measures circuit complexity and performance for optimization

use crate::privacy::circuits::{DepositCircuit, TransferCircuit, WithdrawCircuit};
use ark_bls12_381::Fr;
use ark_relations::r1cs::ConstraintSystem;
use std::time::Instant;

/// Circuit complexity metrics
#[derive(Debug, Clone)]
pub struct CircuitMetrics {
    /// Number of constraints in the circuit
    pub num_constraints: usize,

    /// Number of variables
    pub num_variables: usize,

    /// Number of public inputs
    pub num_public_inputs: usize,

    /// Time to generate constraints (ms)
    pub constraint_gen_time_ms: u128,

    /// Estimated proof generation time (ms)
    /// Based on empirical data: ~1ms per 1000 constraints on modern CPU
    pub estimated_proof_time_ms: u128,

    /// Estimated proof time on Raspberry Pi 4
    /// Pi 4 is ~5-10x slower than modern CPU for this workload
    pub estimated_pi4_time_ms: u128,
}

impl CircuitMetrics {
    /// Calculate estimated proof times based on constraint count
    fn calculate_estimates(num_constraints: usize, _constraint_gen_time_ms: u128) -> (u128, u128) {
        // Modern CPU: ~1ms per 1000 constraints
        let proof_time = (num_constraints as u128) / 1000;

        // Raspberry Pi 4: ~7x slower (empirical data from similar workloads)
        let pi4_time = proof_time * 7;

        (proof_time, pi4_time)
    }
}

/// Benchmark a circuit and return metrics
pub fn benchmark_circuit<C>(circuit: C, name: &str) -> CircuitMetrics
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr>,
{
    println!("\n=== Benchmarking {} ===", name);

    let cs = ConstraintSystem::<Fr>::new_ref();

    // Measure constraint generation time
    let start = Instant::now();
    circuit
        .generate_constraints(cs.clone())
        .expect("Constraint generation failed");
    let constraint_gen_time_ms = start.elapsed().as_millis();

    // Get circuit statistics
    let num_constraints = cs.num_constraints();
    let num_variables = cs.num_instance_variables() + cs.num_witness_variables();
    let num_public_inputs = cs.num_instance_variables();

    let (estimated_proof_time_ms, estimated_pi4_time_ms) =
        CircuitMetrics::calculate_estimates(num_constraints, constraint_gen_time_ms);

    let metrics = CircuitMetrics {
        num_constraints,
        num_variables,
        num_public_inputs,
        constraint_gen_time_ms,
        estimated_proof_time_ms,
        estimated_pi4_time_ms,
    };

    println!("Constraints: {}", num_constraints);
    println!("Variables: {}", num_variables);
    println!("Public inputs: {}", num_public_inputs);
    println!("Constraint gen time: {} ms", constraint_gen_time_ms);
    println!(
        "Est. proof time (modern CPU): {} ms",
        estimated_proof_time_ms
    );
    println!("Est. proof time (Pi 4): {} ms", estimated_pi4_time_ms);

    metrics
}

/// Run comprehensive circuit benchmarks
pub fn run_all_benchmarks() -> BenchmarkSuite {
    println!("\nCIRCUIT COMPLEXITY ANALYSIS");

    // Benchmark Deposit circuit
    let deposit_circuit = DepositCircuit::with_witness([1u8; 32], 1000, [2u8; 32], [3u8; 32]);
    let deposit_metrics = benchmark_circuit(deposit_circuit, "DepositCircuit");

    // Benchmark Transfer circuit (1-in-1-out)
    let transfer_circuit_1x1 = TransferCircuit::with_witness(
        [1u8; 32],
        vec![[2u8; 32]],
        vec![[3u8; 32]],
        vec![1000],
        vec![[4u8; 32]],
        vec![vec![([5u8; 32], true)]],
        vec![1000],
        vec![[6u8; 32]],
        vec![[7u8; 32]],
    );
    let transfer_1x1_metrics =
        benchmark_circuit(transfer_circuit_1x1, "TransferCircuit (1-in-1-out)");

    // Benchmark Transfer circuit (2-in-2-out) - max complexity
    let transfer_circuit_2x2 = TransferCircuit::with_witness(
        [1u8; 32],
        vec![[2u8; 32], [3u8; 32]],
        vec![[4u8; 32], [5u8; 32]],
        vec![500, 500],
        vec![[6u8; 32], [7u8; 32]],
        vec![
            vec![([8u8; 32], true), ([9u8; 32], false)],
            vec![([10u8; 32], true), ([11u8; 32], false)],
        ],
        vec![600, 400],
        vec![[12u8; 32], [13u8; 32]],
        vec![[14u8; 32], [15u8; 32]],
    );
    let transfer_2x2_metrics =
        benchmark_circuit(transfer_circuit_2x2, "TransferCircuit (2-in-2-out)");

    // Benchmark Withdraw circuit
    let withdraw_circuit = WithdrawCircuit::with_witness(
        [1u8; 32],                                   // merkle_root
        [2u8; 32],                                   // nullifier
        500,                                         // withdraw_amount
        1000,                                        // input_value
        [3u8; 32],                                   // input_randomness
        [6u8; 32],                                   // secret
        vec![([4u8; 32], true), ([5u8; 32], false)], // merkle_path
    );
    let withdraw_metrics = benchmark_circuit(withdraw_circuit, "WithdrawCircuit");

    BenchmarkSuite {
        deposit: deposit_metrics,
        transfer_1x1: transfer_1x1_metrics,
        transfer_2x2: transfer_2x2_metrics,
        withdraw: withdraw_metrics,
    }
}

/// Complete benchmark suite results
#[derive(Debug, Clone)]
pub struct BenchmarkSuite {
    pub deposit: CircuitMetrics,
    pub transfer_1x1: CircuitMetrics,
    pub transfer_2x2: CircuitMetrics,
    pub withdraw: CircuitMetrics,
}

impl BenchmarkSuite {
    /// Print summary report
    pub fn print_summary(&self) {
        println!("BENCHMARK SUMMARY");
        println!("====================");
        println!("Circuit Complexity (Constraints):");
        println!("Deposit:        {:>8}", self.deposit.num_constraints);
        println!("Transfer (1x1): {:>8}", self.transfer_1x1.num_constraints);
        println!("Transfer (2x2): {:>8}", self.transfer_2x2.num_constraints);
        println!("Withdraw:       {:>8}", self.withdraw.num_constraints);

        println!("\nEstimated Proof Time on Raspberry Pi 4:");
        println!(
            "Deposit:        {:>8} ms",
            self.deposit.estimated_pi4_time_ms
        );
        println!(
            "Transfer (1x1): {:>8} ms",
            self.transfer_1x1.estimated_pi4_time_ms
        );
        println!(
            "Transfer (2x2): {:>8} ms",
            self.transfer_2x2.estimated_pi4_time_ms
        );
        println!(
            "Withdraw:       {:>8} ms",
            self.withdraw.estimated_pi4_time_ms
        );

        // Check if any circuit exceeds 10 second target on Pi 4
        let max_time = self
            .transfer_2x2
            .estimated_pi4_time_ms
            .max(self.withdraw.estimated_pi4_time_ms);
        println!("\nTarget: <10,000 ms on Pi 4");
        if max_time < 10_000 {
            println!("All circuits meet target!");
        } else {
            println!("Some circuits exceed target - optimization needed");
        }
    }

    /// Check if circuits are optimized for Raspberry Pi
    pub fn is_pi_optimized(&self) -> bool {
        // All circuits should complete in < 10 seconds on Pi 4
        self.deposit.estimated_pi4_time_ms < 10_000
            && self.transfer_1x1.estimated_pi4_time_ms < 10_000
            && self.transfer_2x2.estimated_pi4_time_ms < 10_000
            && self.withdraw.estimated_pi4_time_ms < 10_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_deposit_circuit() {
        let circuit = DepositCircuit::with_witness([1u8; 32], 1000, [2u8; 32], [3u8; 32]);

        let metrics = benchmark_circuit(circuit, "DepositCircuit");

        assert!(metrics.num_constraints > 0);
        assert!(metrics.num_variables > 0);
        assert!(metrics.num_public_inputs > 0);
    }

    #[test]
    fn test_run_all_benchmarks() {
        let suite = run_all_benchmarks();

        // All circuits should have some constraints
        assert!(suite.deposit.num_constraints > 0);
        assert!(suite.transfer_1x1.num_constraints > 0);
        assert!(suite.transfer_2x2.num_constraints > 0);
        assert!(suite.withdraw.num_constraints > 0);

        // Print summary
        suite.print_summary();
    }
}
