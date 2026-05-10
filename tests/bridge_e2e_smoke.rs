//! Smoke test for the bridge E2E harness. Boots the validator
//! through `SubprocessValidator`, queries a slot, and asserts the
//! RPC handle works end to end. The actual bridge round-trip
//! (deposit → listener → pool → submitter → withdraw) lands in
//! follow-up commits on this branch. Ignored by default; CI runs
//! it with `cargo test -- --ignored` after installing the Solana
//! CLI.

mod common;
use common::solana_validator::{paraloom_program_so, SubprocessValidator, PARALOOM_PROGRAM_ID};
use solana_sdk::pubkey::Pubkey;

#[test]
#[ignore = "requires solana-test-validator binary; CI runs with --ignored"]
fn validator_boots_and_responds_to_get_slot() {
    let validator = SubprocessValidator::launch(8899).expect("validator must boot");
    let rpc = validator.rpc_client();
    let slot = rpc.get_slot().expect("get_slot");
    // Genesis is slot 0; a healthy validator advances within
    // milliseconds — the bound is intentionally loose so a
    // slow CI runner does not flake.
    assert!(
        slot < 10_000,
        "slot {} unrealistically large for fresh validator",
        slot
    );
}

/// Boots a validator with the paraloom on-chain program preloaded
/// via `--bpf-program`. The program account at PARALOOM_PROGRAM_ID
/// must exist and be executable — a regression in the deploy plumbing
/// (wrong path, missing build step, address mismatch) would fall
/// out at this assertion rather than later inside a bridge round-trip.
#[test]
#[ignore = "requires solana-test-validator + cargo build-sbf; CI runs with --ignored"]
fn paraloom_program_loads_at_expected_address() {
    let validator = SubprocessValidator::launch_with_programs(
        8900,
        &[(PARALOOM_PROGRAM_ID, paraloom_program_so())],
    )
    .expect("validator must boot with paraloom_program");
    let rpc = validator.rpc_client();
    let program_id: Pubkey = PARALOOM_PROGRAM_ID.parse().expect("program id parses");
    let account = rpc.get_account(&program_id).expect("program account exists");
    assert!(account.executable, "program account must be executable");
}
