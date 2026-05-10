//! Smoke test for the bridge E2E harness. Boots the validator
//! through `SubprocessValidator`, queries a slot, and asserts the
//! RPC handle works end to end. The actual bridge round-trip
//! (deposit → listener → pool → submitter → withdraw) lands in
//! follow-up commits on this branch. Ignored by default; CI runs
//! it with `cargo test -- --ignored` after installing the Solana
//! CLI.

mod common;
use common::solana_validator::SubprocessValidator;

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
