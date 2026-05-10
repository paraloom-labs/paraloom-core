//! Smoke test for the bridge E2E harness. Boots the validator
//! through `SubprocessValidator`, queries a slot, and asserts the
//! RPC handle works end to end. The actual bridge round-trip
//! (deposit → listener → pool → submitter → withdraw) lands in
//! follow-up commits on this branch. Ignored by default; CI runs
//! it with `cargo test -- --ignored` after installing the Solana
//! CLI.

mod common;
use common::solana_validator::{
    fund_new_keypair, paraloom_program_so, SubprocessValidator, PARALOOM_PROGRAM_ID,
};
use paraloom::bridge::solana::{
    create_deposit_instruction, create_initialize_instruction, derive_bridge_vault, EventListener,
    ProgramInterface, RealBridgeRpc,
};
use paraloom::bridge::{BridgeConfig, BridgeStats, EXPECTED_PROGRAM_VERSION};
use paraloom::privacy::ShieldedPool;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::transaction::Transaction;
use std::sync::Arc;
use tokio::sync::RwLock;

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
    let account = rpc
        .get_account(&program_id)
        .expect("program account exists");
    assert!(account.executable, "program account must be executable");
}

/// Full ProgramInterface handshake against a real on-chain handler:
/// boot the validator with paraloom_program loaded, send the
/// Initialize instruction (funds an airdropped payer first),
/// then drive ProgramInterface::verify_program_version through
/// RealBridgeRpc. The handshake must accept because the binary's
/// EXPECTED_PROGRAM_VERSION was the value we wrote on-chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires solana-test-validator + cargo build-sbf; CI runs with --ignored"]
async fn program_version_handshake_against_real_validator() {
    let validator = SubprocessValidator::launch_with_programs(
        8901,
        &[(PARALOOM_PROGRAM_ID, paraloom_program_so())],
    )
    .expect("validator must boot with paraloom_program");
    let rpc = validator.rpc_client();
    let payer = fund_new_keypair(&rpc, 2_000_000_000).expect("airdrop");

    let program_id: Pubkey = PARALOOM_PROGRAM_ID.parse().unwrap();
    let init_ix = create_initialize_instruction(
        &program_id,
        &payer.pubkey(),
        EXPECTED_PROGRAM_VERSION,
        [0u8; 32],
    )
    .expect("build initialize ix");
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx =
        Transaction::new_signed_with_payer(&[init_ix], Some(&payer.pubkey()), &[&payer], blockhash);
    rpc.send_and_confirm_transaction(&tx)
        .expect("send initialize");

    let bridge_rpc: Arc<dyn paraloom::bridge::solana::BridgeRpc> =
        Arc::new(RealBridgeRpc::new(rpc));
    let config = BridgeConfig {
        program_id: PARALOOM_PROGRAM_ID.to_string(),
        ..Default::default()
    };
    let program = ProgramInterface::new(config, bridge_rpc).expect("program interface");
    program
        .verify_program_version()
        .await
        .expect("version handshake against real on-chain state");
}

/// Full deposit round-trip: send a real Deposit instruction on-chain,
/// run the EventListener against the validator's RPC, and assert the
/// listener decoded the deposit and added the note to the L2 pool.
/// This is the test #71's first bullet specifically asks for —
/// "deposit on Solana → assert a note appears on L2".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires solana-test-validator + cargo build-sbf; CI runs with --ignored"]
async fn deposit_on_chain_propagates_to_l2_pool_via_listener() {
    let validator = SubprocessValidator::launch_with_programs(
        8902,
        &[(PARALOOM_PROGRAM_ID, paraloom_program_so())],
    )
    .expect("validator must boot with paraloom_program");
    let rpc = validator.rpc_client();
    let payer = fund_new_keypair(&rpc, 3_000_000_000).expect("airdrop");

    let program_id: Pubkey = PARALOOM_PROGRAM_ID.parse().unwrap();
    let init_ix = create_initialize_instruction(
        &program_id,
        &payer.pubkey(),
        EXPECTED_PROGRAM_VERSION,
        [0u8; 32],
    )
    .expect("init ix");
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx =
        Transaction::new_signed_with_payer(&[init_ix], Some(&payer.pubkey()), &[&payer], blockhash);
    rpc.send_and_confirm_transaction(&tx).expect("init tx");

    let bridge_rpc: Arc<dyn paraloom::bridge::solana::BridgeRpc> =
        Arc::new(RealBridgeRpc::new(rpc.clone()));
    let pool = Arc::new(ShieldedPool::new());
    let stats = Arc::new(RwLock::new(BridgeStats::default()));
    let config = BridgeConfig {
        program_id: PARALOOM_PROGRAM_ID.to_string(),
        enabled: true,
        solana_rpc_url: validator.rpc_url(),
        poll_interval_secs: 1,
        ..Default::default()
    };
    let mut listener =
        EventListener::new(config, bridge_rpc, Arc::clone(&pool), Arc::clone(&stats));
    listener.start().await.expect("listener start");

    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let deposit_ix = create_deposit_instruction(
        &program_id,
        &payer.pubkey(),
        &vault_pda,
        1_000_000,
        [9u8; 32],
        [11u8; 32],
    )
    .expect("deposit ix");
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[deposit_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&tx).expect("deposit tx");

    // Poll for up to 15s for the deposit to materialise — CI
    // runners boot the validator slower than a laptop, and the
    // listener tick is 1s. A fixed sleep proved too tight on CI.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while pool.commitment_count().await == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    listener.stop().await.expect("listener stop");

    assert_eq!(
        pool.commitment_count().await,
        1,
        "L2 pool must have the deposit note"
    );
    assert_eq!(
        stats.read().await.total_deposits,
        1,
        "listener stats must tick"
    );
}
