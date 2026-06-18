//! #178 acceptance: the on-chain `withdraw` is authenticated, plus the
//! Design-A fee path (withdraw credits the settling validator).
//!
//!   * a signer other than the bridge authority is rejected (`has_one`)
//!   * a proof longer than `MAX_PROOF_LEN` is rejected (`ProofTooLarge`)
//!   * the bridge authority (a registered validator) settles a real
//!     withdrawal; the recipient receives `amount - fee` and the fee
//!     (25 bps) stays in the vault as the validator's reward
//!
//! Since #204 the program is loaded UPGRADEABLE and `initialize` /
//! `initialize_validator_registry` must be signed by the upgrade authority,
//! so `bootstrap` generates that authority up front and passes its pubkey to
//! the launch (#217). Settlement is validator-gated (Design A), so bootstrap
//! also registers the authority as a validator.
//!
//! Ignored by default; CI runs it via the bridge-e2e workflow with
//! `--ignored --test-threads=1` after installing the Solana CLI.

mod common;
use common::solana_validator::{
    confirm_within, fund_keypair, paraloom_program_so, SubprocessValidator, PARALOOM_PROGRAM_ID,
};
use paraloom::bridge::solana::{
    create_deposit_instruction, create_initialize_instruction,
    create_initialize_validator_registry_instruction, create_register_validator_instruction,
    create_withdraw_instruction, derive_bridge_vault, derive_nullifier_account,
};
use paraloom::bridge::EXPECTED_PROGRAM_VERSION;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use std::time::Duration;

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;
const WITHDRAWAL_FEE_BPS: u64 = 25;

// Valid withdrawal proof fixture matching the program's embedded verifying key
// (same data as programs/paraloom/src/withdraw_fixture_data.rs). The bridge is
// initialized with FIXTURE_ROOT so this proof verifies on-chain.
const FIXTURE_ROOT: [u8; 32] = [
    47, 84, 196, 123, 85, 59, 134, 71, 150, 197, 0, 225, 103, 229, 16, 83, 195, 133, 20, 202, 42,
    63, 52, 169, 140, 220, 197, 55, 101, 210, 243, 10,
];
const FIXTURE_NULLIFIER: [u8; 32] = [
    193, 236, 245, 0, 121, 36, 11, 2, 101, 68, 92, 233, 30, 137, 43, 131, 96, 80, 130, 226, 106,
    133, 155, 56, 170, 30, 59, 149, 202, 0, 191, 20,
];
const FIXTURE_AMOUNT: u64 = 1_000_000_000;
// The spend-key v2 proof binds `ext_data_hash = sha256(FIXTURE_RECIPIENT || amount)`
// with NATIVE asset, so the on-chain `withdraw` must pay exactly this recipient.
const FIXTURE_RECIPIENT: [u8; 32] = [
    154, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255, 16, 32, 48, 64, 80,
    96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 1,
];
const FIXTURE_PROOF_A: [u8; 64] = [
    21, 90, 173, 60, 66, 17, 41, 84, 10, 25, 93, 39, 213, 77, 226, 251, 85, 120, 7, 236, 55, 146,
    224, 228, 234, 149, 121, 160, 210, 143, 188, 19, 154, 14, 160, 68, 110, 11, 72, 130, 104, 164,
    49, 178, 221, 94, 127, 37, 20, 126, 100, 18, 124, 235, 93, 127, 64, 12, 22, 117, 229, 36, 67,
    38,
];
const FIXTURE_PROOF_B: [u8; 128] = [
    43, 246, 70, 32, 106, 88, 100, 254, 75, 247, 218, 79, 17, 153, 173, 255, 5, 250, 94, 27, 125,
    169, 135, 40, 131, 10, 35, 72, 44, 23, 44, 108, 43, 20, 225, 117, 207, 230, 230, 51, 178, 170,
    238, 112, 93, 126, 204, 246, 113, 244, 40, 218, 255, 86, 94, 202, 104, 150, 37, 251, 80, 242,
    236, 46, 162, 182, 205, 125, 254, 118, 112, 227, 219, 29, 20, 138, 59, 114, 173, 53, 211, 204,
    157, 63, 173, 206, 68, 68, 33, 196, 16, 226, 13, 252, 16, 159, 12, 124, 44, 184, 46, 200, 217,
    44, 7, 144, 88, 247, 187, 233, 231, 244, 61, 80, 253, 140, 206, 185, 227, 162, 132, 124, 118,
    209, 151, 83, 52, 15,
];
const FIXTURE_PROOF_C: [u8; 64] = [
    32, 160, 216, 211, 177, 132, 82, 56, 180, 207, 14, 15, 50, 63, 236, 55, 20, 236, 177, 219, 58,
    213, 204, 200, 92, 233, 211, 172, 232, 141, 71, 218, 162, 160, 135, 31, 95, 219, 81, 86, 38,
    112, 247, 33, 91, 61, 78, 217, 253, 105, 67, 16, 68, 111, 31, 133, 100, 239, 238, 151, 143, 95,
    192, 243,
];

/// The 256-byte alt_bn128 wire proof from the fixture.
fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&FIXTURE_PROOF_A);
    p.extend_from_slice(&FIXTURE_PROOF_B);
    p.extend_from_slice(&FIXTURE_PROOF_C);
    p
}

/// Send a single-instruction tx signed by `signer` and confirm it.
fn send(rpc: &RpcClient, signer: &Keypair, ix: solana_sdk::instruction::Instruction) {
    let bh = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&signer.pubkey()), &[signer], bh);
    rpc.send_and_confirm_transaction(&tx).expect("tx confirm");
}

/// Generate the upgrade authority, boot the validator with the program loaded
/// upgradeable under it, initialize the bridge + validator registry, register
/// the authority as a validator (settlement is validator-gated), and fund the
/// vault. Returns the validator, program id, and the funded authority keypair.
fn bootstrap(port: u16) -> (SubprocessValidator, Pubkey, Keypair) {
    let authority = Keypair::new();
    let validator = SubprocessValidator::launch_with_upgradeable_program(
        port,
        PARALOOM_PROGRAM_ID,
        paraloom_program_so(),
        &authority.pubkey(),
    )
    .expect("validator must boot with paraloom_program");
    let rpc = validator.rpc_client();
    fund_keypair(&rpc, &authority, 4_000_000_000).expect("airdrop authority");
    let program_id: Pubkey = PARALOOM_PROGRAM_ID.parse().unwrap();

    // initialize the bridge (signed by the upgrade authority, #204).
    send(
        &rpc,
        &authority,
        create_initialize_instruction(
            &program_id,
            &authority.pubkey(),
            EXPECTED_PROGRAM_VERSION,
            FIXTURE_ROOT,
        )
        .expect("init ix"),
    );

    // initialize the validator registry + register the authority as a
    // validator so it can settle (Design A: withdraw is validator-gated).
    send(
        &rpc,
        &authority,
        create_initialize_validator_registry_instruction(&program_id, &authority.pubkey())
            .expect("registry ix"),
    );
    send(
        &rpc,
        &authority,
        create_register_validator_instruction(
            &program_id,
            &authority.pubkey(),
            MIN_VALIDATOR_STAKE,
        )
        .expect("register ix"),
    );

    // fund the vault so a withdrawal reaches the on-chain guards.
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    send(
        &rpc,
        &authority,
        create_deposit_instruction(
            &program_id,
            &authority.pubkey(),
            &vault_pda,
            2_000_000_000,
            [9u8; 32],
            [11u8; 32],
        )
        .expect("deposit ix"),
    );

    (validator, program_id, authority)
}

#[test]
#[ignore = "requires solana-test-validator; run in CI via bridge-e2e workflow"]
fn unauthorized_signer_cannot_withdraw() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (validator, program_id, _authority) = bootstrap(8904);
    let rpc = validator.rpc_client();

    // A signer that is NOT the bridge authority attempts a well-formed
    // withdrawal. It is rejected at account validation — both `has_one =
    // authority` and the missing validator_account PDA for this signer.
    let attacker = fund_new_attacker(&rpc);
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let nullifier = [123u8; 32];
    let cur_slot = rpc.get_slot().unwrap_or(0);
    let ix = create_withdraw_instruction(
        &program_id,
        &attacker.pubkey(), // attacker poses as the authority
        &vault_pda,
        [42u8; 32],
        nullifier,
        100_000,
        cur_slot + 150,
        vec![1u8; 192],
        &[], // rejected at account validation before the quorum check
    )
    .expect("withdraw ix");
    let bh = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&attacker.pubkey()), &[&attacker], bh);

    let res = rpc.send_and_confirm_transaction(&tx);
    assert!(
        res.is_err(),
        "unauthorized signer must be rejected by has_one = authority"
    );
    let (nullifier_pda, _) = derive_nullifier_account(&program_id, &nullifier);
    assert!(
        rpc.get_account(&nullifier_pda).is_err(),
        "no nullifier PDA may exist for the rejected withdrawal"
    );
    log::info!("unauthorized withdraw correctly rejected: {:?}", res.err());
}

#[test]
#[ignore = "requires solana-test-validator; run in CI via bridge-e2e workflow"]
fn oversized_proof_rejected() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (validator, program_id, authority) = bootstrap(8905);
    let rpc = validator.rpc_client();

    // The authority (a registered validator) submits, but with a proof past
    // MAX_PROOF_LEN (256). The handler's length guard must reject it.
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let nullifier = [200u8; 32];
    let cur_slot = rpc.get_slot().unwrap_or(0);
    let ix = create_withdraw_instruction(
        &program_id,
        &authority.pubkey(),
        &vault_pda,
        [42u8; 32],
        nullifier,
        100_000,
        cur_slot + 150,
        vec![0u8; 257], // one over MAX_PROOF_LEN
        &[],            // rejected on proof length before the quorum check
    )
    .expect("withdraw ix");
    let bh = rpc.get_latest_blockhash().expect("blockhash");
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&authority.pubkey()), &[&authority], bh);

    let res = rpc.send_and_confirm_transaction(&tx);
    assert!(
        res.is_err(),
        "a proof longer than MAX_PROOF_LEN must be rejected"
    );
    let (nullifier_pda, _) = derive_nullifier_account(&program_id, &nullifier);
    assert!(
        rpc.get_account(&nullifier_pda).is_err(),
        "no nullifier PDA may exist for the rejected oversized-proof withdrawal"
    );
    log::info!("oversized proof correctly rejected: {:?}", res.err());
}

#[test]
#[ignore = "requires solana-test-validator; run in CI via bridge-e2e workflow"]
fn authority_can_withdraw() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (validator, program_id, authority) = bootstrap(8906);
    let rpc = validator.rpc_client();

    // The bridge authority (a registered validator) settles a well-formed
    // withdrawal with a real proof (the fixture) that verifies on-chain against
    // the bridge's FIXTURE_ROOT. bootstrap funded the vault with 2 SOL.
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let vault_before = rpc.get_balance(&vault_pda).expect("vault balance before");

    // Must match the recipient bound into the v2 proof's ext_data_hash.
    let recipient = Pubkey::new_from_array(FIXTURE_RECIPIENT);
    let nullifier = FIXTURE_NULLIFIER;
    let amount = FIXTURE_AMOUNT;
    let fee = amount * WITHDRAWAL_FEE_BPS / 10_000;
    let payout = amount - fee;
    let cur_slot = rpc.get_slot().unwrap_or(0);
    let ix = create_withdraw_instruction(
        &program_id,
        &authority.pubkey(),
        &vault_pda,
        recipient.to_bytes(),
        nullifier,
        amount,
        cur_slot + 150,
        fixture_proof(),
        &[authority.pubkey()], // quorum co-signers (#260); 1 active validator → threshold 1
    )
    .expect("withdraw ix");
    let bh = rpc.get_latest_blockhash().expect("blockhash");
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&authority.pubkey()), &[&authority], bh);

    // Bounded confirm — a withdrawal that never lands fails fast here
    // rather than wedging the runner the way #164's unbounded confirm did.
    let sig = confirm_within(&rpc, &tx, Duration::from_secs(30))
        .expect("authority withdrawal must confirm");
    log::info!("authority withdrawal confirmed: {}", sig);

    // The nullifier PDA is `init`'d by the settlement — its existence is
    // the on-chain record that this note was spent.
    let (nullifier_pda, _) = derive_nullifier_account(&program_id, &nullifier);
    assert!(
        rpc.get_account(&nullifier_pda).is_ok(),
        "nullifier PDA must exist after a successful settlement"
    );

    // The recipient receives amount - fee; the fee stays in the vault as the
    // settling validator's reward, so the vault is debited only by the payout.
    let vault_after = rpc.get_balance(&vault_pda).expect("vault balance after");
    assert_eq!(
        vault_before - vault_after,
        payout,
        "vault must be debited by the payout (amount - fee); the fee stays in the vault"
    );
    assert_eq!(
        rpc.get_balance(&recipient).expect("recipient balance"),
        payout,
        "recipient must receive amount - fee"
    );
}

/// Fund a fresh attacker keypair (not the bridge authority, not a validator).
fn fund_new_attacker(rpc: &RpcClient) -> Keypair {
    let kp = Keypair::new();
    fund_keypair(rpc, &kp, 2_000_000_000).expect("airdrop attacker");
    kp
}
