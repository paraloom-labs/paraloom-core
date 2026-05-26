//! #178 acceptance: the on-chain `withdraw` is authenticated.
//!
//! Reported by PerkinsFund: `Withdraw` declared a bare `authority: Signer`
//! with no `has_one`, so any signer could settle a withdrawal and drain the
//! vault. These tests assert the guards against a real `solana-test-validator`:
//!
//!   * a signer other than the bridge authority is rejected (`has_one`)
//!   * a proof longer than `MAX_PROOF_LEN` is rejected (`ProofTooLarge`)
//!
//! The first two are fast preflight rejections — no consensus, no
//! confirmation wait. The third (`authority_can_withdraw`) is the #164
//! Layer 1 happy path: the bridge authority settles a real withdrawal on
//! chain. It confirms with a bounded deadline (`confirm_within`) so a
//! settlement that never lands fails fast instead of hanging CI, and
//! asserts the on-chain effects (nullifier PDA created, vault debited,
//! recipient credited). Network-layer consensus is a separate test.
//!
//! Ignored by default; CI runs it via the bridge-e2e workflow with
//! `--ignored --test-threads=1` after installing the Solana CLI.

mod common;
use common::solana_validator::{
    confirm_within, fund_new_keypair, paraloom_program_so, SubprocessValidator, PARALOOM_PROGRAM_ID,
};
use paraloom::bridge::solana::{
    create_deposit_instruction, create_initialize_instruction, create_withdraw_instruction,
    derive_bridge_vault, derive_nullifier_account,
};
use paraloom::bridge::EXPECTED_PROGRAM_VERSION;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::Transaction;
use std::time::Duration;

/// Boot a validator, airdrop a fresh authority, initialize the bridge under
/// it, and fund the vault so a withdrawal reaches the on-chain guards rather
/// than failing early on an empty vault. Returns the validator, program id,
/// and the funded authority keypair.
fn bootstrap(port: u16) -> (SubprocessValidator, Pubkey, Keypair) {
    let validator = SubprocessValidator::launch_with_programs(
        port,
        &[(PARALOOM_PROGRAM_ID, paraloom_program_so())],
    )
    .expect("validator must boot with paraloom_program");
    let rpc = validator.rpc_client();
    let authority = fund_new_keypair(&rpc, 3_000_000_000).expect("airdrop authority");
    let program_id: Pubkey = PARALOOM_PROGRAM_ID.parse().unwrap();

    let init_ix = create_initialize_instruction(
        &program_id,
        &authority.pubkey(),
        EXPECTED_PROGRAM_VERSION,
        [0u8; 32],
    )
    .expect("init ix");
    let bh = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[init_ix],
        Some(&authority.pubkey()),
        &[&authority],
        bh,
    );
    rpc.send_and_confirm_transaction(&tx).expect("init tx");

    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let deposit_ix = create_deposit_instruction(
        &program_id,
        &authority.pubkey(),
        &vault_pda,
        2_000_000,
        [9u8; 32],
        [11u8; 32],
    )
    .expect("deposit ix");
    let bh = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[deposit_ix],
        Some(&authority.pubkey()),
        &[&authority],
        bh,
    );
    rpc.send_and_confirm_transaction(&tx).expect("deposit tx");

    (validator, program_id, authority)
}

#[test]
#[ignore = "requires solana-test-validator; run in CI via bridge-e2e workflow"]
fn unauthorized_signer_cannot_withdraw() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (validator, program_id, _authority) = bootstrap(8904);
    let rpc = validator.rpc_client();

    // A signer that is NOT the bridge authority attempts a well-formed
    // withdrawal. `has_one = authority` must reject it at account validation.
    let attacker = fund_new_keypair(&rpc, 2_000_000_000).expect("airdrop attacker");
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

    // The authority itself submits, but with a proof past MAX_PROOF_LEN (256).
    // The handler's length guard must reject it.
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

    // The bridge authority settles a well-formed withdrawal. bootstrap
    // funded the vault with 2_000_000 lamports, so this 1_000_000 draw is
    // within balance and must pass every on-chain guard.
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let vault_before = rpc.get_balance(&vault_pda).expect("vault balance before");

    let recipient = Keypair::new();
    let nullifier = [77u8; 32];
    let amount = 1_000_000u64;
    let cur_slot = rpc.get_slot().unwrap_or(0);
    let ix = create_withdraw_instruction(
        &program_id,
        &authority.pubkey(),
        &vault_pda,
        recipient.pubkey().to_bytes(),
        nullifier,
        amount,
        cur_slot + 150,
        vec![1u8; 192],
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

    // Vault debited by exactly `amount`; recipient credited the same. The
    // authority pays the transaction fee, so the vault delta is clean.
    let vault_after = rpc.get_balance(&vault_pda).expect("vault balance after");
    assert_eq!(
        vault_before - vault_after,
        amount,
        "vault must be debited by exactly the withdrawn amount"
    );
    assert_eq!(
        rpc.get_balance(&recipient.pubkey())
            .expect("recipient balance"),
        amount,
        "recipient must receive exactly the withdrawn amount"
    );
}
