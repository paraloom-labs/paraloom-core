//! #164 acceptance test: withdrawal-consensus → on-chain settlement, end to
//! end against a real `solana-test-validator`, with **real Groth16
//! verification** gating every vote — no hard-coded approvals.
//!
//! What this proves (the security claim #164 calls structurally absent from
//! the running binary):
//!
//!   * A genuinely valid withdrawal proof is accepted by the production
//!     verifier (`ProofVerifier::verify_withdraw`), the validator quorum
//!     votes `Valid` off the back of that verification, and the approved
//!     withdrawal settles on chain via `ResultSubmitter` — the on-chain
//!     `nullifier_account` PDA appears and the vault is debited.
//!   * A tampered proof is *rejected* by the same verifier, the quorum does
//!     not approve, and nothing settles on chain.
//!
//! Honest scope notes:
//!   * The verifying key is produced by an in-process trusted setup and
//!     injected via `WITHDRAWAL_VERIFYING_KEY_PATH`, so the test is hermetic
//!     and needs no committed ceremony key (the real ceremony keys are
//!     git-ignored). The proof is generated against the matching proving
//!     key, so verification exercises real Groth16 — not a stub.
//!   * The single-deposit pool root equals the note commitment, which is why
//!     a depth-0 (`input_path: None`) circuit — the same shape the node's
//!     `load_withdraw_verifying_key` sets up — both satisfies the circuit and
//!     matches the on-chain/pool merkle root.
//!   * On-chain Groth16 verification of the proof is out of scope (#165 /
//!     SIMD-0388): the program accepts any non-empty proof signed by the
//!     bridge authority, so the consensus quorum is the verification gate —
//!     exactly what this exercises.
//!   * Each validator's vote is computed by the production
//!     `ProofVerifier::verify_withdraw` against the injected key, standing in
//!     for the networked validator set running the identical check.
//!
//! Ignored by default; CI runs it via the bridge-e2e workflow with
//! `--ignored --test-threads=1` after installing the Solana CLI.

mod common;
use common::solana_validator::{
    fund_new_keypair, paraloom_program_so, SubprocessValidator, PARALOOM_PROGRAM_ID,
};

use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use paraloom::bridge::solana::BridgeRpc;
use paraloom::bridge::solana::{
    create_deposit_instruction, create_initialize_instruction, derive_bridge_vault,
    derive_nullifier_account, RealBridgeRpc, ResultSubmitter,
};
use paraloom::bridge::{BridgeConfig, BridgeStats, WithdrawalRequest, EXPECTED_PROGRAM_VERSION};
use paraloom::consensus::withdrawal::{
    VerificationVote, WithdrawalVerificationRequest, WithdrawalVerificationResult,
};
use paraloom::consensus::WithdrawalVerificationCoordinator;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use paraloom::privacy::proof::ProofVerifier;
use paraloom::privacy::transaction::WithdrawTx;
use paraloom::privacy::{DepositTx, Nullifier, ShieldedAddress, ShieldedPool};
use paraloom::types::NodeId;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{write_keypair_file, Signer};
use solana_sdk::transaction::Transaction;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The seeded, depth-0 circuit whose structure the node's
/// `load_withdraw_verifying_key` sets up. Setup only needs the shape, so the
/// scalar witnesses are zero and `input_path` is `None`.
fn setup_shape() -> WithdrawCircuit {
    WithdrawCircuit {
        merkle_root: Some([0u8; 32]),
        nullifier: Some([0u8; 32]),
        withdraw_amount: Some(0),
        input_value: Some(0),
        input_randomness: Some([0u8; 32]),
        input_recipient: Some([0u8; 32]),
        input_path: None,
        secret: Some([0u8; 32]),
    }
}

/// Build a `WithdrawTx` carrying `proof` for the production verifier. The
/// merkle root is the (single-leaf) pool root, which equals the commitment.
fn withdraw_tx(
    nullifier: &Nullifier,
    amount: u64,
    merkle_root: [u8; 32],
    proof: Vec<u8>,
) -> WithdrawTx {
    WithdrawTx {
        tx_id: "e2e-164".to_string(),
        input_nullifier: nullifier.clone(),
        amount,
        to_public: vec![7u8; 32],
        zk_proof: proof,
        merkle_root,
        fee: 0,
        timestamp: 0,
    }
}

/// Each "validator" votes by running the production verifier against the
/// injected key — not a hard-coded `Valid`.
fn vote_for(tx: &WithdrawTx) -> VerificationVote {
    match ProofVerifier::verify_withdraw(tx) {
        r if r.is_valid() => VerificationVote::Valid,
        other => VerificationVote::Invalid {
            reason: format!("{:?}", other),
        },
    }
}

// Multi-threaded so the overall timeout fires even while a blocking RPC
// call is parked on a worker thread; otherwise a stuck on-chain confirm
// could hang the whole CI job instead of failing this test with a log
// trail. Each phase logs a `PHASE …` marker (visible under --nocapture),
// so the last marker printed before a timeout pinpoints where it stuck.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires solana-test-validator; run in CI via bridge-e2e workflow"]
async fn withdrawal_consensus_settles_on_chain() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    tokio::time::timeout(std::time::Duration::from_secs(180), run_consensus_e2e())
        .await
        .expect("E2E exceeded 180s — see the last 'PHASE' log line for where it stuck");
}

async fn run_consensus_e2e() {
    // ── Trusted setup + inject the verifying key the verifier will use ──
    log::info!("PHASE 1: groth16 trusted setup + inject verifying key");
    let mut rng = StdRng::seed_from_u64(0);
    let (pk, vk) = Groth16ProofSystem::setup(setup_shape(), &mut rng).expect("groth16 setup");
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .expect("serialize vk");
    let vk_path = std::env::temp_dir().join("paraloom_164_vk.key");
    std::fs::write(&vk_path, &vk_bytes).expect("write vk");
    // ProofVerifier reads this env var before falling back to the ceremony
    // key (set once; this is the test binary's only verifier key).
    std::env::set_var("WITHDRAWAL_VERIFYING_KEY_PATH", &vk_path);

    // ── Validator + bridge authority + on-chain init + vault funding ────
    log::info!("PHASE 2: launching solana-test-validator on :8903");
    let validator = SubprocessValidator::launch_with_programs(
        8903,
        &[(PARALOOM_PROGRAM_ID, paraloom_program_so())],
    )
    .expect("validator must boot with paraloom_program");
    let rpc = validator.rpc_client();
    log::info!("PHASE 3: airdropping bridge authority");
    let authority = fund_new_keypair(&rpc, 5_000_000_000).expect("airdrop authority");
    let authority_path = std::env::temp_dir().join("paraloom_164_authority.json");
    write_keypair_file(&authority, &authority_path).expect("write authority keypair");

    let program_id: Pubkey = PARALOOM_PROGRAM_ID.parse().unwrap();
    log::info!("PHASE 4: initialize bridge on-chain");
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

    log::info!("PHASE 5: fund vault via on-chain deposit");
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let deposit_amount: u64 = 2_000_000;
    let deposit_ix = create_deposit_instruction(
        &program_id,
        &authority.pubkey(),
        &vault_pda,
        deposit_amount,
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
    let vault_before = rpc.get_balance(&vault_pda).expect("vault before");

    // ── Shielded pool note → single-leaf root == commitment ─────────────
    log::info!("PHASE 6: shielded-pool deposit");
    let pool = Arc::new(ShieldedPool::new());
    let recipient_bytes: [u8; 32] = [42u8; 32];
    let randomness = [4u8; 32]; // doubles as the spending key / secret
    let pool_fee = 1_000u64;
    let pool_deposit = 1_000_000u64;
    let deposit_tx = DepositTx::new(
        vec![0x01; 32],
        pool_deposit,
        ShieldedAddress(recipient_bytes),
        randomness,
        pool_fee,
    );
    let note = deposit_tx.output_note.clone();
    let net_amount = pool_deposit - pool_fee; // note value
    pool.deposit(note.clone(), net_amount)
        .await
        .expect("pool deposit");

    let commitment = note.commitment();
    let merkle_root: [u8; 32] = *commitment.as_bytes();
    assert_eq!(
        pool.root().await,
        merkle_root,
        "single-leaf pool root must equal the note commitment"
    );
    let nullifier = Nullifier::derive(&commitment, &randomness);
    let withdraw_amount = net_amount;

    // ── Real, verifying Groth16 proof (depth-0 witness) ─────────────────
    log::info!("PHASE 7: generate real Groth16 proof");
    let prove_circuit = WithdrawCircuit::with_witness(
        merkle_root,
        nullifier.0,
        withdraw_amount,
        note.amount,
        note.randomness,
        recipient_bytes,
        randomness, // secret == spending key, matching Nullifier::derive
        Vec::new(), // depth-0: no path, so commitment == merkle_root
    );
    let proof_obj = Groth16ProofSystem::prove(&pk, prove_circuit, &mut rng).expect("prove");
    let mut proof = Vec::new();
    proof_obj
        .serialize_compressed(&mut proof)
        .expect("serialize proof");

    // Anchor: the production verifier accepts this proof against the
    // injected key. If this fails, nothing downstream is meaningful.
    let good_tx = withdraw_tx(&nullifier, withdraw_amount, merkle_root, proof.clone());
    assert!(
        ProofVerifier::verify_withdraw(&good_tx).is_valid(),
        "honestly generated proof must verify under the injected key"
    );

    // ════════════ POSITIVE: real verification → quorum → settle ════════
    log::info!("PHASE 8: positive — register validators + cast verified votes");
    let coordinator = Arc::new(WithdrawalVerificationCoordinator::new());
    let validators: Vec<NodeId> = (0..10u8).map(|i| NodeId(vec![i])).collect();
    for v in &validators {
        coordinator.register_validator(v.clone()).await;
    }
    let request = WithdrawalVerificationRequest {
        request_id: "e2e-164-ok".to_string(),
        nullifier: nullifier.0,
        amount: withdraw_amount,
        recipient: recipient_bytes,
        proof: proof.clone(),
        fee: 0,
        timestamp: 0,
    };
    coordinator
        .start_verification(request.clone())
        .await
        .expect("start verification");
    for v in &validators {
        let vote = vote_for(&good_tx);
        assert!(
            matches!(vote, VerificationVote::Valid),
            "valid proof must vote Valid"
        );
        coordinator
            .submit_result(WithdrawalVerificationResult {
                request_id: request.request_id.clone(),
                validator: v.clone(),
                vote,
                timestamp: 0,
            })
            .await
            .expect("submit vote");
    }
    log::info!("PHASE 9: wait_for_consensus (quorum)");
    let consensus = coordinator
        .wait_for_consensus(&request.request_id)
        .await
        .expect("consensus reached");
    assert!(
        matches!(consensus, VerificationVote::Valid),
        "quorum must approve valid proof"
    );

    // Settle on chain via ResultSubmitter; verify_single_node re-verifies the
    // same proof against the injected key before submitting.
    let stats = Arc::new(RwLock::new(BridgeStats::default()));
    let bridge_rpc: Arc<dyn BridgeRpc> = Arc::new(RealBridgeRpc::new(rpc.clone()));
    let config = BridgeConfig {
        program_id: PARALOOM_PROGRAM_ID.to_string(),
        enabled: true,
        solana_rpc_url: validator.rpc_url(),
        poll_interval_secs: 1,
        authority_keypair_path: Some(authority_path.to_string_lossy().to_string()),
        ..Default::default()
    };
    let submitter = ResultSubmitter::new(config, bridge_rpc, Arc::clone(&pool), Arc::clone(&stats))
        .expect("submitter");
    log::info!("PHASE 10: submit consensus-approved withdrawal on-chain");
    let current_slot = rpc.get_slot().unwrap_or(0);
    let on_chain_request = WithdrawalRequest {
        nullifier: nullifier.0,
        amount: withdraw_amount,
        recipient: recipient_bytes,
        fee: 0,
        expiration_slot: current_slot + 150,
        proof: proof.clone(),
    };
    let sig = submitter
        .submit(on_chain_request)
        .await
        .expect("on-chain settlement");
    log::info!("settled on chain: {}", sig);

    // Assertions: nullifier PDA exists, vault debited.
    log::info!("PHASE 11: positive assertions (nullifier PDA + vault debit)");
    let (nullifier_pda, _) = derive_nullifier_account(&program_id, &nullifier.0);
    let nullifier_account = rpc
        .get_account(&nullifier_pda)
        .expect("nullifier PDA must exist after settlement");
    assert_eq!(
        nullifier_account.owner, program_id,
        "nullifier PDA owned by program"
    );
    let vault_after = rpc.get_balance(&vault_pda).expect("vault after");
    assert_eq!(
        vault_before - vault_after,
        withdraw_amount,
        "vault debited by the withdrawal amount"
    );
    assert!(
        pool.is_spent(&nullifier).await,
        "nullifier marked spent in pool"
    );

    // ════════════ NEGATIVE: tampered proof → rejected, no settle ═══════
    log::info!("PHASE 12: negative — tampered proof must be rejected");
    let mut bad_proof = proof.clone();
    bad_proof[0] ^= 0xFF; // corrupt the proof bytes
    let bad_randomness = [5u8; 32];
    let bad_deposit = DepositTx::new(
        vec![0x02; 32],
        pool_deposit,
        ShieldedAddress(recipient_bytes),
        bad_randomness,
        pool_fee,
    );
    let bad_note = bad_deposit.output_note.clone();
    pool.deposit(bad_note.clone(), net_amount)
        .await
        .expect("pool deposit 2");
    let bad_commitment = bad_note.commitment();
    let bad_root: [u8; 32] = *bad_commitment.as_bytes();
    let bad_nullifier = Nullifier::derive(&bad_commitment, &bad_randomness);

    let bad_tx = withdraw_tx(&bad_nullifier, withdraw_amount, bad_root, bad_proof.clone());
    assert!(
        !ProofVerifier::verify_withdraw(&bad_tx).is_valid(),
        "tampered proof must be rejected by the verifier"
    );

    let neg_coord = Arc::new(WithdrawalVerificationCoordinator::new());
    for v in &validators {
        neg_coord.register_validator(v.clone()).await;
    }
    let bad_request = WithdrawalVerificationRequest {
        request_id: "e2e-164-bad".to_string(),
        nullifier: bad_nullifier.0,
        amount: withdraw_amount,
        recipient: recipient_bytes,
        proof: bad_proof.clone(),
        fee: 0,
        timestamp: 0,
    };
    neg_coord
        .start_verification(bad_request.clone())
        .await
        .expect("start bad verification");
    for v in &validators {
        let vote = vote_for(&bad_tx);
        assert!(
            matches!(vote, VerificationVote::Invalid { .. }),
            "bad proof must vote Invalid"
        );
        let _ = neg_coord
            .submit_result(WithdrawalVerificationResult {
                request_id: bad_request.request_id.clone(),
                validator: v.clone(),
                vote,
                timestamp: 0,
            })
            .await;
    }
    let bad_consensus = neg_coord
        .check_consensus(&bad_request.request_id)
        .await
        .expect("check");
    assert!(
        !matches!(bad_consensus, Some(VerificationVote::Valid)),
        "quorum must NOT approve a tampered proof"
    );
    let (bad_pda, _) = derive_nullifier_account(&program_id, &bad_nullifier.0);
    assert!(
        rpc.get_account(&bad_pda).is_err(),
        "no nullifier PDA must exist for the rejected withdrawal"
    );

    let _ = std::fs::remove_file(&authority_path);
    let _ = std::fs::remove_file(&vk_path);
}
