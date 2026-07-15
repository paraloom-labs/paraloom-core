//! claim_rewards over the real reward flow: a `transact` withdrawal credits the
//! settling validator its 25 bps fee into `pending_rewards`, then `claim_rewards`
//! transfers that out of `bridge_vault`, zeros pending, and accumulates
//! `total_earnings`. The fee is credited by `transact` itself (the only path
//! that mints pending rewards) — the former `distribute_fee` admin shortcut was
//! removed as an unbacked drain surface, and the legacy off-chain-root
//! `withdraw` path was removed in favour of the program-owned-tree `transact`.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::transact_fixture_data as fx;
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;
/// Pre-fund the fixed recipient above rent so the tiny withdrawal credits an
/// existing account (see transact_test).
const RECIPIENT_PREFUND: u64 = 1_000_000_000;
/// The transact fixture withdraws `|ext_amount|` (500 units); the fee is
/// `500 * 25 / 10000 = 1` lamport, credited to the settling validator.
const EXPECTED_FEE: u64 = fx::FIXTURE_EXT_AMOUNT.unsigned_abs() * 25 / 10_000;

fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

async fn send(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn claim_rewards_drains_pending_and_accumulates_earnings() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let recipient = Pubkey::new_from_array(fx::FIXTURE_RECIPIENT);
    pt.add_account(
        recipient,
        Account {
            lamports: RECIPIENT_PREFUND,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    // An independent validator that co-signs the quorum. The settling authority
    // is excluded from its own tally, so this second validator is what actually
    // satisfies the quorum; the fee still accrues to the authority's validator.
    let cosigner = Keypair::new();
    let (cosigner_pda, _) =
        Pubkey::find_program_address(&[b"validator", cosigner.pubkey().as_ref()], &program_id);
    let (nf0_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_0], &program_id);
    let (nf1_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_1], &program_id);

    // initialize → init tree → init registry → register the settling authority.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 0x0004_0000,
                initial_merkle_root: [0u8; 32],
            }
            .data(),
            accounts: accounts::Initialize {
                bridge_state: state_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeMerkleTree {}.data(),
            accounts: accounts::InitializeMerkleTree {
                merkle_tree: tree_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Register an INDEPENDENT validator to co-sign the quorum. Fund it from the
    // payer (stake + fees), then self-register it (RegisterValidator is
    // permissionless). total_active_stake becomes 2 SOL; with the authority's
    // 1 SOL excluded, eligible stake is 1 SOL and the cosigner's 1 SOL clears it.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        solana_sdk::system_instruction::transfer(
            &payer.pubkey(),
            &cosigner.pubkey(),
            MIN_VALIDATOR_STAKE + 100_000_000,
        ),
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &cosigner,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: cosigner_pda,
                validator_registry: registry_pda,
                validator: cosigner.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Fund the vault (2 SOL) so it stays rent-exempt through the payout + claim.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        solana_sdk::system_instruction::transfer(&payer.pubkey(), &vault_pda, 2_000_000_000),
    )
    .await;

    // deposit_note the fixture's input note so the on-chain tree reaches
    // FIXTURE_ROOT (the root the transact proof proves membership against).
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::DepositNote {
                amount: fx::FIXTURE_DEPOSIT_AMOUNT,
                pubkey: fx::FIXTURE_DEPOSIT_PUBKEY,
                blinding: fx::FIXTURE_DEPOSIT_BLINDING,
            }
            .data(),
            accounts: accounts::DepositNote {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                merkle_tree: tree_pda,
                depositor: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // transact — credits EXPECTED_FEE to the settling validator's pending_rewards.
    // The authority is excluded from its own quorum, so the independent cosigner
    // supplies the satisfying (wallet, PDA) pair; the tx is signed by both.
    let transact_ix = Instruction {
        program_id,
        data: instruction::Transact {
            nullifiers: [fx::FIXTURE_NULLIFIER_0, fx::FIXTURE_NULLIFIER_1],
            output_commitments: [fx::FIXTURE_COMMITMENT_0, fx::FIXTURE_COMMITMENT_1],
            root: fx::FIXTURE_ROOT,
            ext_amount: fx::FIXTURE_EXT_AMOUNT,
            proof: fixture_proof(),
            expiration_slot: 0,
        }
        .data(),
        accounts: {
            let mut metas = accounts::Transact {
                bridge_state: state_pda,
                merkle_tree: tree_pda,
                bridge_vault: vault_pda,
                nullifier_account_0: nf0_pda,
                nullifier_account_1: nf1_pda,
                recipient,
                validator_account: validator_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None);
            // Quorum co-signer (#260): an INDEPENDENT registered validator,
            // co-signing as a (wallet, PDA) pair. The authority's own pair is
            // not needed — it is skipped in the tally.
            metas.push(AccountMeta::new_readonly(cosigner.pubkey(), true));
            metas.push(AccountMeta::new_readonly(cosigner_pda, false));
            metas
        },
    };
    let transact_tx = Transaction::new_signed_with_payer(
        &[transact_ix],
        Some(&upgrade_authority.pubkey()),
        &[&upgrade_authority, &cosigner],
        recent_blockhash,
    );
    banks_client.process_transaction(transact_tx).await.unwrap();

    // The fee is now pending; nothing claimed yet.
    let before = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let before = ValidatorAccount::try_deserialize(&mut before.data.as_slice()).unwrap();
    assert_eq!(before.pending_rewards, EXPECTED_FEE);
    assert_eq!(before.total_earnings, 0);

    // claim_rewards — pays pending out of the vault, zeros it, accumulates earnings.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::ClaimRewards {}.data(),
            accounts: accounts::ClaimRewards {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.pending_rewards, 0);
    assert_eq!(acc.total_earnings, EXPECTED_FEE);
}
