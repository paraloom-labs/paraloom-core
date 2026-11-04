//! On-chain e2e for `transact_spl` (#779): the SPL analogue of the native
//! `transact` test. Flow: initialize -> merkle tree -> validator registry ->
//! register two validators (settling authority + independent cosigner) ->
//! init the asset vault + open its cap -> `deposit_note_spl` recreates the
//! fixture's spent note (tree reaches `SPL_FIXTURE_ROOT` and funds the vault)
//! -> `transact_spl` spends it, paying a token withdraw out of the asset vault
//! to the recipient token account and the fee to the validator's token account.
//!
//! The proof fixture is emitted by `emit_transact_spl_fixture` from the SAME
//! ceremony keys as the native fixture — only the `asset` public input differs
//! — so a green run proves the deployed transact VK verifies an SPL-asset spend
//! with no new ceremony.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::merkle_tree::{IncrementalMerkleTree, TREE_DEPTH, ZERO_HASHES};
use paraloom_program::transact_spl_fixture_data as fx;
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount};
use solana_program_test::{tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, program_test, TEST_TOKEN_FUND};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

async fn send(
    banks: &mut solana_program_test::BanksClient,
    blockhash: solana_sdk::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], blockhash);
    banks.process_transaction(tx).await.unwrap();
}

/// Bake an initialized SPL mint at a FIXED address (so it matches the fixture's
/// `SPL_FIXTURE_MINT`, whose bytes are the proof's asset field element).
fn bake_mint_at(pt: &mut ProgramTest, mint: Pubkey) {
    use anchor_lang::solana_program::program_option::COption;
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::Some(Pubkey::new_unique()),
        supply: 1_000_000_000_000_000,
        decimals: 0,
        is_initialized: true,
        freeze_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    pt.add_account(
        mint,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
}

/// Bake an initialized SPL token account at a FIXED address.
fn bake_token_account_at(pt: &mut ProgramTest, addr: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    use anchor_lang::solana_program::program_option::COption;
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: COption::None,
        state: spl_token::state::AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    }
    .pack_into_slice(&mut data);
    pt.add_account(
        addr,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        },
    );
}

fn token_amount(account: &Account) -> u64 {
    spl_token::state::Account::unpack(&account.data).unwrap().amount
}

/// The custom (program) error code of a failed transaction, if it failed
/// with one — lets the #1337 tests distinguish *where* a spend was rejected
/// (Anchor account validation vs. the handler's own checks vs. proof
/// verification).
fn extract_custom_error(err: &solana_program_test::BanksClientError) -> Option<u32> {
    match err {
        solana_program_test::BanksClientError::TransactionError(
            solana_sdk::transaction::TransactionError::InstructionError(
                _,
                solana_sdk::instruction::InstructionError::Custom(code),
            ),
        ) => Some(*code),
        _ => None,
    }
}


/// Everything the `transact_spl` tests share: bridge + tree + registry
/// initialized, two validators registered, the fixture note deposited (tree
/// at `SPL_FIXTURE_ROOT`, vault funded). Extracted from the original
/// withdrawal e2e so the #1337 tests can drive the same settled state.
struct FixtureContext {
    banks: solana_program_test::BanksClient,
    upgrade_authority: Keypair,
    cosigner: Keypair,
    blockhash: solana_sdk::hash::Hash,
    program_id: Pubkey,
    state_pda: Pubkey,
    tree_pda: Pubkey,
    registry_pda: Pubkey,
    validator_pda: Pubkey,
    cosigner_pda: Pubkey,
    asset_mint: Pubkey,
    asset_vault: Pubkey,
    asset_vault_authority: Pubkey,
    recipient_token: Pubkey,
    fee_token: Pubkey,
    fee_token_wrong_owner: Pubkey,
    nf0_pda: Pubkey,
    nf1_pda: Pubkey,
    vault_before: u64,
}

async fn setup_spl_fixture() -> FixtureContext {
    let program_id = paraloom_program::ID;
    let mut pt = program_test(program_id);
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    // Staking mint for the registry/quorum (independent of the shielded asset).
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let authority_token = add_token_account(
        &mut pt,
        stake_mint,
        upgrade_authority.pubkey(),
        TEST_TOKEN_FUND,
    );
    let cosigner = Keypair::new();
    pt.add_account(
        cosigner.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let cosigner_token =
        add_token_account(&mut pt, stake_mint, cosigner.pubkey(), TEST_TOKEN_FUND);

    // The shielded SPL asset, its depositor, the payout recipient, and the fee
    // account — all keyed to the fixture's fixed mint/recipient addresses.
    let asset_mint = Pubkey::new_from_array(fx::SPL_FIXTURE_MINT);
    bake_mint_at(&mut pt, asset_mint);
    let depositor = Keypair::new();
    pt.add_account(
        depositor.pubkey(),
        Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let depositor_token = add_token_account(
        &mut pt,
        asset_mint,
        depositor.pubkey(),
        fx::SPL_FIXTURE_DEPOSIT_AMOUNT,
    );
    // Payout destination at the fixture's bound token-account address.
    let recipient_token = Pubkey::new_from_array(fx::SPL_FIXTURE_RECIPIENT_TOKEN_ACCOUNT);
    bake_token_account_at(&mut pt, recipient_token, asset_mint, Pubkey::new_unique(), 0);
    // The settling validator's fee account for the withdrawn asset.
    let fee_token = add_token_account(&mut pt, asset_mint, upgrade_authority.pubkey(), 0);
    // A token account for the same mint owned by somebody else — used by the
    // guard tests to prove withdrawals still reject a fee account the
    // settling authority does not own.
    let fee_token_wrong_owner = Pubkey::new_unique();
    bake_token_account_at(&mut pt, fee_token_wrong_owner, asset_mint, Pubkey::new_unique(), 0);

    let (mut banks, _payer, blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let (cosigner_pda, _) =
        Pubkey::find_program_address(&[b"validator", cosigner.pubkey().as_ref()], &program_id);
    let (asset_vault, _) =
        Pubkey::find_program_address(&[b"asset_vault", asset_mint.as_ref()], &program_id);
    let (asset_vault_authority, _) =
        Pubkey::find_program_address(&[b"asset_vault_authority"], &program_id);
    let (asset_config, _) =
        Pubkey::find_program_address(&[b"asset_config", asset_mint.as_ref()], &program_id);
    let (nf0_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", fx::SPL_FIXTURE_NULLIFIER_0.as_ref()], &program_id);
    let (nf1_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", fx::SPL_FIXTURE_NULLIFIER_1.as_ref()], &program_id);

    // 1. initialize bridge state.
    send(
        &mut banks,
        blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 1,
                initial_merkle_root: [0u8; 32],
            }
            .data(),
            accounts: accounts::Initialize {
                bridge_state: state_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // 2. initialize the merkle tree.
    send(
        &mut banks,
        blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeMerkleTree {}.data(),
            accounts: accounts::InitializeMerkleTree {
                merkle_tree: tree_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // 3. initialize the validator registry.
    send(
        &mut banks,
        blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
                stake_vault_authority: Pubkey::find_program_address(
                    &[b"stake_vault_authority"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
                rent: solana_sdk::sysvar::rent::ID,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // 4. init the asset vault + config, then open the per-asset cap.
    send(
        &mut banks,
        blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitAssetVault {}.data(),
            accounts: accounts::InitAssetVault {
                authority: upgrade_authority.pubkey(),
                mint: asset_mint,
                asset_vault,
                asset_vault_authority,
                asset_config,
                program_data: program_data_pda,
                token_program: spl_token::id(),
                system_program: system_program::ID,
                rent: solana_sdk::sysvar::rent::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks,
        blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SetAssetDepositCap {
                new_cap: fx::SPL_FIXTURE_DEPOSIT_AMOUNT * 10,
            }
            .data(),
            accounts: accounts::SetAssetDepositCap {
                asset_config,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // 5. register the settling authority as a validator.
    send(
        &mut banks,
        blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_account: validator_pda,
                validator_token_account: authority_token,
                stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
                token_program: spl_token::id(),
                validator_registry: registry_pda,
                validator: upgrade_authority.pubkey(),
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // 5b. register an independent cosigner validator (satisfies the quorum).
    send(
        &mut banks,
        blockhash,
        &cosigner,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_account: cosigner_pda,
                validator_token_account: cosigner_token,
                stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
                token_program: spl_token::id(),
                validator_registry: registry_pda,
                validator: cosigner.pubkey(),
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // 6. deposit_note_spl the fixture's input note: appends c0 at leaf 0 (tree
    //    reaches SPL_FIXTURE_ROOT) and funds the vault with the input amount.
    send(
        &mut banks,
        blockhash,
        &depositor,
        Instruction {
            program_id,
            data: instruction::DepositNoteSpl {
                amount: fx::SPL_FIXTURE_DEPOSIT_AMOUNT,
                pubkey: fx::SPL_FIXTURE_DEPOSIT_PUBKEY,
                blinding: fx::SPL_FIXTURE_DEPOSIT_BLINDING,
            }
            .data(),
            accounts: accounts::DepositNoteSpl {
                bridge_state: state_pda,
                asset_config,
                mint: asset_mint,
                asset_vault,
                depositor_token_account: depositor_token,
                merkle_tree: tree_pda,
                depositor: depositor.pubkey(),
                token_program: spl_token::id(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Load-bearing cross-check: the on-chain tree reached the fixture root.
    let tree_raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut tree_raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 1, "one note deposited");
    assert_eq!(
        tree.root, fx::SPL_FIXTURE_ROOT,
        "on-chain tree root must equal the host circuit root the proof proves"
    );
    let vault_before = token_amount(&banks.get_account(asset_vault).await.unwrap().unwrap());
    assert_eq!(vault_before, fx::SPL_FIXTURE_DEPOSIT_AMOUNT, "vault funded by deposit");

    FixtureContext {
        banks,
        upgrade_authority,
        cosigner,
        blockhash,
        program_id,
        state_pda,
        tree_pda,
        registry_pda,
        validator_pda,
        cosigner_pda,
        asset_mint,
        asset_vault,
        asset_vault_authority,
        recipient_token,
        fee_token,
        fee_token_wrong_owner,
        nf0_pda,
        nf1_pda,
        vault_before,
    }
}

#[tokio::test]
async fn transact_spl_settles_a_token_withdrawal() {
    let mut ctx = setup_spl_fixture().await;

    // 7. transact_spl: spend the note, pay the token withdraw out of the vault.
    let transact_ix = Instruction {
        program_id: ctx.program_id,
        data: instruction::TransactSpl {
            nullifiers: [fx::SPL_FIXTURE_NULLIFIER_0, fx::SPL_FIXTURE_NULLIFIER_1],
            output_commitments: [fx::SPL_FIXTURE_COMMITMENT_0, fx::SPL_FIXTURE_COMMITMENT_1],
            root: fx::SPL_FIXTURE_ROOT,
            ext_amount: fx::SPL_FIXTURE_EXT_AMOUNT,
            proof: {
                let mut p = Vec::new();
                p.extend_from_slice(&fx::SPL_FIXTURE_PROOF_A);
                p.extend_from_slice(&fx::SPL_FIXTURE_PROOF_B);
                p.extend_from_slice(&fx::SPL_FIXTURE_PROOF_C);
                p
            },
        }
        .data(),
        accounts: {
            let mut metas = accounts::TransactSpl {
                bridge_state: ctx.state_pda,
                merkle_tree: ctx.tree_pda,
                mint: ctx.asset_mint,
                asset_vault: ctx.asset_vault,
                asset_vault_authority: ctx.asset_vault_authority,
                recipient_token_account: ctx.recipient_token,
                fee_token_account: ctx.fee_token,
                nullifier_account_0: ctx.nf0_pda,
                nullifier_account_1: ctx.nf1_pda,
                validator_account: ctx.validator_pda,
                validator_registry: ctx.registry_pda,
                authority: ctx.upgrade_authority.pubkey(),
                token_program: spl_token::id(),
                system_program: system_program::ID,
            }
            .to_account_metas(None);
            // The accounts struct no longer marks the two token accounts
            // `mut` (they are unchecked there since #1337); the settlement
            // builder marks them writable, as the payout/fee CPIs need.
            metas[5].is_writable = true; // recipient_token_account
            metas[6].is_writable = true; // fee_token_account
            metas.push(AccountMeta::new_readonly(ctx.cosigner.pubkey(), true));
            metas.push(AccountMeta::new_readonly(ctx.cosigner_pda, false));
            metas
        },
    };
    // Raise the compute-unit ceiling, exactly as the on-chain settlement path
    // prepends it (cosign_message): the Groth16 verify plus the two token CPIs
    // exceed the 200k default, which only bites under the BPF VM (native tests
    // enforce no CU limit). Without it the BPF run fails "Computational budget
    // exceeded" even though the instruction is correct.
    let transact_tx = Transaction::new_signed_with_payer(
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            transact_ix,
        ],
        Some(&ctx.upgrade_authority.pubkey()),
        &[&ctx.upgrade_authority, &ctx.cosigner],
        ctx.blockhash,
    );
    ctx.banks.process_transaction(transact_tx).await.unwrap();

    let gross = fx::SPL_FIXTURE_EXT_AMOUNT.unsigned_abs();
    let fee = gross * 25 / 10_000;
    let payout = gross - fee;

    // Recipient token account received the payout net of the fee.
    let recipient_after = token_amount(&ctx.banks.get_account(ctx.recipient_token).await.unwrap().unwrap());
    assert_eq!(recipient_after, payout, "recipient token account gains |ext| - fee");
    // The fee landed in the settling validator's token account.
    let fee_after = token_amount(&ctx.banks.get_account(ctx.fee_token).await.unwrap().unwrap());
    assert_eq!(fee_after, fee, "fee paid to the validator's token account");
    // The vault paid out exactly gross.
    let vault_after = token_amount(&ctx.banks.get_account(ctx.asset_vault).await.unwrap().unwrap());
    assert_eq!(ctx.vault_before - vault_after, gross, "vault debited by gross");

    // Both input nullifiers were recorded.
    for (pda, expected) in [
        (ctx.nf0_pda, fx::SPL_FIXTURE_NULLIFIER_0),
        (ctx.nf1_pda, fx::SPL_FIXTURE_NULLIFIER_1),
    ] {
        let raw = ctx.banks.get_account(pda).await.unwrap().expect("nullifier PDA exists");
        let nul = NullifierAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
        assert_eq!(nul.nullifier, expected);
        assert_eq!(nul.withdrawal_id, 1);
    }

    // Both output commitments appended: leaf 0 (deposit) + 2 outputs = 3.
    let tree_raw = ctx.banks.get_account(ctx.tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut tree_raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 3, "two output commitments appended");
    assert_ne!(tree.root, ZERO_HASHES[TREE_DEPTH]);
    assert!(tree.is_known_root(fx::SPL_FIXTURE_ROOT));

    let state_raw = ctx.banks.get_account(ctx.state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.withdrawal_count, 1);
}

/// Build a `transact_spl` instruction against the fixture state with the
/// given token accounts — same account order and writable flags as the
/// co-sign settlement builder (`create_transact_spl_instruction` marks the
/// recipient and fee accounts `AccountMeta::new`, i.e. writable).
fn transact_spl_ix(
    ctx: &FixtureContext,
    ext_amount: i64,
    recipient_token_account: Pubkey,
    fee_token_account: Pubkey,
) -> Instruction {
    let mut metas = accounts::TransactSpl {
        bridge_state: ctx.state_pda,
        merkle_tree: ctx.tree_pda,
        mint: ctx.asset_mint,
        asset_vault: ctx.asset_vault,
        asset_vault_authority: ctx.asset_vault_authority,
        recipient_token_account,
        fee_token_account,
        nullifier_account_0: ctx.nf0_pda,
        nullifier_account_1: ctx.nf1_pda,
        validator_account: ctx.validator_pda,
        validator_registry: ctx.registry_pda,
        authority: ctx.upgrade_authority.pubkey(),
        token_program: spl_token::id(),
        system_program: system_program::ID,
    }
    .to_account_metas(None);
    metas[5].is_writable = true; // recipient_token_account
    metas[6].is_writable = true; // fee_token_account
    metas.push(AccountMeta::new_readonly(ctx.cosigner.pubkey(), true));
    metas.push(AccountMeta::new_readonly(ctx.cosigner_pda, false));
    Instruction {
        program_id: ctx.program_id,
        data: instruction::TransactSpl {
            nullifiers: [fx::SPL_FIXTURE_NULLIFIER_0, fx::SPL_FIXTURE_NULLIFIER_1],
            output_commitments: [fx::SPL_FIXTURE_COMMITMENT_0, fx::SPL_FIXTURE_COMMITMENT_1],
            root: fx::SPL_FIXTURE_ROOT,
            ext_amount,
            proof: {
                let mut p = Vec::new();
                p.extend_from_slice(&fx::SPL_FIXTURE_PROOF_A);
                p.extend_from_slice(&fx::SPL_FIXTURE_PROOF_B);
                p.extend_from_slice(&fx::SPL_FIXTURE_PROOF_C);
                p
            },
        }
        .data(),
        accounts: metas,
    }
}

/// Submit a `transact_spl` instruction and return its custom error code.
async fn transact_error(ctx: &mut FixtureContext, ix: Instruction) -> Option<u32> {
    let tx = Transaction::new_signed_with_payer(
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        Some(&ctx.upgrade_authority.pubkey()),
        &[&ctx.upgrade_authority, &ctx.cosigner],
        ctx.blockhash,
    );
    let err = ctx.banks.process_transaction(tx).await.unwrap_err();
    extract_custom_error(&err)
}

#[tokio::test]
async fn transact_spl_accepts_uninitialized_token_accounts_for_internal_transfer() {
    let mut ctx = setup_spl_fixture().await;

    // Internal shielded transfer (#1337): `ext_amount == 0`, and the wallet
    // passes `Pubkey::default()` for the recipient (its `recipientHex` is
    // "00".repeat(32)) plus a default fee account. No tokens move and no fee
    // is paid, so the program must not demand initialized token accounts.
    // The fixture proof binds the *withdrawal's* ext_data_hash, so a correct
    // program rejects this spend at proof verification (InvalidProof, 6002) —
    // what must NOT happen is the unmodified program's Anchor-boundary
    // rejection (AccountOwnedByWrongProgram 3007 / AccountNotInitialized
    // 3012), which is what breaks every private SPL transfer on-chain.
    let ix = transact_spl_ix(&ctx, 0, Pubkey::default(), Pubkey::default());
    let err_code = transact_error(&mut ctx, ix).await;
    assert_ne!(
        err_code,
        Some(3007),
        "internal transfer must not fail account validation with AccountOwnedByWrongProgram"
    );
    assert_ne!(
        err_code,
        Some(3012),
        "internal transfer must not fail account validation with AccountNotInitialized"
    );
    assert_eq!(
        err_code,
        Some(6002),
        "internal transfer must reach proof verification and fail there (InvalidProof)"
    );
}

#[tokio::test]
async fn transact_spl_withdrawal_rejects_uninitialized_fee_token_account() {
    let mut ctx = setup_spl_fixture().await;

    // Withdrawal (`ext_amount < 0`, fee > 0): the fee is paid inline to the
    // fee token account, so a missing one must still be rejected —
    // relaxing the internal-transfer path must not weaken withdrawals.
    // The expected code is AccountNotInitialized (3012): the code the
    // program has always produced for a nonexistent token account, which
    // the handler's manual validation preserves.
    let uninitialized_fee_account = Keypair::new().pubkey();
    let ix = transact_spl_ix(
        &ctx,
        fx::SPL_FIXTURE_EXT_AMOUNT,
        ctx.recipient_token,
        uninitialized_fee_account,
    );
    let err_code = transact_error(&mut ctx, ix).await;
    assert_eq!(
        err_code,
        Some(3012),
        "withdrawal with a missing fee token account must be rejected with AccountNotInitialized"
    );
}

#[tokio::test]
async fn transact_spl_withdrawal_rejects_fee_token_account_not_owned_by_authority() {
    let mut ctx = setup_spl_fixture().await;

    // The fee must land in the settling authority's own token account: a
    // valid token account for the mint owned by somebody else must still be
    // rejected (the accounts struct's old `token::authority = authority`
    // constraint, now enforced in the handler where the fee is paid).
    let ix = transact_spl_ix(
        &ctx,
        fx::SPL_FIXTURE_EXT_AMOUNT,
        ctx.recipient_token,
        ctx.fee_token_wrong_owner,
    );
    let err_code = transact_error(&mut ctx, ix).await;
    assert_eq!(
        err_code,
        Some(anchor_lang::error::ErrorCode::ConstraintTokenOwner as u32),
        "withdrawal with a fee account owned by someone else must be rejected with ConstraintTokenOwner"
    );
}
