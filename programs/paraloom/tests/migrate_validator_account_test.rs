//! On-chain test for `migrate_validator_account`.
//!
//! Adding the two unbonding fields (`unbonding_amount`, `unbonding_slot`) to
//! `ValidatorAccount` grew its on-chain layout by 16 bytes. Already-deployed
//! validator PDAs carry the pre-unbonding (legacy) layout and must be grown
//! in place before they can be read as the new type. `migrate_validator_account`
//! is the upgrade-authority-gated, idempotent grow that does this; the added
//! tail zero-fills, which reads as "nothing unbonding".
//!
//! This seeds a raw legacy-sized `ValidatorAccount` (correct discriminator,
//! zeroed body, old length) directly into the test bank, migrates it, and
//! asserts the account is now the full current size, the new fields read 0,
//! and it typed-deserializes.

use anchor_lang::prelude::*;
use anchor_lang::{Discriminator, InstructionData, Space, ToAccountMetas};
use paraloom_program::{
    accounts, instruction, ValidatorAccount, MIN_VALIDATOR_STAKE, UNBONDING_SLOTS,
};
use solana_program_test::{
    processor, tokio, BanksClientError, ProgramTest, ProgramTestBanksClientExt, ProgramTestContext,
};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    rent::Rent,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

/// Send `ix` signed by `signer` (also the fee payer) on a fresh blockhash.
async fn send(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    ix: Instruction,
) -> std::result::Result<(), BanksClientError> {
    let blockhash = ctx.get_new_latest_blockhash().await.expect("new blockhash");
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], blockhash);
    ctx.banks_client.process_transaction(tx).await
}

#[tokio::test]
async fn migrate_grows_legacy_validator_account() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    // Current size = 8-byte discriminator + INIT_SPACE. The legacy layout is
    // 16 bytes shorter (the two u64 unbonding fields did not exist yet).
    let new_len = 8 + ValidatorAccount::INIT_SPACE;
    let legacy_len = new_len - 16;

    // The wallet the legacy PDA belongs to — only used as a seed / instruction
    // arg here; no signature is needed from it.
    let validator_wallet = Keypair::new().pubkey();
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator_wallet.as_ref()], &program_id);

    // Seed a raw legacy account: correct Anchor discriminator, zeroed body,
    // legacy length, owned by the program. Over-fund it so the migration's
    // realloc needs no top-up (it still grows the buffer).
    let mut data = ValidatorAccount::DISCRIMINATOR.to_vec();
    data.resize(legacy_len, 0);
    pt.add_account(
        validator_pda,
        Account {
            lamports: 10_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let migrate_ix = Instruction {
        program_id,
        // Anchor names the arg field after the handler param (`_validator`);
        // only the byte order matters on the wire.
        data: instruction::MigrateValidatorAccount {
            _validator: validator_wallet,
        }
        .data(),
        accounts: accounts::MigrateValidatorAccount {
            validator_account: validator_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    let mut tx =
        Transaction::new_with_payer(&[migrate_ix.clone()], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.expect("migrate");

    let raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.data.len(), new_len, "account grown to current layout");
    // The appended tail (the two new u64 fields) is zero.
    assert_eq!(&raw.data[legacy_len..], &vec![0u8; 16][..]);

    let acc = ValidatorAccount::try_deserialize(&mut raw.data.as_slice())
        .expect("legacy account now deserializes as the current type");
    assert_eq!(acc.unbonding_amount, 0);
    assert_eq!(acc.unbonding_slot, 0);

    // Idempotent: migrating an already-migrated account is a no-op that still
    // succeeds and leaves the size unchanged.
    let new_blockhash = banks_client
        .get_new_latest_blockhash(&recent_blockhash)
        .await
        .expect("new blockhash");
    let mut tx2 = Transaction::new_with_payer(&[migrate_ix], Some(&upgrade_authority.pubkey()));
    tx2.sign(&[&upgrade_authority], new_blockhash);
    banks_client
        .process_transaction(tx2)
        .await
        .expect("second migrate is a no-op");

    let raw2 = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw2.data.len(), new_len, "size unchanged on re-migrate");
}

/// Regression (audit fix B2): migrating a STAKED legacy PDA must top up the
/// incremental rent so the stake stays fully withdrawable. The old
/// `min_balance(new_len) > current` guard never fired on a staked PDA (the
/// stake dwarfs the ~111k-lamport rent delta), so the account was left funded
/// only to the OLD rent floor once the stake was withdrawn — reverting a later
/// `withdraw_unbonded_stake` for dropping below rent-exemption. The fix adds the
/// `rent(129) - rent(113)` delta unconditionally.
///
/// This builds a raw legacy-layout (113-byte) STAKED account (is_active=true,
/// stake_amount=MIN, lamports = rent(113) + MIN), migrates it, confirms the rent
/// top-up, then drives the stake through unbonding (deactivate) and asserts the
/// post-window `withdraw_unbonded_stake` SUCCEEDS and closes the PDA (#392),
/// refunding its lamports to the wallet.
#[tokio::test]
async fn migrate_staked_legacy_account_stays_withdrawable() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let new_len = 8 + ValidatorAccount::INIT_SPACE; // 129
    let legacy_len = new_len - 16; // 113 (no unbonding fields yet)

    // The validator wallet the legacy PDA belongs to. It must self-sign the
    // eventual withdraw, so seed it as a funded system account.
    let validator = Keypair::new();
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    // Build the raw legacy STAKED body. Old 113-byte account = 8-byte
    // discriminator + 105-byte body with NO unbonding fields. Field offsets
    // within the discriminator-prefixed account: validator [8..40],
    // stake_amount [40..48], is_active [88].
    let mut data = ValidatorAccount::DISCRIMINATOR.to_vec();
    data.resize(legacy_len, 0);
    data[8..40].copy_from_slice(validator.pubkey().as_ref());
    data[40..48].copy_from_slice(&MIN_VALIDATOR_STAKE.to_le_bytes());
    data[88] = 1; // is_active = true

    let rent_legacy = Rent::default().minimum_balance(legacy_len);
    let rent_new = Rent::default().minimum_balance(new_len);
    let expected_delta = rent_new - rent_legacy; // 111_360 for the default rent

    // A real staked legacy PDA holds exactly its old rent floor + the stake.
    pt.add_account(
        validator_pda,
        Account {
            lamports: rent_legacy + MIN_VALIDATOR_STAKE,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    // Fund the validator wallet so it can pay the withdraw fee.
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), 1_000_000);
    let mut ctx = pt.start_with_context().await;

    // Registry init (needed for deactivate).
    send(
        &mut ctx,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
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
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("init registry");

    // Migrate the staked legacy PDA.
    let pda_before_migrate = ctx
        .banks_client
        .get_balance(validator_pda)
        .await
        .expect("balance");
    send(
        &mut ctx,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::MigrateValidatorAccount {
                _validator: validator.pubkey(),
            }
            .data(),
            accounts: accounts::MigrateValidatorAccount {
                validator_account: validator_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("migrate staked legacy account");

    let raw = ctx
        .banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.data.len(), new_len, "account grown to current layout");
    // The incremental rent for the 16 added bytes was topped up (the whole point
    // of the fix), so the PDA holds the stake ON TOP OF the new rent floor.
    assert_eq!(
        raw.lamports - pda_before_migrate,
        expected_delta,
        "migrate must add exactly the incremental rent delta"
    );
    assert_eq!(
        expected_delta, 111_360,
        "rent(129) - rent(113) under default rent"
    );
    assert!(
        raw.lamports >= rent_new + MIN_VALIDATOR_STAKE,
        "staked PDA must be rent-exempt at the new floor with the stake intact"
    );
    let acc = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(acc.is_active, "migration preserves the staked/active body");
    assert_eq!(acc.stake_amount, MIN_VALIDATOR_STAKE);
    assert_eq!(acc.unbonding_amount, 0);

    // Drive the stake into unbonding via deactivate (admin-signed), then withdraw
    // after the window. This is what would revert pre-fix: a PDA left at the old
    // rent floor drops below rent-exemption when the stake is withdrawn.
    send(
        &mut ctx,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::DeactivateValidator {}.data(),
            accounts: accounts::DeactivateValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("deactivate");

    let raw = ctx
        .banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(acc.unbonding_amount, MIN_VALIDATOR_STAKE);
    assert!(acc.unbonding_slot >= UNBONDING_SLOTS);

    ctx.warp_to_slot(acc.unbonding_slot)
        .expect("warp past unbonding window");

    send(
        &mut ctx,
        &validator,
        Instruction {
            program_id,
            data: instruction::WithdrawUnbondedStake {}.data(),
            accounts: accounts::WithdrawUnbondedStake {
                stake_mint,
                validator_account: validator_pda,
                validator: validator.pubkey(),
                validator_token_account: validator_token,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
                stake_vault_authority: Pubkey::find_program_address(
                    &[b"stake_vault_authority"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("withdraw must SUCCEED on a rent-topped-up migrated staked PDA");

    // With the end-of-life close (#392), the withdraw reclaims the PDA outright:
    // the migrated + rent-topped-up account is drained to the wallet and its
    // address freed. (The pre-close regression concern — the migrate rent top-up
    // keeping the PDA above the new rent floor after the stake leaves — is what
    // lets `close` succeed here rather than underflow; the account is then closed
    // rather than left funded.)
    let closed = ctx.banks_client.get_account(validator_pda).await.unwrap();
    assert!(
        closed.is_none() || closed.unwrap().lamports == 0,
        "PDA must be closed after withdraw"
    );
}


#[tokio::test]
async fn migrated_legacy_113_and_129_byte_validators_withdraw_without_initialized_token_ata() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let new_len = 8 + ValidatorAccount::INIT_SPACE; // 145
    let legacy_113_len = new_len - 32; // 113 (pre-#375, no unbonding or dual-stake fields)
    let legacy_129_len = new_len - 16; // 129 (pre-#968, no dual-stake fields)

    let validator_113 = Keypair::new();
    let validator_129 = Keypair::new();
    let (pda_113, _) =
        Pubkey::find_program_address(&[b"validator", validator_113.pubkey().as_ref()], &program_id);
    let (pda_129, _) =
        Pubkey::find_program_address(&[b"validator", validator_129.pubkey().as_ref()], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    for (wallet, pda, len) in [
        (&validator_113, pda_113, legacy_113_len),
        (&validator_129, pda_129, legacy_129_len),
    ] {
        let mut data = ValidatorAccount::DISCRIMINATOR.to_vec();
        data.resize(len, 0);
        data[8..40].copy_from_slice(wallet.pubkey().as_ref());
        data[40..48].copy_from_slice(&MIN_VALIDATOR_STAKE.to_le_bytes());
        data[88] = 1; // is_active = true

        let rent_old = Rent::default().minimum_balance(len);
        pt.add_account(
            pda,
            Account {
                lamports: rent_old + MIN_VALIDATOR_STAKE,
                data,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        );
        pt.add_account(
            wallet.pubkey(),
            Account {
                lamports: 10_000_000_000,
                data: vec![],
                owner: solana_sdk::system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let mut ctx = pt.start_with_context().await;

    send(
        &mut ctx,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
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
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("init registry");

    for (wallet, pda, old_len) in [
        (&validator_113, pda_113, legacy_113_len),
        (&validator_129, pda_129, legacy_129_len),
    ] {
        let before_lamports = ctx.banks_client.get_balance(pda).await.unwrap();
        send(
            &mut ctx,
            &upgrade_authority,
            Instruction {
                program_id,
                data: instruction::MigrateValidatorAccount {
                    _validator: wallet.pubkey(),
                }
                .data(),
                accounts: accounts::MigrateValidatorAccount {
                    validator_account: pda,
                    authority: upgrade_authority.pubkey(),
                    program_data: program_data_pda,
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None),
            },
        )
        .await
        .expect("migrate legacy validator");

        let raw = ctx.banks_client.get_account(pda).await.unwrap().unwrap();
        assert_eq!(raw.data.len(), new_len);
        let expected_delta =
            Rent::default().minimum_balance(new_len) - Rent::default().minimum_balance(old_len);
        assert_eq!(raw.lamports - before_lamports, expected_delta);

        send(
            &mut ctx,
            &upgrade_authority,
            Instruction {
                program_id,
                data: instruction::DeactivateValidator {}.data(),
                accounts: accounts::DeactivateValidator {
                    validator_account: pda,
                    validator_registry: registry_pda,
                    authority: upgrade_authority.pubkey(),
                }
                .to_account_metas(None),
            },
        )
        .await
        .expect("deactivate legacy validator");
    }

    let raw_113 = ctx.banks_client.get_account(pda_113).await.unwrap().unwrap();
    let acc_113 = ValidatorAccount::try_deserialize(&mut raw_113.data.as_slice()).unwrap();
    ctx.warp_to_slot(acc_113.unbonding_slot)
        .expect("warp past unbonding window");

    // Pre-dual-stake validators have `token_unbonding_amount == 0` and never
    // created an Associated Token Account for `stake_mint`. Passing an
    // uninitialized token account address (as `paraloom-cli validator
    // withdraw-unbonded` does) must still allow withdrawing their SOL stake and
    // closing the PDA.
    for (wallet, pda) in [(&validator_113, pda_113), (&validator_129, pda_129)] {
        let uninitialized_ata = Pubkey::new_unique();
        let wallet_before = ctx.banks_client.get_balance(wallet.pubkey()).await.unwrap();
        send(
            &mut ctx,
            wallet,
            Instruction {
                program_id,
                data: instruction::WithdrawUnbondedStake {}.data(),
                accounts: accounts::WithdrawUnbondedStake {
                    stake_mint,
                    validator_account: pda,
                    validator: wallet.pubkey(),
                    validator_token_account: uninitialized_ata,
                    stake_token_vault: Pubkey::find_program_address(
                        &[b"stake_token_vault"],
                        &program_id,
                    )
                    .0,
                    stake_vault_authority: Pubkey::find_program_address(
                        &[b"stake_vault_authority"],
                        &program_id,
                    )
                    .0,
                    token_program: spl_token::id(),
                }
                .to_account_metas(None),
            },
        )
        .await
        .expect("legacy validator without stake_mint ATA must withdraw SOL stake and close PDA");

        let wallet_after = ctx.banks_client.get_balance(wallet.pubkey()).await.unwrap();
        assert!(
            wallet_after >= wallet_before + MIN_VALIDATOR_STAKE,
            "legacy validator must recover full unbonded SOL stake + rent"
        );
        let closed = ctx.banks_client.get_account(pda).await.unwrap();
        assert!(closed.is_none() || closed.unwrap().lamports == 0);
    }
}

#[tokio::test]
async fn migrate_validator_account_rejects_wrong_owner_and_corrupted_lengths() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let new_len = 8 + ValidatorAccount::INIT_SPACE; // 145
    let legacy_129_len = new_len - 16;

    // 1. Account with valid discriminator and legacy length (129), but wrong owner.
    let w_wrong_owner = Keypair::new().pubkey();
    let (pda_wrong_owner, _) =
        Pubkey::find_program_address(&[b"validator", w_wrong_owner.as_ref()], &program_id);
    let mut d_wrong_owner = ValidatorAccount::DISCRIMINATOR.to_vec();
    d_wrong_owner.resize(legacy_129_len, 0);
    pt.add_account(
        pda_wrong_owner,
        Account {
            lamports: 10_000_000,
            data: d_wrong_owner,
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    // 2. Truncated account (48 bytes < 113) with valid discriminator.
    let w_truncated = Keypair::new().pubkey();
    let (pda_truncated, _) =
        Pubkey::find_program_address(&[b"validator", w_truncated.as_ref()], &program_id);
    let mut d_truncated = ValidatorAccount::DISCRIMINATOR.to_vec();
    d_truncated.resize(48, 0);
    pt.add_account(
        pda_truncated,
        Account {
            lamports: 10_000_000,
            data: d_truncated,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // 3. Corrupted intermediate length (120 bytes: neither 113, 129, nor 145).
    let w_corrupted = Keypair::new().pubkey();
    let (pda_corrupted, _) =
        Pubkey::find_program_address(&[b"validator", w_corrupted.as_ref()], &program_id);
    let mut d_corrupted = ValidatorAccount::DISCRIMINATOR.to_vec();
    d_corrupted.resize(120, 0);
    pt.add_account(
        pda_corrupted,
        Account {
            lamports: 10_000_000,
            data: d_corrupted,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // 4. Oversized account (160 bytes > 145).
    let w_oversized = Keypair::new().pubkey();
    let (pda_oversized, _) =
        Pubkey::find_program_address(&[b"validator", w_oversized.as_ref()], &program_id);
    let mut d_oversized = ValidatorAccount::DISCRIMINATOR.to_vec();
    d_oversized.resize(160, 0);
    pt.add_account(
        pda_oversized,
        Account {
            lamports: 10_000_000,
            data: d_oversized,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let mut ctx = pt.start_with_context().await;

    for (label, wallet, pda) in [
        ("wrong owner", w_wrong_owner, pda_wrong_owner),
        ("truncated 48-byte", w_truncated, pda_truncated),
        ("corrupted 120-byte", w_corrupted, pda_corrupted),
        ("oversized 160-byte", w_oversized, pda_oversized),
    ] {
        let res = send(
            &mut ctx,
            &upgrade_authority,
            Instruction {
                program_id,
                data: instruction::MigrateValidatorAccount { _validator: wallet }.data(),
                accounts: accounts::MigrateValidatorAccount {
                    validator_account: pda,
                    authority: upgrade_authority.pubkey(),
                    program_data: program_data_pda,
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None),
            },
        )
        .await;
        assert!(
            res.is_err(),
            "migrate_validator_account must reject {label} PDA"
        );
    }
}

#[tokio::test]
async fn migrate_bridge_state_enforces_owner_exact_legacy_length_and_unconditional_rent_delta() {
    use paraloom_program::BridgeState;

    let program_id = paraloom_program::ID;
    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let new_len = 8 + BridgeState::INIT_SPACE; // 117
    let legacy_len = new_len - 8; // 109 (pre-#642, before deposit_cap: u64)

    // Case 1: Truncated BridgeState (16 bytes < 109) must be rejected rather than
    // zero-extended into a 117-byte BridgeState with a zeroed authority.
    {
        let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
        let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
        let mut truncated = BridgeState::DISCRIMINATOR.to_vec();
        truncated.resize(16, 0);
        pt.add_account(
            bridge_state_pda,
            Account {
                lamports: 10_000_000,
                data: truncated,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        );
        let mut ctx = pt.start_with_context().await;
        let res = send(
            &mut ctx,
            &upgrade_authority,
            Instruction {
                program_id,
                data: instruction::MigrateBridgeState {}.data(),
                accounts: accounts::MigrateBridgeState {
                    bridge_state: bridge_state_pda,
                    authority: upgrade_authority.pubkey(),
                    program_data: program_data_pda,
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None),
            },
        )
        .await;
        assert!(
            res.is_err(),
            "migrate_bridge_state must reject truncated 16-byte BridgeState instead of zero-filling authority"
        );
    }

    // Case 2: Valid 109-byte legacy BridgeState with excess lamports must receive
    // the full incremental rent delta `rent(117) - rent(109)` from authority.
    {
        let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
        let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
        let mut legacy = BridgeState::DISCRIMINATOR.to_vec();
        legacy.resize(legacy_len, 0);
        legacy[8..12].copy_from_slice(&0x0004_0000u32.to_le_bytes());
        legacy[12..44].copy_from_slice(upgrade_authority.pubkey().as_ref());

        let rent_old = Rent::default().minimum_balance(legacy_len);
        let rent_new = Rent::default().minimum_balance(new_len);
        let expected_delta = rent_new - rent_old;
        let excess = 50_000u64;

        pt.add_account(
            bridge_state_pda,
            Account {
                lamports: rent_old + excess,
                data: legacy,
                owner: program_id,
                executable: false,
                rent_epoch: 0,
            },
        );
        let mut ctx = pt.start_with_context().await;
        let before = ctx.banks_client.get_balance(bridge_state_pda).await.unwrap();
        send(
            &mut ctx,
            &upgrade_authority,
            Instruction {
                program_id,
                data: instruction::MigrateBridgeState {}.data(),
                accounts: accounts::MigrateBridgeState {
                    bridge_state: bridge_state_pda,
                    authority: upgrade_authority.pubkey(),
                    program_data: program_data_pda,
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None),
            },
        )
        .await
        .expect("migrate valid 109-byte BridgeState");

        let raw = ctx
            .banks_client
            .get_account(bridge_state_pda)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw.data.len(), new_len);
        assert_eq!(
            raw.lamports - before,
            expected_delta,
            "migrate_bridge_state must top up the full incremental rent delta without consuming excess lamports"
        );
        let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();
        assert_eq!(state.authority, upgrade_authority.pubkey());
        assert_eq!(state.deposit_cap, 0);
    }
}
