//! Fifth on-chain unit test for #71. Opens validator-registry
//! coverage: `initialize_validator_registry` then `register_validator`
//! with the minimum stake. Pins both pieces the consensus layer
//! relies on — the registry counters tick correctly so quorum math
//! has the right population, and a fresh `ValidatorAccount` lands
//! with the default reputation (1000) and `is_active = true` so the
//! consensus pipeline does not silently exclude newly registered
//! validators.
//!
//! Registry init now requires the program upgrade authority (#204);
//! register is validator-signed (the auto-payer).

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::{add_program_data, add_stake_mint, entry, funded_validator};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

#[tokio::test]
async fn register_validator_initializes_account_and_counters() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (validator, validator_token) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_account_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    let init_ix = Instruction {
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
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let register_ix = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            token_stake_amount: 1_000_000,
            stake_amount: MIN_VALIDATOR_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            stake_mint,
            validator_token_account: validator_token,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            token_program: spl_token::id(),
            validator_account: validator_account_pda,
            validator_registry: registry_pda,
            validator: validator.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[register_ix], Some(&validator.pubkey()));
    tx.sign(&[&validator], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let registry_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let registry = ValidatorRegistry::try_deserialize(&mut registry_raw.data.as_slice()).unwrap();
    assert_eq!(registry.total_validators, 1);
    assert_eq!(registry.active_validators, 1);
    assert_eq!(registry.minimum_stake, MIN_VALIDATOR_STAKE);

    let acc_raw = banks_client
        .get_account(validator_account_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.validator, validator.pubkey());
    assert_eq!(acc.stake_amount, MIN_VALIDATOR_STAKE);
    assert_eq!(acc.reputation_score, 1000);
    assert!(acc.is_active);
    assert_eq!(acc.times_slashed, 0);
}
