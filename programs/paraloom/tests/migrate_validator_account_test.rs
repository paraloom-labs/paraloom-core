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
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest, ProgramTestBanksClientExt};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

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
