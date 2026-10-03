use paraloom::bridge::solana::{
    build_settlement_message, derive_associated_token_address, CoSignPayload, SettlementParams,
    SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use solana_sdk::pubkey::Pubkey;

#[test]
fn transact_spl_cosign_binds_token_2022_program_for_token_2022_mint() {
    let program_id = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let recipient_token_account = Pubkey::new_unique();

    let payload = CoSignPayload {
        program_id: program_id.to_bytes(),
        authority: authority.to_bytes(),
        bridge_vault: Pubkey::new_unique().to_bytes(),
        blockhash: [7u8; 32],
        quorum_validators: vec![authority.to_bytes()],
        params: SettlementParams::TransactSpl {
            recipient_token_account: recipient_token_account.to_bytes(),
            mint: mint.to_bytes(),
            token_program: SPL_TOKEN_2022_PROGRAM_ID.to_bytes(),
            nullifiers: [[8u8; 32], [9u8; 32]],
            output_commitments: [[10u8; 32], [11u8; 32]],
            root: [12u8; 32],
            ext_amount: -500,
            proof: vec![0u8; 256],
        },
    };

    let message = build_settlement_message(&payload).expect("SPL Token-2022 co-sign message builds");
    let transact_spl_ix = &message.instructions[1];
    let account_at = |position: usize| {
        message.account_keys[transact_spl_ix.accounts[position] as usize]
    };

    let actual_fee_account = account_at(6);
    let actual_token_program = account_at(12);
    let expected_token_2022_fee_account =
        derive_associated_token_address(&authority, &mint, &SPL_TOKEN_2022_PROGRAM_ID);

    assert_eq!(
        actual_token_program, SPL_TOKEN_2022_PROGRAM_ID,
        "Token-2022 settlement instruction must bind Token-2022 program id"
    );
    assert_eq!(
        actual_fee_account, expected_token_2022_fee_account,
        "validator fee account must be derived using Token-2022 ATA seeds"
    );
}

#[test]
fn transact_spl_cosign_defaults_zeroed_token_program_to_classic() {
    let program_id = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let recipient_token_account = Pubkey::new_unique();

    let payload = CoSignPayload {
        program_id: program_id.to_bytes(),
        authority: authority.to_bytes(),
        bridge_vault: Pubkey::new_unique().to_bytes(),
        blockhash: [7u8; 32],
        quorum_validators: vec![authority.to_bytes()],
        params: SettlementParams::TransactSpl {
            recipient_token_account: recipient_token_account.to_bytes(),
            mint: mint.to_bytes(),
            token_program: [0u8; 32],
            nullifiers: [[8u8; 32], [9u8; 32]],
            output_commitments: [[10u8; 32], [11u8; 32]],
            root: [12u8; 32],
            ext_amount: -500,
            proof: vec![0u8; 256],
        },
    };

    let message = build_settlement_message(&payload).expect("SPL classic co-sign message builds");
    let transact_spl_ix = &message.instructions[1];
    let account_at = |position: usize| {
        message.account_keys[transact_spl_ix.accounts[position] as usize]
    };

    let actual_fee_account = account_at(6);
    let actual_token_program = account_at(12);
    let expected_classic_fee_account =
        derive_associated_token_address(&authority, &mint, &SPL_TOKEN_PROGRAM_ID);

    assert_eq!(
        actual_token_program, SPL_TOKEN_PROGRAM_ID,
        "zeroed token_program must default to classic SPL Token program"
    );
    assert_eq!(
        actual_fee_account, expected_classic_fee_account,
        "fee account must default to classic SPL Token ATA"
    );
}

#[test]
fn transact_spl_cosign_rejects_unsupported_token_program() {
    let program_id = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let recipient_token_account = Pubkey::new_unique();
    let invalid_program = Pubkey::new_unique();

    let payload = CoSignPayload {
        program_id: program_id.to_bytes(),
        authority: authority.to_bytes(),
        bridge_vault: Pubkey::new_unique().to_bytes(),
        blockhash: [7u8; 32],
        quorum_validators: vec![authority.to_bytes()],
        params: SettlementParams::TransactSpl {
            recipient_token_account: recipient_token_account.to_bytes(),
            mint: mint.to_bytes(),
            token_program: invalid_program.to_bytes(),
            nullifiers: [[8u8; 32], [9u8; 32]],
            output_commitments: [[10u8; 32], [11u8; 32]],
            root: [12u8; 32],
            ext_amount: -500,
            proof: vec![0u8; 256],
        },
    };

    let result = build_settlement_message(&payload);
    assert!(result.is_err(), "unsupported token program must be rejected");
}
