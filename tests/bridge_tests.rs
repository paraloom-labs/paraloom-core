//! Bridge integration tests

use paraloom::bridge::{Bridge, BridgeConfig, DepositEvent, WithdrawalRequest};
use paraloom::privacy::{pedersen, ShieldedPool};
use std::sync::Arc;

#[tokio::test]
async fn test_bridge_initialization() {
    let config = BridgeConfig {
        enabled: false,
        ..Default::default()
    };

    let bridge = Bridge::new(config);
    let stats = bridge.stats().await;

    assert_eq!(stats.total_deposits, 0);
    assert_eq!(stats.total_withdrawals, 0);
}

#[tokio::test]
async fn test_bridge_with_pool() {
    let config = BridgeConfig {
        enabled: true,
        solana_rpc_url: std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
        program_id: "11111111111111111111111111111111".to_string(),
        poll_interval_secs: 10,
        start_block: Some(0),
        authority_keypair_path: None,
        bridge_vault: None,
        // Future-proof: any new field added to `BridgeConfig` picks up
        // the default rather than failing this test build.
        ..Default::default()
    };

    let pool = Arc::new(ShieldedPool::new());
    let mut bridge = Bridge::new(config);

    let result = bridge.init(pool).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_bridge_disabled() {
    let config = BridgeConfig {
        enabled: false,
        ..Default::default()
    };

    let pool = Arc::new(ShieldedPool::new());
    let mut bridge = Bridge::new(config);

    let result = bridge.init(pool).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_deposit_event_structure() {
    let randomness = pedersen::generate_randomness();

    let event = DepositEvent {
        signature: "test_signature".to_string(),
        from: [0x01u8; 32],
        amount: 1000,
        recipient: [0x02u8; 32],
        randomness,
        asset_id: [0u8; 32],
        fee: 10,
        block: 12345,
        timestamp: 1699564800,
    };

    assert_eq!(event.amount, 1000);
    assert_eq!(event.fee, 10);
    assert_eq!(event.block, 12345);
}

#[tokio::test]
async fn test_withdrawal_request_structure() {
    let request = WithdrawalRequest {
        nullifier: [0x03u8; 32],
        amount: 500,
        recipient: [0x04u8; 32],
        fee: 5,
        expiration_slot: u64::MAX,
        proof: vec![0u8; 128],
    };

    assert_eq!(request.amount, 500);
    assert_eq!(request.fee, 5);
    assert_eq!(request.proof.len(), 128);
}

#[tokio::test]
async fn test_bridge_stats_update() {
    let config = BridgeConfig::default();
    let bridge = Bridge::new(config);

    let stats = bridge.stats().await;
    assert_eq!(stats.volume_deposited, 0);
    assert_eq!(stats.volume_withdrawn, 0);
}

#[test]
fn test_create_initialize_validator_registry_instruction_layout() {
    use paraloom::bridge::solana::{
        create_initialize_validator_registry_instruction, derive_program_data,
        derive_stake_token_vault, derive_stake_vault_authority, derive_validator_registry,
        SPL_TOKEN_PROGRAM_ID,
    };
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::sysvar::rent;

    let program_id = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let stake_mint = Pubkey::new_unique();
    let token_program = SPL_TOKEN_PROGRAM_ID;

    let ix = create_initialize_validator_registry_instruction(
        &program_id,
        &authority,
        &stake_mint,
        &token_program,
    )
    .expect("instruction creation failed");

    assert_eq!(ix.program_id, program_id);
    assert_eq!(ix.accounts.len(), 9);

    let (expected_registry, _) = derive_validator_registry(&program_id);
    let (expected_vault, _) = derive_stake_token_vault(&program_id);
    let (expected_vault_authority, _) = derive_stake_vault_authority(&program_id);
    let (expected_program_data, _) = derive_program_data(&program_id);

    assert_eq!(ix.accounts[0].pubkey, expected_registry);
    assert!(ix.accounts[0].is_writable);
    assert!(!ix.accounts[0].is_signer);

    assert_eq!(ix.accounts[1].pubkey, authority);
    assert!(ix.accounts[1].is_writable);
    assert!(ix.accounts[1].is_signer);

    assert_eq!(ix.accounts[2].pubkey, stake_mint);
    assert!(!ix.accounts[2].is_writable);
    assert!(!ix.accounts[2].is_signer);

    assert_eq!(ix.accounts[3].pubkey, expected_vault);
    assert!(ix.accounts[3].is_writable);
    assert!(!ix.accounts[3].is_signer);

    assert_eq!(ix.accounts[4].pubkey, expected_vault_authority);
    assert!(!ix.accounts[4].is_writable);
    assert!(!ix.accounts[4].is_signer);

    assert_eq!(ix.accounts[5].pubkey, expected_program_data);
    assert!(!ix.accounts[5].is_writable);
    assert!(!ix.accounts[5].is_signer);

    assert_eq!(ix.accounts[6].pubkey, token_program);
    assert!(!ix.accounts[6].is_writable);
    assert!(!ix.accounts[6].is_signer);

    assert_eq!(ix.accounts[7].pubkey, Pubkey::default());
    assert!(!ix.accounts[7].is_writable);
    assert!(!ix.accounts[7].is_signer);

    assert_eq!(ix.accounts[8].pubkey, rent::id());
    assert!(!ix.accounts[8].is_writable);
    assert!(!ix.accounts[8].is_signer);
}
