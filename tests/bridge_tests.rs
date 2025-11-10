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
