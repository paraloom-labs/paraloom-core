use paraloom::bridge::{Bridge, BridgeConfig};
use paraloom::privacy::ShieldedPool;
use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;

#[tokio::test]
async fn bridge_start_verifies_program_version() {
    let config = BridgeConfig {
        enabled: true,
        solana_rpc_url: "http://127.0.0.1:1".to_string(),
        // A fresh key has no initialized BridgeState account and therefore no
        // recorded program_version for ProgramInterface::verify_program_version
        // to match against EXPECTED_PROGRAM_VERSION.
        program_id: Pubkey::new_unique().to_string(),
        poll_interval_secs: 3600,
        ..Default::default()
    };

    let pool = Arc::new(ShieldedPool::new());
    let mut bridge = Bridge::new(config);
    bridge.init(pool).await.expect("bridge init builds RPC clients only");

    let started = bridge.start().await;
    assert!(
        started.is_err(),
        "Bridge::start must fail when on-chain program version cannot be verified"
    );
}
