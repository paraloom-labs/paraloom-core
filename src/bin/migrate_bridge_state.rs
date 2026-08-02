//! Grow a `BridgeState` created before the `deposit_cap` field (#642) to the
//! current layout, then optionally open the deposit cap.
//!
//! The TVL cap appended `deposit_cap` to `BridgeState`. After a redeploy that
//! ships the field, every instruction that deserializes `BridgeState`
//! (transact / deposit_note / pause / set_deposit_cap) aborts
//! `AccountDidNotDeserialize` on the shorter pre-migration account.
//! `set_deposit_cap` can't self-heal it (it takes `Account<BridgeState>`, which
//! fails to deserialize the short account first), so this runs the dedicated
//! `migrate_bridge_state` migration, then — if `DEPOSIT_CAP` is set — opens the
//! cap in a second transaction.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program's upgrade / cold authority (signer)
//!   DEPOSIT_CAP                    optional: lamport cap to set after migrating

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let deposit_cap: Option<u64> = match std::env::var("DEPOSIT_CAP") {
        Ok(s) => Some(s.parse()?),
        Err(_) => None,
    };

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (bridge_state, _) = derive_bridge_state(&program_id);
    let len = client.get_account(&bridge_state)?.data.len();

    println!("=== migrate bridge state ===");
    println!("Program:       {program_id}");
    println!("Authority:     {}", authority.pubkey());
    println!("Bridge state:  {bridge_state} (len {len})");

    // Grow the account (idempotent: the on-chain handler no-ops once at the
    // current length).
    let ix = create_migrate_bridge_state_instruction(&program_id, &authority.pubkey())?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );
    println!("\nSending migrate_bridge_state...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Migrated. Signature: {sig}");
    println!("New len: {}", client.get_account(&bridge_state)?.data.len());

    if let Some(cap) = deposit_cap {
        let ix = create_set_deposit_cap_instruction(&program_id, &authority.pubkey(), cap);
        let blockhash = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&authority.pubkey()),
            &[&authority],
            blockhash,
        );
        println!("\nSetting deposit cap to {cap} lamports...");
        let sig = client.send_and_confirm_transaction(&tx)?;
        println!("Deposit cap set. Signature: {sig}");
    } else {
        println!("\nDEPOSIT_CAP not set — cap stays 0 (closed). Set it deliberately later.");
    }

    Ok(())
}
