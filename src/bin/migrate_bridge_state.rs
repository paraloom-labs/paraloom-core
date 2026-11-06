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

const BRIDGE_STATE_DISC: [u8; 8] = [6, 190, 226, 198, 76, 100, 157, 198];
const BRIDGE_STATE_LEN: usize = 121;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let deposit_cap: Option<u64> = match std::env::var("DEPOSIT_CAP") {
        Ok(s) if !s.trim().is_empty() => Some(s.trim().parse()?),
        _ => None,
    };

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (bridge_state, _) = derive_bridge_state(&program_id);
    let acc = client.get_account(&bridge_state)?;
    if acc.owner != program_id {
        return Err(format!(
            "bridge_state {bridge_state} is owned by {}, expected program {program_id}",
            acc.owner
        )
        .into());
    }
    if acc.data.len() < 8 || acc.data[0..8] != BRIDGE_STATE_DISC {
        return Err("bridge_state account has an invalid Anchor discriminator".into());
    }
    let len = acc.data.len();

    println!("=== migrate bridge state ===");
    println!("Program:       {program_id}");
    println!("Authority:     {}", authority.pubkey());
    println!("Bridge state:  {bridge_state} (len {len})");

    if len < BRIDGE_STATE_LEN {
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
        let new_len = client.get_account(&bridge_state)?.data.len();
        println!("New len: {new_len}");
        if new_len < BRIDGE_STATE_LEN {
            return Err(format!(
                "bridge_state migration incomplete: len {new_len} < {BRIDGE_STATE_LEN}"
            )
            .into());
        }
    } else {
        println!("\nBridgeState is already migrated (len {len} >= {BRIDGE_STATE_LEN}); skipping migrate_bridge_state tx.");
    }

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
        let post_data = client.get_account_data(&bridge_state)?;
        if post_data.len() < BRIDGE_STATE_LEN {
            return Err("bridge_state account too short after set_deposit_cap".into());
        }
        let onchain_cap = u64::from_le_bytes(post_data[113..121].try_into()?);
        if onchain_cap != cap {
            return Err(format!(
                "on-chain deposit_cap ({onchain_cap}) does not match requested cap ({cap})"
            )
            .into());
        }
    } else {
        println!("\nDEPOSIT_CAP not set — cap stays unchanged. Set it deliberately later.");
    }

    Ok(())
}
