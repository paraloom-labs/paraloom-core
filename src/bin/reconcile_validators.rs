//! Idempotent redeploy reconcile tool.
//!
//! After an in-place upgrade to the post-#371/#373/#375/#377 binary, this brings
//! the on-chain validator set into agreement with the new program WITHOUT
//! bricking it, in the load-bearing order the mainnet de-risk audit requires:
//!
//!   1. **Migrate** EVERY `ValidatorAccount` PDA 113 -> 129 bytes. Every
//!      validator-touching instruction typed-loads `ValidatorAccount` and aborts
//!      on the old 113-byte layout, so this MUST run before anything else. The
//!      on-chain `migrate_validator_account` also tops up the incremental rent
//!      (#377 B2) so the stake stays fully withdrawable.
//!   2. **Deactivate** every `is_active` PDA NOT in the keep-set. Post-#377 this
//!      routes the stake into unbonding (recoverable), it is not lost.
//!   3. **Reset** the registry LAST to exactly the keep-set. `reset` OVERWRITES
//!      the counters, so it must be the final counter-mutating op; running it
//!      before deactivation would leave orphans `is_active` and trip the M5
//!      bound on honest settlements.
//!   4. **Verify** `total_active_stake == Σ(stake over is_active PDAs)`.
//!
//! Dry-run by default (prints the plan only). Set `RECONCILE_EXECUTE=1` to send.
//! Safe to re-run: migrate no-ops at 129 bytes, deactivate no-ops on already-
//! inactive, reset overwrites to the same set.
//!
//! Env:
//!   SOLANA_RPC_URL, SOLANA_PROGRAM_ID
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the upgrade == registry authority keypair
//!   RECONCILE_KEEP                 comma-separated validator wallets to keep
//!                                  active (MUST include the settler's wallet)
//!   RECONCILE_SETTLER             the settlement authority's validator wallet;
//!                                  required, must be in RECONCILE_KEEP, never
//!                                  deactivated (else settlement bricks)
//!   RECONCILE_EXECUTE=1            actually send (default: print the plan only)

use paraloom::bridge::solana::*;
use solana_account_decoder::UiAccountEncoding;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_client::rpc_filter::{Memcmp, RpcFilterType};
use solana_sdk::{
    account::Account, commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::collections::HashSet;
use std::str::FromStr;

/// `getProgramAccounts` config for enumerating `ValidatorAccount` PDAs.
///
/// MUST request Base64: after migration every PDA is 129 bytes and the RPC
/// rejects base58 encoding above 128 bytes (`-32600 "Encoded binary (base 58)
/// data should be less than 128 bytes"`). The default (base58) works today at
/// 113 bytes but breaks the post-migrate verify and any idempotent re-run.
fn validator_accounts_config() -> RpcProgramAccountsConfig {
    RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            0,
            VALIDATOR_DISC.to_vec(),
        ))]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// `sha256("account:ValidatorAccount")[..8]`.
const VALIDATOR_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];
/// Current on-chain `ValidatorAccount` size = 8 (disc) + INIT_SPACE (121) after
/// the #375 unbonding fields. Anything smaller (113 = pre-#375) needs migration.
const NEW_LEN: usize = 129;

struct ValidatorRow {
    wallet: Pubkey,
    pda: Pubkey,
    data_len: usize,
    is_active: bool,
    stake_amount: u64,
}

fn decode(pda: Pubkey, acc: &Account) -> Option<ValidatorRow> {
    let d = &acc.data;
    if d.len() < 89 || d[0..8] != VALIDATOR_DISC {
        return None;
    }
    let wallet = Pubkey::new_from_array(d[8..40].try_into().ok()?);
    let stake_amount = u64::from_le_bytes(d[40..48].try_into().ok()?);
    let is_active = d[88] != 0; // offset: disc(8)+pubkey(32)+5*u64/i64(40)+... = byte 88
    Some(ValidatorRow {
        wallet,
        pda,
        data_len: d.len(),
        is_active,
        stake_amount,
    })
}

/// Send one instruction, re-signing with a fresh blockhash on transient
/// failures. A single dropped tx would otherwise abort a ~50-tx reconcile
/// mid-run; each attempt fetches a new blockhash so a retry is never rejected
/// as a stale duplicate. All txs are idempotent on-chain (migrate/deactivate/
/// reset no-op when already applied), so a retry after an ambiguous confirm is
/// safe.
fn send(
    client: &RpcClient,
    authority: &solana_sdk::signature::Keypair,
    ix: solana_sdk::instruction::Instruction,
) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_ATTEMPTS: usize = 4;
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let blockhash = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            std::slice::from_ref(&ix),
            Some(&authority.pubkey()),
            &[authority],
            blockhash,
        );
        match client.send_and_confirm_transaction(&tx) {
            Ok(sig) => {
                println!("    sig {sig}");
                return Ok(());
            }
            Err(e) => {
                println!("    attempt {attempt}/{MAX_ATTEMPTS} failed: {e}");
                last_err = Some(Box::new(e));
            }
        }
    }
    Err(last_err.expect("at least one attempt ran"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let keep: HashSet<Pubkey> = std::env::var("RECONCILE_KEEP")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Pubkey::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let execute = std::env::var("RECONCILE_EXECUTE").ok().as_deref() == Some("1");

    // The settlement (bridge) authority's validator wallet MUST stay active — if
    // the CLI deactivated it, every future `transact` would abort
    // `ValidatorNotActive` with no reactivate path (recoverable only by rotating
    // the bridge authority). The CLI can't infer which wallet is the settler, so
    // require it explicitly and refuse to run unless it is in the keep-set.
    let settler = Pubkey::from_str(&std::env::var("RECONCILE_SETTLER").map_err(|_| {
        "RECONCILE_SETTLER is required (the settlement authority's validator wallet, e.g. Hky4Zx2…) — it must never be deactivated"
    })?)?;

    if keep.is_empty() {
        return Err("RECONCILE_KEEP is empty — refusing to reset to zero validators".into());
    }
    if !keep.contains(&settler) {
        return Err(format!(
            "settler {settler} is not in RECONCILE_KEEP — deactivating it would brick settlement; add it to the keep-set"
        )
        .into());
    }

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!(
        "=== Validator reconcile ({}) ===",
        if execute { "EXECUTE" } else { "DRY-RUN" }
    );
    println!("Program:   {program_id}");
    println!("Authority: {}", authority.pubkey());
    println!("Settler:   {settler} (protected — never deactivated)");
    println!(
        "Keep-set ({}): {:?}\n",
        keep.len(),
        keep.iter().collect::<Vec<_>>()
    );

    // Enumerate every ValidatorAccount PDA (both 113 and 129 byte).
    let mut rows: Vec<ValidatorRow> = client
        .get_program_accounts_with_config(&program_id, validator_accounts_config())?
        .into_iter()
        .filter_map(|(pda, acc)| decode(pda, &acc))
        .collect();
    rows.sort_by_key(|r| r.wallet.to_bytes());

    println!("Found {} ValidatorAccount PDAs:", rows.len());
    for r in &rows {
        println!(
            "  {}  pda={} len={} active={} stake={} SOL  keep={}",
            r.wallet,
            r.pda,
            r.data_len,
            r.is_active,
            r.stake_amount as f64 / 1e9,
            keep.contains(&r.wallet)
        );
    }

    // Every keep-set wallet MUST exist on-chain AND be active before we touch
    // anything: `reset_validator_registry` requires each remaining-account be
    // `is_active` (it aborts otherwise), and it runs LAST — after migrate +
    // deactivate have already committed. A missing/inactive keep entry would
    // therefore strand the reconcile half-done. Hard-fail up front instead.
    let by_wallet: std::collections::HashMap<Pubkey, &ValidatorRow> =
        rows.iter().map(|r| (r.wallet, r)).collect();
    let mut bad_keep: Vec<String> = Vec::new();
    for w in &keep {
        match by_wallet.get(w) {
            None => bad_keep.push(format!(
                "{w} (no on-chain ValidatorAccount — register it first)"
            )),
            Some(r) if !r.is_active => bad_keep.push(format!("{w} (inactive — reset would abort)")),
            Some(_) => {}
        }
    }
    if !bad_keep.is_empty() {
        return Err(format!(
            "keep-set has {} unusable wallet(s); fix before reconciling:\n  - {}",
            bad_keep.len(),
            bad_keep.join("\n  - ")
        )
        .into());
    }

    let to_migrate: Vec<&ValidatorRow> = rows.iter().filter(|r| r.data_len < NEW_LEN).collect();
    let to_deactivate: Vec<&ValidatorRow> = rows
        .iter()
        .filter(|r| r.is_active && !keep.contains(&r.wallet))
        .collect();
    let keep_wallets: Vec<Pubkey> = rows
        .iter()
        .filter(|r| keep.contains(&r.wallet))
        .map(|r| r.wallet)
        .collect();

    println!(
        "\nPlan:\n  1. migrate {} PDAs (len<{NEW_LEN})\n  2. deactivate {} orphan active PDAs\n  3. reset registry to {} keep-set validators (last)\n",
        to_migrate.len(),
        to_deactivate.len(),
        keep_wallets.len()
    );

    if !execute {
        println!("DRY-RUN — set RECONCILE_EXECUTE=1 to send. Nothing was submitted.");
        return Ok(());
    }

    // 1. migrate all (must precede any typed load in reset/deactivate).
    println!("[1/4] migrating {} PDAs...", to_migrate.len());
    for r in &to_migrate {
        println!("  migrate {}", r.wallet);
        send(
            &client,
            &authority,
            create_migrate_validator_account_instruction(
                &program_id,
                &authority.pubkey(),
                &r.wallet,
            ),
        )?;
    }

    // 2. deactivate orphans (routes stake to unbonding, #377 B1).
    println!("[2/4] deactivating {} orphans...", to_deactivate.len());
    for r in &to_deactivate {
        println!("  deactivate {}", r.wallet);
        send(
            &client,
            &authority,
            create_deactivate_validator_instruction(&program_id, &authority.pubkey(), &r.wallet)?,
        )?;
    }

    // 3. reset LAST to exactly the keep-set.
    println!(
        "[3/4] resetting registry to {} validators...",
        keep_wallets.len()
    );
    send(
        &client,
        &authority,
        create_reset_validator_registry_instruction(
            &program_id,
            &authority.pubkey(),
            &keep_wallets,
        )?,
    )?;

    // 4. verify the invariant on-chain.
    println!("[4/4] verifying invariant...");
    let refreshed: Vec<ValidatorRow> = client
        .get_program_accounts_with_config(&program_id, validator_accounts_config())?
        .into_iter()
        .filter_map(|(pda, acc)| decode(pda, &acc))
        .collect();
    let active_sum: u64 = refreshed
        .iter()
        .filter(|r| r.is_active)
        .map(|r| r.stake_amount)
        .sum();
    let active_count = refreshed.iter().filter(|r| r.is_active).count();

    let (registry_pda, _) = derive_validator_registry(&program_id);
    let reg = client.get_account(&registry_pda)?;
    // ValidatorRegistry: disc(8) + authority(32) + total(8) + active(8) + min(8) + total_active_stake(8)
    let reg_active = u64::from_le_bytes(reg.data[48..56].try_into()?);
    let reg_stake = u64::from_le_bytes(reg.data[64..72].try_into()?);

    println!(
        "  on-chain: {} active PDAs summing {} SOL",
        active_count,
        active_sum as f64 / 1e9
    );
    println!(
        "  registry: active_validators={} total_active_stake={} SOL",
        reg_active,
        reg_stake as f64 / 1e9
    );
    if reg_stake == active_sum && reg_active as usize == active_count {
        println!("  ✓ invariant holds (total_active_stake == Σ active stake).");
    } else {
        println!("  ✗ INVARIANT MISMATCH — do NOT unpause; investigate before any settlement.");
    }
    println!(
        "\nReconcile complete. Smoke-test a >=2-independent-co-signer settlement before unpausing."
    );
    Ok(())
}
