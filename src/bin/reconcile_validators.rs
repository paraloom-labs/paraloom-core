//! Idempotent redeploy reconcile tool.
//!
//! After an in-place upgrade to the post-#371/#373/#375/#377 binary, this brings
//! the on-chain validator set into agreement with the new program WITHOUT
//! bricking it, in the load-bearing order the mainnet de-risk audit requires:
//!
//!   1. **Migrate** EVERY `ValidatorAccount` PDA up to 145 bytes (8 + INIT_SPACE
//!      after dual-stake; live PDAs are 129, pre-dual-stake). Every
//!      validator-touching instruction typed-loads `ValidatorAccount` and aborts
//!      on the old 113-byte layout, so this MUST run before anything else. The
//!      on-chain `migrate_validator_account` also tops up the incremental rent
//!      (#377 B2) so the stake stays fully withdrawable.
//!   2. **Pre-reset** the `ValidatorRegistry` if it is still at the pre-dual-stake
//!      72-byte layout. Deactivating any orphan in Step 2 typed-loads the registry
//!      and fails with `AccountDidNotDeserialize` if it has not yet grown to 112 bytes,
//!      deadlocking before the Step 3 reset. Pre-resetting with all currently-active
//!      validators grows the PDA to 112 bytes so deactivation succeeds and cleanly
//!      decrements the active stake/counters.
//!   3. **Deactivate** every `is_active` PDA NOT in the keep-set. Post-#377 this
//!      routes the stake into unbonding (recoverable), it is not lost.
//!   4. **Reset** the registry LAST to exactly the keep-set. `reset` OVERWRITES
//!      the counters, so it must be the final counter-mutating op; running it
//!      before deactivation would leave orphans `is_active` and trip the M5
//!      bound on honest settlements.
//!   5. **Verify** `total_active_stake == Σ(stake over is_active PDAs)` and
//!      `active_validators == active_count`, returning an error and exiting non-zero
//!      if the invariant fails.
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
/// MUST request Base64: after migration every PDA is 145 bytes and the RPC
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
// 8 (disc) + ValidatorAccount::INIT_SPACE. INIT_SPACE is now 137 after
// dual-stake added token_stake_amount + token_unbonding_amount (2 x u64 = +16)
// on top of the post-#375 unbonding fields, so the target is 145, not the 129
// this tool was first written for. The live PDAs are 129 (pre-dual-stake), so
// the migrate filter (data_len < NEW_LEN) must use 145 or it would treat every
// 129-byte PDA as already-migrated and skip it, then deactivate/reset would
// abort typed-loading a 129-byte account against the 145-byte layout.
const NEW_LEN: usize = 145;
/// Current on-chain `ValidatorRegistry` size = 8 (disc) + INIT_SPACE (104) after
/// dual-stake added stake_mint (32) and min_token_stake (8).
/// Pre-dual-stake registry layout is 72 bytes.
const REGISTRY_NEW_LEN: usize = 112;

#[derive(Debug, PartialEq, Eq, Clone)]
struct ValidatorRow {
    wallet: Pubkey,
    pda: Pubkey,
    data_len: usize,
    is_active: bool,
    stake_amount: u64,
}

fn decode(program_id: &Pubkey, pda: Pubkey, acc: &Account) -> Option<ValidatorRow> {
    let d = &acc.data;
    if d.len() < 89 || d[0..8] != VALIDATOR_DISC {
        return None;
    }
    let wallet = Pubkey::new_from_array(d[8..40].try_into().ok()?);
    let (expected_pda, _) = derive_validator_account(program_id, &wallet);
    if pda != expected_pda {
        return None;
    }
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

fn check_reconcile_invariant(
    reg_data_len: usize,
    reg_active: u64,
    reg_stake: u64,
    active_count: usize,
    active_sum: u64,
) -> Result<(), String> {
    if reg_data_len < REGISTRY_NEW_LEN {
        return Err(format!(
            "INVARIANT MISMATCH: registry account unexpectedly short ({reg_data_len} < {REGISTRY_NEW_LEN} bytes)"
        ));
    }
    if reg_stake == active_sum && reg_active as usize == active_count {
        Ok(())
    } else {
        Err(format!(
            "INVARIANT MISMATCH: registry (active_validators={reg_active}, total_active_stake={reg_stake}) \
             != on-chain (active_count={active_count}, active_sum={active_sum})"
        ))
    }
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

    // The dual-stake mint the reset re-pins into the registry. `reset` grows the
    // pre-dual-stake registry to the current layout, and its `stake_mint` field
    // predates that layout, so it must be supplied explicitly. Getting this wrong
    // pins the wrong mint and every future dual-stake `register_validator` fails.
    let stake_mint = Pubkey::from_str(&std::env::var("RECONCILE_STAKE_MINT").map_err(|_| {
        "RECONCILE_STAKE_MINT is required (the dual-stake token mint to pin into the registry, e.g. the mock PARALOOM mint)"
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
        .filter_map(|(pda, acc)| decode(&program_id, pda, &acc))
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
    let all_active_wallets: Vec<Pubkey> = rows
        .iter()
        .filter(|r| r.is_active)
        .map(|r| r.wallet)
        .collect();

    let (registry_pda, _) = derive_validator_registry(&program_id);
    let reg_acc = client.get_account(&registry_pda)?;
    let reg_needs_migration = reg_acc.data.len() < REGISTRY_NEW_LEN;

    println!(
        "\nPlan:\n  1. migrate {} PDAs (len<{NEW_LEN}){}",
        to_migrate.len(),
        if reg_needs_migration {
            format!(
                "\n  1b. pre-reset registry to grow {} -> {REGISTRY_NEW_LEN} bytes before deactivation",
                reg_acc.data.len()
            )
        } else {
            String::new()
        }
    );
    println!("  2. deactivate {} orphan active PDAs", to_deactivate.len());
    println!(
        "  3. reset registry to {} keep-set validators (last)\n",
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

    // If the on-chain ValidatorRegistry is pre-dual-stake (< 112 bytes, e.g. 72 bytes),
    // any call to `deactivate_validator` in Step 2 will fail with AccountDidNotDeserialize
    // because `DeactivateValidator` typed-loads the 112-byte `ValidatorRegistry`.
    // To unblock Step 2, pre-reset/grow the registry to the current layout with all
    // currently-active validators so that `deactivate_validator` can typed-load the registry
    // and correctly decrement the active count/stake as each orphan is deactivated.
    let reg_before_deactivate = client.get_account(&registry_pda)?;
    if reg_before_deactivate.data.len() < REGISTRY_NEW_LEN {
        println!(
            "  growing registry ({} < {REGISTRY_NEW_LEN} bytes) with {} active validators...",
            reg_before_deactivate.data.len(),
            all_active_wallets.len()
        );
        send(
            &client,
            &authority,
            create_reset_validator_registry_instruction(
                &program_id,
                &authority.pubkey(),
                &all_active_wallets,
                &stake_mint,
                all_active_wallets.len() as u64,
            )?,
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
            &stake_mint,
            // keep_wallets is the authoritative active set enumerated from
            // getProgramAccounts above, so its length is the expected count.
            keep_wallets.len() as u64,
        )?,
    )?;

    // 4. verify the invariant on-chain.
    println!("[4/4] verifying invariant...");
    let refreshed: Vec<ValidatorRow> = client
        .get_program_accounts_with_config(&program_id, validator_accounts_config())?
        .into_iter()
        .filter_map(|(pda, acc)| decode(&program_id, pda, &acc))
        .collect();
    let active_sum: u64 = refreshed
        .iter()
        .filter(|r| r.is_active)
        .map(|r| r.stake_amount)
        .sum();
    let active_count = refreshed.iter().filter(|r| r.is_active).count();

    let reg = client.get_account(&registry_pda)?;
    if reg.data.len() < 72 {
        println!(
            "  ✗ INVARIANT MISMATCH — registry account unexpectedly short ({} bytes).",
            reg.data.len()
        );
        return Err(format!(
            "INVARIANT MISMATCH: registry data too short ({} bytes)",
            reg.data.len()
        )
        .into());
    }
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
    match check_reconcile_invariant(
        reg.data.len(),
        reg_active,
        reg_stake,
        active_count,
        active_sum,
    ) {
        Ok(()) => {
            println!("  ✓ invariant holds (total_active_stake == Σ active stake).");
        }
        Err(e) => {
            println!("  ✗ INVARIANT MISMATCH — do NOT unpause; investigate before any settlement.");
            return Err(e.into());
        }
    }
    println!(
        "\nReconcile complete. Smoke-test a >=2-independent-co-signer settlement before unpausing."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator_account_data(
        wallet: &Pubkey,
        stake: u64,
        is_active: bool,
        len: usize,
    ) -> Vec<u8> {
        let mut data = vec![0u8; len];
        if len >= 8 {
            data[0..8].copy_from_slice(&VALIDATOR_DISC);
        }
        if len >= 40 {
            data[8..40].copy_from_slice(wallet.as_ref());
        }
        if len >= 48 {
            data[40..48].copy_from_slice(&stake.to_le_bytes());
        }
        if len > 88 {
            data[88] = if is_active { 1 } else { 0 };
        }
        data
    }

    #[test]
    fn test_decode_canonical_pda() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let (canonical_pda, _) = derive_validator_account(&program_id, &wallet);
        let data = make_validator_account_data(&wallet, 1_500_000_000, true, 145);
        let acc = Account {
            lamports: 2_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let row = decode(&program_id, canonical_pda, &acc).expect("should decode canonical PDA");
        assert_eq!(row.wallet, wallet);
        assert_eq!(row.pda, canonical_pda);
        assert_eq!(row.data_len, 145);
        assert!(row.is_active);
        assert_eq!(row.stake_amount, 1_500_000_000);
    }

    #[test]
    fn test_decode_rejects_non_canonical_pda() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let wrong_pda = Pubkey::new_unique(); // Not derived with [b"validator", wallet]
        let data = make_validator_account_data(&wallet, 1_000_000_000, true, 145);
        let acc = Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let res = decode(&program_id, wrong_pda, &acc);
        assert!(res.is_none(), "decode must reject non-canonical PDA");
    }

    #[test]
    fn test_decode_rejects_invalid_discriminator() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let (canonical_pda, _) = derive_validator_account(&program_id, &wallet);
        let mut data = make_validator_account_data(&wallet, 1_000_000_000, true, 145);
        data[0] ^= 0xff; // Corrupt discriminator
        let acc = Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let res = decode(&program_id, canonical_pda, &acc);
        assert!(res.is_none(), "decode must reject invalid discriminator");
    }

    #[test]
    fn test_decode_rejects_short_data() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let (canonical_pda, _) = derive_validator_account(&program_id, &wallet);
        let data = make_validator_account_data(&wallet, 1_000_000_000, true, 88); // 88 < 89
        let acc = Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let res = decode(&program_id, canonical_pda, &acc);
        assert!(res.is_none(), "decode must reject data shorter than 89 bytes");
    }

    #[test]
    fn test_decode_inactive_validator() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let (canonical_pda, _) = derive_validator_account(&program_id, &wallet);
        let data = make_validator_account_data(&wallet, 1_000_000_000, false, 129);
        let acc = Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        };

        let row = decode(&program_id, canonical_pda, &acc).expect("should decode inactive PDA");
        assert_eq!(row.wallet, wallet);
        assert!(!row.is_active);
        assert_eq!(row.data_len, 129);
    }

    #[test]
    fn test_invariant_check_success() {
        let res = check_reconcile_invariant(112, 3, 3_000_000_000, 3, 3_000_000_000);
        assert!(res.is_ok());
    }

    #[test]
    fn test_invariant_check_fails_on_short_registry() {
        let res = check_reconcile_invariant(72, 3, 3_000_000_000, 3, 3_000_000_000);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("registry account unexpectedly short"));
    }

    #[test]
    fn test_invariant_check_fails_on_stake_mismatch() {
        let res = check_reconcile_invariant(112, 3, 2_000_000_000, 3, 3_000_000_000);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("INVARIANT MISMATCH"));
    }

    #[test]
    fn test_invariant_check_fails_on_count_mismatch() {
        let res = check_reconcile_invariant(112, 2, 3_000_000_000, 3, 3_000_000_000);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("INVARIANT MISMATCH"));
    }
}
