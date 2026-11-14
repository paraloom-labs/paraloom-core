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
/// `sha256("account:ValidatorRegistry")[..8]`.
const REGISTRY_DISC: [u8; 8] = [125, 198, 232, 234, 166, 21, 55, 100];
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
/// Current on-chain `ValidatorRegistry` size = 8 (disc) + INIT_SPACE (104)
/// after dual-stake added `stake_mint` (32) + `min_token_stake` (8).
/// Pre-dual-stake registries are 72 bytes, which causes typed `Account<ValidatorRegistry>`
/// loads in `deactivate_validator` to abort with `AccountDidNotDeserialize` unless
/// `reset_validator_registry` grows the registry first.
const REGISTRY_NEW_LEN: usize = 112;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatorRow {
    wallet: Pubkey,
    pda: Pubkey,
    data_len: usize,
    is_active: bool,
    stake_amount: u64,
}

fn decode(program_id: &Pubkey, pda: Pubkey, acc: &Account) -> Option<ValidatorRow> {
    if acc.owner != *program_id {
        return None;
    }
    let d = &acc.data;
    if d.len() < 89 || d[0..8] != VALIDATOR_DISC {
        return None;
    }
    let wallet = Pubkey::new_from_array(d[8..40].try_into().ok()?);
    let (expected_pda, _) = derive_validator_account(program_id, &wallet);
    if expected_pda != pda {
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

/// Returns `true` when `validator_registry` must be grown/re-authored via
/// `reset_validator_registry` BEFORE `deactivate_validator` can typed-load
/// `Account<ValidatorRegistry>` with `has_one = authority`.
fn registry_needs_pre_reset(reg_data: &[u8], authority: &Pubkey) -> bool {
    if reg_data.len() < REGISTRY_NEW_LEN {
        return true;
    }
    reg_data[8..40] != authority.to_bytes()
}

/// Verify the post-reconcile on-chain invariant:
/// - `reg_data` has the full 112-byte dual-stake layout and `REGISTRY_DISC`
/// - `reg_active == active_count`
/// - `reg_stake == Σ(active stake)` (checked against u64 overflow)
/// - `reg_stake_mint == expected_stake_mint`
fn verify_reconciled_state(
    refreshed: &[ValidatorRow],
    reg_data: &[u8],
    expected_stake_mint: &Pubkey,
) -> Result<(usize, u64, u64, u64), String> {
    if reg_data.len() < REGISTRY_NEW_LEN {
        return Err(format!(
            "registry data too short after reset: {} bytes (expected >= {REGISTRY_NEW_LEN})",
            reg_data.len()
        ));
    }
    if reg_data[0..8] != REGISTRY_DISC {
        return Err("registry discriminator mismatch".to_string());
    }
    let mut active_sum: u64 = 0;
    let mut active_count: usize = 0;
    for r in refreshed.iter().filter(|r| r.is_active) {
        active_sum = active_sum
            .checked_add(r.stake_amount)
            .ok_or_else(|| "active stake sum overflowed u64".to_string())?;
        active_count += 1;
    }
    let reg_active = u64::from_le_bytes(reg_data[48..56].try_into().unwrap());
    let reg_stake = u64::from_le_bytes(reg_data[64..72].try_into().unwrap());
    let reg_stake_mint = Pubkey::new_from_array(reg_data[72..104].try_into().unwrap());

    if reg_stake_mint != *expected_stake_mint {
        return Err(format!(
            "registry stake_mint mismatch: on-chain {reg_stake_mint} != expected {expected_stake_mint}"
        ));
    }
    if reg_stake != active_sum || reg_active != active_count as u64 {
        return Err(format!(
            "invariant mismatch: registry (active={reg_active}, stake={reg_stake}) != PDAs (active={active_count}, stake={active_sum})"
        ));
    }
    Ok((active_count, active_sum, reg_active, reg_stake))
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

    // Enumerate every canonical ValidatorAccount PDA (113, 129, and 145 byte).
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

    // If the on-chain ValidatorRegistry is still at the pre-dual-stake layout
    // (< 112 bytes) or carries a stale authority pubkey, `deactivate_validator`
    // (which typed-loads `Account<ValidatorRegistry>` with `has_one = authority`)
    // would abort with `AccountDidNotDeserialize` / `ConstraintHasOne` before Step 3
    // ever had a chance to grow the registry. Pre-grow the registry first when needed,
    // then run Step 2 deactivations, and finally run Step 3 reset to restore the
    // exact keep-set counters after `deactivate_validator` decrements them.
    let (registry_pda, _) = derive_validator_registry(&program_id);
    if !to_deactivate.is_empty() {
        let reg_pre = client.get_account(&registry_pda)?;
        if registry_needs_pre_reset(&reg_pre.data, &authority.pubkey()) {
            println!(
                "[2a/4] Pre-dual-stake registry detected ({} -> {REGISTRY_NEW_LEN} bytes). Expanding layout with zero-state reset before deactivation...",
                reg_pre.data.len()
            );
            send(
                &client,
                &authority,
                create_reset_validator_registry_instruction(
                    &program_id,
                    &authority.pubkey(),
                    &[], // Zero-state expansion before deactivations so Step 2b cannot underflow keep_wallets counters
                    &stake_mint,
                    0,
                )?,
            )?;
        }
    }

    // 2. deactivate orphans (routes stake to unbonding, #377 B1).
    println!("[2b/4] deactivating {} orphans...", to_deactivate.len());
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

    let reg = client.get_account(&registry_pda)?;
    match verify_reconciled_state(&refreshed, &reg.data, &stake_mint) {
        Ok((active_count, active_sum, reg_active, reg_stake)) => {
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
            println!("  ✓ invariant holds (total_active_stake == Σ active stake).");
        }
        Err(err) => {
            println!("  ✗ INVARIANT MISMATCH — do NOT unpause; investigate before any settlement: {err}");
            return Err(err.into());
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

    fn make_validator_account(
        program_id: &Pubkey,
        wallet: &Pubkey,
        stake: u64,
        is_active: bool,
        len: usize,
    ) -> Account {
        let mut data = vec![0u8; len];
        data[0..8].copy_from_slice(&VALIDATOR_DISC);
        data[8..40].copy_from_slice(wallet.as_ref());
        data[40..48].copy_from_slice(&stake.to_le_bytes());
        data[88] = u8::from(is_active);
        Account {
            lamports: stake,
            data,
            owner: *program_id,
            executable: false,
            rent_epoch: 0,
        }
    }

    fn make_registry_bytes(
        authority: &Pubkey,
        active_validators: u64,
        total_active_stake: u64,
        stake_mint: Option<&Pubkey>,
    ) -> Vec<u8> {
        let len = if stake_mint.is_some() {
            REGISTRY_NEW_LEN
        } else {
            72
        };
        let mut data = vec![0u8; len];
        data[0..8].copy_from_slice(&REGISTRY_DISC);
        data[8..40].copy_from_slice(authority.as_ref());
        data[40..48].copy_from_slice(&active_validators.to_le_bytes());
        data[48..56].copy_from_slice(&active_validators.to_le_bytes());
        data[56..64].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        data[64..72].copy_from_slice(&total_active_stake.to_le_bytes());
        if let Some(mint) = stake_mint {
            data[72..104].copy_from_slice(mint.as_ref());
            data[104..112].copy_from_slice(&1_000_000u64.to_le_bytes());
        }
        data
    }

    #[test]
    fn decode_rejects_non_canonical_pda_and_wrong_owner() {
        let program_id = Pubkey::new_unique();
        let wallet = Pubkey::new_unique();
        let (canonical_pda, _) = derive_validator_account(&program_id, &wallet);
        let acc = make_validator_account(&program_id, &wallet, 2_000_000_000, true, NEW_LEN);

        // Canonical PDA decodes cleanly.
        let decoded = decode(&program_id, canonical_pda, &acc).expect("canonical PDA must decode");
        assert_eq!(decoded.wallet, wallet);
        assert_eq!(decoded.stake_amount, 2_000_000_000);
        assert!(decoded.is_active);

        // Spoofed/non-canonical PDA with matching wallet bytes is rejected.
        let fake_pda = Pubkey::new_unique();
        assert!(decode(&program_id, fake_pda, &acc).is_none());

        // Wrong owner is rejected.
        let mut wrong_owner = acc.clone();
        wrong_owner.owner = Pubkey::new_unique();
        assert!(decode(&program_id, canonical_pda, &wrong_owner).is_none());
    }

    #[test]
    fn legacy_72_byte_registry_or_stale_authority_triggers_pre_reset() {
        let authority = Pubkey::new_unique();
        let other_authority = Pubkey::new_unique();
        let stake_mint = Pubkey::new_unique();

        let legacy_72 = make_registry_bytes(&authority, 3, 3_000_000_000, None);
        assert!(
            registry_needs_pre_reset(&legacy_72, &authority),
            "72-byte pre-dual-stake registry must trigger pre-reset before deactivate_validator"
        );

        let stale_auth_112 =
            make_registry_bytes(&other_authority, 3, 3_000_000_000, Some(&stake_mint));
        assert!(
            registry_needs_pre_reset(&stale_auth_112, &authority),
            "mismatched registry authority must trigger pre-reset before deactivate_validator"
        );

        let migrated_112 = make_registry_bytes(&authority, 3, 3_000_000_000, Some(&stake_mint));
        assert!(!registry_needs_pre_reset(&migrated_112, &authority));
    }

    #[test]
    fn verify_reconciled_state_fails_closed_on_mismatch() {
        let authority = Pubkey::new_unique();
        let stake_mint = Pubkey::new_unique();
        let w1 = Pubkey::new_unique();
        let w2 = Pubkey::new_unique();
        let rows = vec![
            ValidatorRow {
                wallet: w1,
                pda: Pubkey::new_unique(),
                data_len: NEW_LEN,
                is_active: true,
                stake_amount: 1_000_000_000,
            },
            ValidatorRow {
                wallet: w2,
                pda: Pubkey::new_unique(),
                data_len: NEW_LEN,
                is_active: false,
                stake_amount: 0,
            },
        ];

        let ok_reg = make_registry_bytes(&authority, 1, 1_000_000_000, Some(&stake_mint));
        assert!(verify_reconciled_state(&rows, &ok_reg, &stake_mint).is_ok());

        let bad_stake_reg = make_registry_bytes(&authority, 1, 2_000_000_000, Some(&stake_mint));
        assert!(verify_reconciled_state(&rows, &bad_stake_reg, &stake_mint).is_err());

        let wrong_mint = Pubkey::new_unique();
        assert!(verify_reconciled_state(&rows, &ok_reg, &wrong_mint).is_err());
    }

    #[test]
    fn step_2a_zero_state_expansion_instruction_uses_empty_slice() {
        let program_id = Pubkey::new_unique();
        let authority = Pubkey::new_unique();
        let stake_mint = Pubkey::new_unique();
        let expand_ix = create_reset_validator_registry_instruction(
            &program_id,
            &authority,
            &[],
            &stake_mint,
            0,
        )
        .expect("zero-state expansion instruction must build");
        // 4 base accounts (validator_registry, authority, program_data, system_program) + 0 remaining accounts
        assert_eq!(expand_ix.accounts.len(), 4);
        // Trailing 8 bytes of instruction data encode expected_active_validators = 0u64 LE
        assert_eq!(&expand_ix.data[expand_ix.data.len() - 8..], &0u64.to_le_bytes());
    }
}
