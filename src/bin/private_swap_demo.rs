//! Private-swap end-to-end driver (#240, re-laid over v3).
//!
//! Runs the private *swap-out* flow through the real relayer
//! ([`paraloom::relayer::PrivateSwapRelayer::execute_swap_out`]):
//!
//! 1. The operator deposits a native-SOL note into the shielded pool
//!    (`deposit_note`, v3).
//! 2. The relayer withdraws that note to a FRESH keypair via a v3 `transact`
//!    (`ext_amount < 0`, `recipient = fresh`): the nullifier is burned by the
//!    2-of-2 validator quorum, severing the link to the deposit. It then runs a
//!    REAL Jupiter swap SOL -> USDC signed FROM the fresh address. The swapped
//!    USDC lands at the fresh address, unlinkable to the depositor.
//! 3. Prints the settlement, the fresh address, and how much USDC the route
//!    realized.
//!
//! # Why swap-out and not a full round-trip
//!
//! The v3 program is native-SOL only: `deposit_note` re-shields SOL, not an SPL
//! token, so the swapped USDC cannot be put back into the pool until the SPL
//! redeploy. This driver therefore stops after the swap — the USDC is held at
//! the unlinkable fresh address, whose key the operator keeps (written next to
//! the run). That is a real private buy; re-shielding the token is separate,
//! redeploy-gated work.
//!
//! # Fork vs. live
//!
//! Jupiter liquidity is mainnet-only. Point the env at either:
//! * a **localnet mainnet-fork** (Jupiter + DEX pools + the Paraloom program +
//!   its 2-validator quorum cloned/running locally — see
//!   `scripts/localnet/private_swap_fork.sh`), with `SWAP_LEGACY_ROUTING=1` and
//!   `SWAP_DEXES=Whirlpool` so the route only touches cloned accounts; or
//! * **real mainnet** (`node.paraloom.io` ingress + real Jupiter), for a live
//!   small-amount run — leave the fork toggles unset.
//!
//! Run against plain devnet and the swap step returns `NoRoute`; the driver
//! narrates that honestly instead of faking a success.
//!
//! # Required environment
//!   SOLANA_RPC_URL                 RPC endpoint (default http://localhost:8899).
//!   SOLANA_PROGRAM_ID              deployed Paraloom program id.
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  funded key that pays the deposit.
//!   TRANSACT_INGRESS_URL           transact quorum ingress (default node.paraloom.io).
//!
//! # Optional environment (defaults in parentheses)
//!   TRANSACT_PROVING_KEY   v3 proving key (keys/transact_v3_proving.key).
//!   USDC_MINT              output mint (EPjFW…Dt1v, mainnet USDC).
//!   SWAP_AMOUNT_LAMPORTS   SOL note size to swap (50_000_000 = 0.05 SOL).
//!   SLIPPAGE_BPS           Jupiter slippage tolerance (50).
//!   JUPITER_BASE_URL       Jupiter base (lite-api.jup.ag/swap/v1).
//!   SWAP_LEGACY_ROUTING    "1" => single-hop + legacy tx (fork only).
//!   SWAP_DEXES             pin the route to a DEX allow-list (e.g. Whirlpool).
//!   AIRDROP                "1" => airdrop the deposit funds (fork/localnet only).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use paraloom::bridge::solana::*;
use paraloom::privacy::poseidon_circom::v3_pubkey;
use paraloom::privacy::types::{ShieldedAddress, NATIVE_SOL_ASSET};
use paraloom::relayer::{
    JupiterSwapProvider, OnChainSubmitter, PrivateSwapRelayer, PrivateSwapRequest, RelayerError,
    ReqwestJupiterClient, RpcSwapSubmitter, DEFAULT_JUPITER_BASE_URL,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::{path::Path, str::FromStr};

const DEFAULT_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const DEFAULT_PROVING_KEY: &str = "keys/transact_v3_proving.key";

fn fr_to_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = f.into_bigint().to_bytes_le();
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

fn rand_fr() -> Fr {
    use ark_std::rand::RngCore;
    let mut b = [0u8; 32];
    ark_std::rand::thread_rng().fill_bytes(&mut b);
    b[31] &= 0x1f;
    Fr::from_le_bytes_mod_order(&b)
}

fn header(s: &str) {
    println!("\n=== {s} ===");
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| v == "1").unwrap_or(false)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!(
        "=== Paraloom Private Swap-Out (deposit -> withdraw to fresh -> Jupiter SOL->USDC) ==="
    );

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id = Pubkey::from_str(
        &std::env::var("SOLANA_PROGRAM_ID")
            .map_err(|_| anyhow::anyhow!("SOLANA_PROGRAM_ID env var required"))?,
    )?;
    let payer = load_keypair_from_file(
        &std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")
            .map_err(|_| anyhow::anyhow!("BRIDGE_AUTHORITY_KEYPAIR_PATH env var required"))?,
    )?;
    let ingress = std::env::var("TRANSACT_INGRESS_URL")
        .unwrap_or_else(|_| "https://node.paraloom.io".to_string());
    let proving_key_path =
        std::env::var("TRANSACT_PROVING_KEY").unwrap_or_else(|_| DEFAULT_PROVING_KEY.to_string());
    let usdc_mint = Pubkey::from_str(
        &std::env::var("USDC_MINT").unwrap_or_else(|_| DEFAULT_USDC_MINT.to_string()),
    )?;
    let jupiter_base_url =
        std::env::var("JUPITER_BASE_URL").unwrap_or_else(|_| DEFAULT_JUPITER_BASE_URL.to_string());
    let swap_amount: u64 = match std::env::var("SWAP_AMOUNT_LAMPORTS") {
        Ok(s) => s.parse()?,
        Err(_) => LAMPORTS_PER_SOL / 20, // 0.05 SOL
    };
    let slippage_bps: u16 = match std::env::var("SLIPPAGE_BPS") {
        Ok(s) => s.parse()?,
        Err(_) => 50,
    };

    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
    let usdc_asset: [u8; 32] = usdc_mint.to_bytes();
    let (vault_pda, _) = derive_bridge_vault(&program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    header("Pre-flight");
    println!("RPC URL:           {rpc_url}");
    println!("Program ID:        {program_id}");
    println!("Payer (depositor): {}", payer.pubkey());
    println!("Ingress:           {ingress}");
    println!("Output mint (USDC):{usdc_mint}");
    println!("Jupiter base:      {jupiter_base_url}");
    println!(
        "Swap amount:       {} SOL ({swap_amount} lamports)",
        swap_amount as f64 / 1e9
    );
    if !Path::new(&proving_key_path).exists() {
        return Err(anyhow::anyhow!(
            "transact proving key missing at {proving_key_path}"
        ));
    }
    client.get_account(&tree_pda).map_err(|_| {
        anyhow::anyhow!("merkle_tree PDA not found — is the program deployed here?")
    })?;

    // Fork/localnet only: fund the payer so the deposit can land. Never on mainnet.
    if env_flag("AIRDROP") {
        let need = swap_amount + LAMPORTS_PER_SOL;
        println!("Airdropping payer {} SOL (fork)...", need as f64 / 1e9);
        let _ = client.request_airdrop(&payer.pubkey(), need);
        for _ in 0..20 {
            if client.get_balance(&payer.pubkey()).unwrap_or(0) >= need {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    // ── Step 1: deposit a native-SOL v3 note (or resume a persisted one) ─────
    // The note's spend witness (sk, blinding, pubkey, leaf, amount) is persisted
    // to a file the instant the deposit confirms — BEFORE the withdraw is
    // attempted — so a failed/incomplete run never strands the deposited SOL:
    // re-run with RESUME_NOTE=<file> to retry the withdraw against the same note
    // instead of depositing again.
    let (in_sk_le, in_blinding_le, in_note_pubkey_le, leaf_index, note_amount): (
        [u8; 32],
        [u8; 32],
        [u8; 32],
        u64,
        u64,
    ) = if let Ok(resume_path) = std::env::var("RESUME_NOTE") {
        header("Step 1: resume persisted note (skip deposit)");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&resume_path)?)?;
        let hex32 = |k: &str| -> anyhow::Result<[u8; 32]> {
            let s = v[k]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("note file missing {k}"))?;
            hex::decode(s)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("{k} not 32 bytes"))
        };
        let li = v["leaf_index"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("note file missing leaf_index"))?;
        let amt = v["amount"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("note file missing amount"))?;
        println!(
            "resumed note:      {resume_path} (leaf {li}, {} SOL)",
            amt as f64 / 1e9
        );
        (
            hex32("in_sk")?,
            hex32("in_blinding")?,
            hex32("in_note_pubkey")?,
            li,
            amt,
        )
    } else {
        header("Step 1: shielded deposit (native SOL, deposit_note v3)");
        let sk = rand_fr();
        let blinding = rand_fr();
        let pk_note = v3_pubkey(sk);
        let ix = create_deposit_note_instruction(
            &program_id,
            &payer.pubkey(),
            &vault_pda,
            swap_amount,
            fr_to_le(&pk_note),
            fr_to_le(&blinding),
        )?;
        let bh = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
        let deposit_sig = client.send_and_confirm_transaction(&tx)?;
        println!("deposit tx:        {deposit_sig}");

        // Read the just-appended leaf index from the on-chain tree.
        let raw = client.get_account_data(&tree_pda)?;
        let next_index = u64::from_le_bytes(raw[8..16].try_into()?);
        let leaf_index = next_index - 1;
        println!("leaf index:        {leaf_index}");

        // Persist the note secret NOW, before the withdraw, so the deposit is
        // always recoverable if the rest of the run fails.
        let sk_le = fr_to_le(&sk);
        let blinding_le = fr_to_le(&blinding);
        let pk_le = fr_to_le(&pk_note);
        let note_path = format!("private_swap_note_leaf{leaf_index}.json");
        let note = serde_json::json!({
            "in_sk": hex::encode(sk_le),
            "in_blinding": hex::encode(blinding_le),
            "in_note_pubkey": hex::encode(pk_le),
            "leaf_index": leaf_index,
            "amount": swap_amount,
        });
        std::fs::write(&note_path, serde_json::to_string_pretty(&note)?)?;
        println!("note saved:        {note_path}  (retry withdraw with RESUME_NOTE={note_path})");
        (sk_le, blinding_le, pk_le, leaf_index, swap_amount)
    };

    // ── Step 2: build the fresh (user-controlled) output wallet ─────────────
    header("Step 2: fresh output wallet");
    // Caller-supplied per the swap-out contract: the party that will spend the
    // USDC (the operator) holds this key, not the relayer. Persist it so the
    // realized USDC is recoverable after the run.
    let fresh = Keypair::new();
    let fresh_path = format!("private_swap_fresh_{}.json", fresh.pubkey());
    std::fs::write(
        &fresh_path,
        serde_json::to_string(&fresh.to_bytes().to_vec())?,
    )?;
    println!("fresh address:     {}", fresh.pubkey());
    println!("fresh key saved:   {fresh_path}  (holds the swapped USDC — keep it)");

    // ── Step 3: run the relayer swap-out ────────────────────────────────────
    header("Step 3: execute_swap_out (withdraw via quorum -> Jupiter SOL->USDC)");
    let mut jupiter = JupiterSwapProvider::new(
        ReqwestJupiterClient::new(jupiter_base_url.clone()),
        RpcSwapSubmitter::new(rpc_url.clone()),
        slippage_bps,
        0,
        None,
    )
    .map_err(|e| anyhow::anyhow!("building Jupiter provider: {e}"))?;
    if env_flag("SWAP_LEGACY_ROUTING") {
        jupiter = jupiter.with_legacy_routing();
    }
    if let Ok(dexes) = std::env::var("SWAP_DEXES") {
        jupiter = jupiter.with_dexes(dexes);
    }

    let submitter = OnChainSubmitter::new(rpc_url.clone(), program_id, ingress, &proving_key_path)
        .map_err(|e| anyhow::anyhow!("building on-chain submitter: {e}"))?;

    // The fresh address pays the swap's own rent + fees out of the withdrawn
    // lamports, so reserve a margin the swap must not spend. ~0.005 SOL is the
    // boundary (two token-account rents + two fees + the fresh account's own
    // rent floor); 0.01 SOL keeps a clean margin.
    let relayer = PrivateSwapRelayer::new(jupiter, submitter)
        .with_native_swap_overhead(LAMPORTS_PER_SOL / 100);

    let request = PrivateSwapRequest {
        amount_in: note_amount,
        asset_in: NATIVE_SOL_ASSET,
        in_sk: in_sk_le,
        in_blinding: in_blinding_le,
        in_note_pubkey: in_note_pubkey_le,
        in_leaf_index: leaf_index,
        asset_out: usdc_asset,
        // Unused on the swap-out path (no re-shield), but the request carries
        // them for the full-round-trip `execute`; fill with fresh randomness.
        reshield_recipient: ShieldedAddress::from_bytes(fr_to_le(&rand_fr())),
        reshield_randomness: fr_to_le(&rand_fr()),
        fee_bps: 0,
    };

    match relayer.execute_swap_out(request, &fresh).await {
        Ok(result) => {
            header("Private swap-out complete");
            let fresh_pk = Pubkey::new_from_array(result.fresh_address);
            println!(
                "Withdraw settled:  {} lamports -> {fresh_pk}",
                result.withdraw_leg.amount
            );
            println!("  quorum ref:      {}", result.withdraw_leg.signature);
            println!(
                "USDC realized:     {} (base units) at {fresh_pk}",
                result.gross_out_amount
            );
            println!();
            println!(
                "The deposit was funded by {}; the SOL->USDC swap originates at the",
                payer.pubkey()
            );
            println!("fresh address, which shares no signer with it. Verify on-chain:");
            println!("  spl-token accounts --owner {fresh_pk} --url {rpc_url}");
            println!();
            println!("Note: the USDC is held publicly at the (unlinkable) fresh address, not");
            println!("re-shielded — the native-only v3 pool cannot re-deposit an SPL token.");
            println!("Re-shielding the output is redeploy-gated follow-up work.");
            Ok(())
        }
        Err(RelayerError::NoRoute(msg)) => {
            header("No swap route (expected off a mainnet-fork / mainnet)");
            println!("Jupiter returned no route for SOL -> USDC: {msg}");
            println!();
            println!("Jupiter liquidity is mainnet-only. Run against the localnet mainnet-fork");
            println!("(scripts/localnet/private_swap_fork.sh) or real mainnet.");
            println!("The note (leaf {leaf_index}) is intact and recoverable via its saved file.");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("private swap-out failed: {e}")),
    }
}
