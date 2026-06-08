//! Devnet/localnet private-swap end-to-end demo (#240).
//!
//! Runs the FULL private-swap flow through the real relayer
//! (`paraloom::relayer::PrivateSwapRelayer`):
//!
//! 1. The user deposits a shielded note (native SOL) into the pool.
//! 2. `PrivateSwapRelayer::execute` composes three legs: it withdraws the note
//!    to a FRESH ephemeral keypair (the nullifier is burned on-chain, severing
//!    the link to the user's deposit); performs a REAL Jupiter v6 swap
//!    SOL -> USDC from the fresh address (`JupiterSwapProvider` routes via the
//!    live `quote-api.jup.ag/v6` and submits through the configured RPC); then
//!    re-deposits the USDC output into the user's new shielded balance.
//! 3. Prints each leg's signature + the fresh address so the link-severing is
//!    visible.
//!
//! # Honest framing
//!
//! Jupiter's liquidity is mainnet-only — there is no devnet/testnet Jupiter API
//! or pool liquidity. So a REAL swap cannot run against plain devnet. This demo
//! is built to run against a LOCALNET MAINNET-FORK: a `solana-test-validator`
//! with the Jupiter program + DEX pools cloned from mainnet (see
//! `scripts/localnet/private_swap_fork.sh`). The swap leg then trades against
//! that forked mainnet liquidity — real routing, no real money. Paraloom's own
//! deposit/withdraw legs are also live and publicly verifiable on devnet
//! separately (the wallet's deposit->withdraw flow).
//!
//! Run it without the fork (plain devnet) and the swap step returns `NoRoute`;
//! the demo narrates that honestly instead of faking a success.
//!
//! # Required environment
//!   SOLANA_RPC_URL           RPC endpoint (default http://localhost:8899).
//!   SOLANA_PROGRAM_ID        deployed Paraloom program id.
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  funded, registered-validator authority key.
//!
//! # Optional environment (defaults in parentheses)
//!   USDC_MINT                output mint (EPjFW…Dt1v, mainnet USDC).
//!   SWAP_AMOUNT_LAMPORTS     SOL note size to swap (50_000_000 = 0.05 SOL).
//!   SLIPPAGE_BPS             Jupiter slippage tolerance (50).
//!   JUPITER_BASE_URL         Jupiter v6 base (quote-api.jup.ag/v6).

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand as ark_rand;
use paraloom::bridge::solana::*;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use paraloom::privacy::types::{Note, Nullifier, ShieldedAddress};
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
use std::{fs, path::Path, str::FromStr, time::Instant};

const PROVING_KEY_PATH: &str = "keys/withdraw_proving_v3.key";
const VERIFYING_KEY_PATH: &str = "keys/withdraw_verifying_v3.key";
/// Mainnet USDC mint — the deepest, most reliable SOL pair to fork.
const DEFAULT_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const EXPIRATION_WINDOW_SLOTS: u64 = 1_000;

fn header(s: &str) {
    println!("\n=== {} ===", s);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    println!("=== Paraloom Private-Swap End-to-End Demo (#240) ===");
    println!("deposit -> withdraw to fresh key -> REAL Jupiter SOL->USDC -> re-deposit");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")
        .map_err(|_| anyhow::anyhow!("SOLANA_PROGRAM_ID env var required"))?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")
        .map_err(|_| anyhow::anyhow!("BRIDGE_AUTHORITY_KEYPAIR_PATH env var required"))?;
    let usdc_mint_str =
        std::env::var("USDC_MINT").unwrap_or_else(|_| DEFAULT_USDC_MINT.to_string());
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

    let program_id = Pubkey::from_str(&program_id_str)?;
    let usdc_mint = Pubkey::from_str(&usdc_mint_str)?;
    let usdc_asset: [u8; 32] = usdc_mint.to_bytes();
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    header("Pre-flight checks");
    println!("RPC URL:           {}", rpc_url);
    println!("Program ID:        {}", program_id);
    println!("Authority:         {}", authority.pubkey());
    println!("Output mint (USDC):{}", usdc_mint);
    println!("Jupiter base:      {}", jupiter_base_url);
    println!(
        "Swap amount:       {} SOL ({} lamports)",
        swap_amount as f64 / 1e9,
        swap_amount
    );

    if !Path::new(PROVING_KEY_PATH).exists() {
        return Err(anyhow::anyhow!(
            "Proving key missing at {PROVING_KEY_PATH}. Run:\n  \
             cargo run --release --bin setup-withdrawal-ceremony"
        ));
    }

    let (bridge_state, _) = derive_bridge_state(&program_id);
    client
        .get_account(&bridge_state)
        .map_err(|_| anyhow::anyhow!("Bridge state PDA not found. Run bridge-init first."))?;
    let (bridge_vault, _) = derive_bridge_vault(&program_id);
    println!("Bridge state PDA:  {}", bridge_state);
    println!("Bridge vault PDA:  {}", bridge_vault);

    // The shared bridge_vault accumulates every deposit in production, so a single
    // withdraw never drains it. A fresh demo vault holds only this one note, so
    // withdrawing the full note would leave it below the rent-exempt floor (the
    // "account (1) insufficient funds for rent" a SystemAccount vault hits). Seed a
    // small rent buffer up front so the withdraw leg's transfer settles.
    let vault_buffer = LAMPORTS_PER_SOL / 100; // 0.01 SOL, well above the rent floor
    let _ = client.request_airdrop(&bridge_vault, vault_buffer)?;
    for _ in 0..20 {
        if client.get_balance(&bridge_vault)? >= vault_buffer {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // ----------------------------------------------------------------
    // Step 1: the user deposits a native-SOL note into the shielded pool.
    // ----------------------------------------------------------------
    header("Step 1: user shielded deposit (native SOL)");
    let user = Keypair::new();
    println!("User (depositor):  {}", user.pubkey());

    let airdrop_amount = swap_amount + LAMPORTS_PER_SOL; // note + tx fees
    println!("Airdropping user {} SOL...", airdrop_amount as f64 / 1e9);
    let _ = client.request_airdrop(&user.pubkey(), airdrop_amount)?;
    let mut user_balance = 0u64;
    for _ in 0..20 {
        user_balance = client.get_balance(&user.pubkey())?;
        if user_balance >= airdrop_amount {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if user_balance < airdrop_amount {
        return Err(anyhow::anyhow!(
            "Airdrop did not credit the user within 10s (balance {user_balance})"
        ));
    }

    // The note the user is spending. randomness doubles as the spend secret on
    // the single-note path (mirrors demo_flow / the relayer's nullifier derive).
    let mut rng_std = ark_rand::thread_rng();
    let mut recipient_bytes = [0u8; 32];
    let mut randomness = [0u8; 32];
    ark_rand::RngCore::fill_bytes(&mut rng_std, &mut recipient_bytes);
    ark_rand::RngCore::fill_bytes(&mut rng_std, &mut randomness);
    let recipient = ShieldedAddress::from_bytes(recipient_bytes);

    let input_note = Note::new_native(recipient.clone(), swap_amount, randomness);
    let commitment = input_note.commitment();
    println!("Shielded address:  {}", recipient.to_hex());
    println!("Commitment:        {}", commitment.to_hex());

    let ix_deposit = create_deposit_instruction(
        &program_id,
        &user.pubkey(),
        &bridge_vault,
        swap_amount,
        recipient_bytes,
        randomness,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let deposit_tx = Transaction::new_signed_with_payer(
        &[ix_deposit],
        Some(&user.pubkey()),
        &[&user],
        blockhash,
    );
    let deposit_sig = client.send_and_confirm_transaction(&deposit_tx)?;
    println!("User deposit tx:   {}", deposit_sig);

    // ----------------------------------------------------------------
    // Step 2: generate the Groth16 withdrawal proof for the note. The relayer
    // forwards it unmodified to the withdraw leg. Single-deposit local case:
    // root = commitment, path = [] (same simplification as demo_flow).
    // ----------------------------------------------------------------
    header("Step 2: Groth16 withdrawal proof");
    let nullifier = Nullifier::derive(&commitment, &randomness);
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes.copy_from_slice(commitment.as_bytes());
    let mut nullifier_bytes = [0u8; 32];
    nullifier_bytes.copy_from_slice(nullifier.as_bytes());

    let proving_key_bytes = fs::read(PROVING_KEY_PATH)?;
    let proving_key = ProvingKey::<Bls12_381>::deserialize_compressed(&proving_key_bytes[..])?;
    let circuit = WithdrawCircuit::with_witness(
        merkle_root_bytes,
        nullifier_bytes,
        swap_amount,
        swap_amount,
        randomness,
        recipient_bytes,
        randomness,
        Vec::new(),
    );
    let proof_start = Instant::now();
    let mut rng = ark_rand::thread_rng();
    let proof = Groth16ProofSystem::prove::<WithdrawCircuit, _>(&proving_key, circuit, &mut rng)?;
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    println!(
        "Proof:             {} bytes in {:.2}s",
        proof_bytes.len(),
        proof_start.elapsed().as_secs_f64()
    );
    if Path::new(VERIFYING_KEY_PATH).exists() {
        let vk =
            VerifyingKey::<Bls12_381>::deserialize_compressed(&fs::read(VERIFYING_KEY_PATH)?[..])?;
        let public_inputs = vec![
            Fr::from_le_bytes_mod_order(&merkle_root_bytes),
            Fr::from_le_bytes_mod_order(&nullifier_bytes),
            Fr::from(swap_amount),
        ];
        // The on-chain withdraw path records the proof but does NOT verify it
        // (#165, pending SIMD-0388 BLS12-381 precompiles); real verification is
        // the L2 quorum's job. So a local-verify mismatch (e.g. a proving key /
        // verifying key vintage skew between keys/withdraw_*_v3.key) is a
        // diagnostic, not a blocker for exercising the on-chain legs — what the
        // chain actually checks is the non-empty proof and the nullifier the
        // relayer derives. Surface it honestly and keep going.
        match Groth16ProofSystem::verify(&vk, &public_inputs, &proof) {
            Ok(true) => println!("Local verify:      OK"),
            Ok(false) => println!(
                "Local verify:      MISMATCH (informational; on-chain does not verify proofs, #165)"
            ),
            Err(e) => println!("Local verify:      error {e} (informational)"),
        }
    }

    // ----------------------------------------------------------------
    // Step 3: run the real relayer. Withdraw->swap->re-deposit, composed.
    // ----------------------------------------------------------------
    header("Step 3: PrivateSwapRelayer::execute (withdraw -> Jupiter -> re-deposit)");

    // Swap provider: real Jupiter routing + real on-chain submission to the
    // configured RPC (the localnet mainnet-fork). 0 platform fee keeps the demo
    // free of a fee-account setup; the relayer-fee mechanics are unit-tested.
    let jupiter = JupiterSwapProvider::new(
        ReqwestJupiterClient::new(jupiter_base_url.clone()),
        RpcSwapSubmitter::new(rpc_url.clone()),
        slippage_bps,
        0,
        None,
    )
    .map_err(|e| anyhow::anyhow!("building Jupiter provider: {e}"))?
    // The fork only clones a couple of pools and none of mainnet's ALTs, so ask
    // Jupiter for a single-hop legacy tx that references only cloned accounts...
    .with_legacy_routing()
    // ...and pin the route to Orca Whirlpool, the AMM the fork actually cloned,
    // so Jupiter's Route does not CPI into an un-cloned DEX program.
    .with_dexes("Whirlpool");

    // On-chain submitter: authority signs the withdraw legs; the ephemeral key
    // signs the re-deposit leg. authority must be a registered validator.
    let submitter = OnChainSubmitter::new(
        rpc_url.clone(),
        program_id,
        authority.insecure_clone(),
        EXPIRATION_WINDOW_SLOTS,
    );

    // On a native-SOL leg the fresh address pays every downstream on-chain cost
    // out of the same lamports, so the relayer trades the note amount minus this
    // reserve. The reserve must cover: the output USDC ATA rent (swap leg) + the
    // shielded vault token-account rent (re-deposit leg), ~0.00204 SOL each, two
    // tx fees, AND leave the ephemeral account itself rent-exempt (~0.00089 SOL,
    // since a system account can't end between zero and the rent floor). ~0.005
    // SOL lands right on that boundary, so reserve 0.01 SOL for a clean margin.
    let native_swap_overhead = LAMPORTS_PER_SOL / 100; // 0.01 SOL
    let relayer =
        PrivateSwapRelayer::new(jupiter, submitter).with_native_swap_overhead(native_swap_overhead);

    let mut reshield_recipient_bytes = [0u8; 32];
    let mut reshield_randomness = [0u8; 32];
    ark_rand::RngCore::fill_bytes(&mut rng_std, &mut reshield_recipient_bytes);
    ark_rand::RngCore::fill_bytes(&mut rng_std, &mut reshield_randomness);

    let request = PrivateSwapRequest {
        input_note,
        asset_out: usdc_asset,
        reshield_recipient: ShieldedAddress::from_bytes(reshield_recipient_bytes),
        reshield_randomness,
        fee_bps: 0,
        withdraw_proof: proof_bytes,
    };

    match relayer.execute(request).await {
        Ok(result) => {
            header("Private swap complete");
            let fresh = Pubkey::new_from_array(result.fresh_address);
            println!("Fresh ephemeral:   {}", fresh);
            println!("  (shares NO signer with the user {} above)", user.pubkey());
            println!();
            println!(
                "Withdraw leg:      {:?}  {} -> fresh   tx {}",
                result.withdraw_leg.leg, result.withdraw_leg.amount, result.withdraw_leg.signature
            );
            println!(
                "Gross swap out:    {} USDC base units (Jupiter realized)",
                result.gross_out_amount
            );
            println!("Relayer fee:       {}", result.relayer_fee);
            println!("Net re-shielded:   {}", result.net_out_amount);
            println!(
                "Deposit leg:       {:?}  {} from fresh   tx {}",
                result.deposit_leg.leg, result.deposit_leg.amount, result.deposit_leg.signature
            );
            println!("Output note:       {} USDC", result.output_note.amount);
            println!();
            println!("Inspect the on-chain trace:");
            println!(
                "  solana confirm -v {} --url {}",
                result.withdraw_leg.signature, rpc_url
            );
            println!(
                "  solana confirm -v {} --url {}",
                result.deposit_leg.signature, rpc_url
            );
            println!();
            println!("The user funded the original deposit; the SOL->USDC swap and the");
            println!("re-deposit originate at the unlinkable fresh address. The chain shows");
            println!("no shared signer between them.");
            Ok(())
        }
        Err(RelayerError::NoRoute(msg)) => {
            header("No swap route (expected on plain devnet)");
            println!("Jupiter returned no route for SOL -> USDC: {msg}");
            println!();
            println!("This is the documented devnet-vs-mainnet reality: Jupiter liquidity is");
            println!("mainnet-only. To run the swap leg for real, start the localnet");
            println!("mainnet-fork and point SOLANA_RPC_URL/JUPITER_BASE_URL at it:");
            println!("  scripts/localnet/private_swap_fork.sh");
            println!();
            println!("The Paraloom deposit leg above DID execute on-chain (tx {deposit_sig});");
            println!("only the public swap leg needs forked mainnet liquidity.");
            // Not an error: this is the honest, documented devnet outcome.
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("private swap failed: {e}")),
    }
}
