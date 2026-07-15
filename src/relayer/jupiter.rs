//! Jupiter v6 swap provider (#239): the public leg of a private swap routed
//! over real Solana liquidity via [Jupiter](https://station.jup.ag/)'s
//! aggregator.
//!
//! # Where this sits
//!
//! The private-swap relayer ([`super::private_swap`]) withdraws a shielded note
//! to a fresh ephemeral address (step 1), swaps `asset_in -> asset_out` there
//! (step 2), and re-deposits the result (step 4). This module implements step 2
//! against Jupiter v6. It is wired in as a [`SwapProvider`] so the orchestration
//! is unchanged: the relayer hands us the in/out mints, the amount, and the
//! per-swap ephemeral [`Keypair`], and we return the realized gross output.
//!
//! # The Jupiter v6 call sequence
//!
//! 1. **Quote** — `GET /v6/quote?inputMint&outputMint&amount&slippageBps&platformFeeBps`.
//!    Returns the best `routePlan` and the expected `outAmount`. No liquidity
//!    path for the pair/amount yields an empty/`error` response, surfaced as
//!    [`RelayerError::NoRoute`].
//! 2. **Swap** — `POST /v6/swap` with `{ quoteResponse, userPublicKey, feeAccount }`.
//!    Returns a base64-encoded, ready-to-sign `swapTransaction` (a versioned
//!    transaction) routed through the platform-fee account.
//! 3. **Execute** — sign that transaction with the fresh ephemeral keypair and
//!    submit it through the Solana RPC, then report the quote's `outAmount` as
//!    the realized gross output.
//!
//! # Fee model (the resolved #238 decision)
//!
//! The relayer fee is taken **on the public leg by Jupiter itself**, via the
//! quote's `platformFeeBps` plus a `feeAccount` (a token account the relayer
//! controls for the output mint). Jupiter deducts the fee inside the route and
//! credits the fee account; it never touches the shielded amounts. This is why
//! [`PrivateSwapRequest::fee_bps`](super::private_swap::PrivateSwapRequest) and
//! the provider's `platform_fee_bps` are two views of the same cut — the
//! orchestrator's abstract `fee_bps` is realized here as Jupiter's
//! `platformFeeBps`.
//!
//! # Honest devnet note
//!
//! Jupiter's liquidity is overwhelmingly on **mainnet**. On devnet most pairs
//! return no route, so [`JupiterSwapProvider::swap`] there typically fails with
//! [`RelayerError::NoRoute`] — handled gracefully, not a panic. The #240 demo
//! should therefore either run against mainnet liquidity or expect (and narrate)
//! the no-route path on devnet. Against mainnet the full quote -> swap -> submit
//! sequence executes normally.
//!
//! # Testability
//!
//! The HTTP transport is injected as a [`JupiterHttpClient`] and the on-chain
//! submission as a [`SwapSubmitter`], so the quote/swap parsing, mint
//! conversion, fee/slippage plumbing, and the no-route path are all unit-tested
//! with canned JSON and no network or validator. The production path uses
//! [`ReqwestJupiterClient`] + [`RpcSwapSubmitter`]; their thin wrappers around
//! `reqwest` / `RpcClient` are the only parts not exercised in CI (no network).

use crate::privacy::types::{AssetId, NATIVE_SOL_ASSET};
use crate::relayer::private_swap::{RelayerError, Result, SwapProvider, SwapResult};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_sdk::transaction::VersionedTransaction;
use std::str::FromStr;

/// Wrapped-SOL mint. Jupiter trades wSOL rather than the native lamport
/// balance, so [`NATIVE_SOL_ASSET`] maps to this mint on the wire.
pub const WRAPPED_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Default Jupiter Swap API base (the public hosted endpoint). The legacy
/// `quote-api.jup.ag/v6` host was retired; the current free, keyless endpoint is
/// `lite-api.jup.ag/swap/v1` (the paid/keyed host is `api.jup.ag/swap/v1`). The
/// client appends `/quote` and `/swap`. Overridable on the provider so unit
/// tests point at a canned client and operators can use a paid endpoint.
pub const DEFAULT_JUPITER_BASE_URL: &str = "https://lite-api.jup.ag/swap/v1";

/// Convert an [`AssetId`] into the base58 mint string Jupiter expects.
///
/// [`NATIVE_SOL_ASSET`] (all-zero) maps to [`WRAPPED_SOL_MINT`]; every other id
/// is the SPL mint's 32 bytes, encoded base58.
pub fn asset_to_mint(asset: AssetId) -> String {
    if asset == NATIVE_SOL_ASSET {
        WRAPPED_SOL_MINT.to_string()
    } else {
        bs58::encode(asset).into_string()
    }
}

/// The fields we read out of a Jupiter v6 quote. Jupiter returns more, but the
/// whole object is round-tripped back into the swap request as `quoteResponse`,
/// so we keep the raw value too.
#[derive(Debug, Clone, Deserialize)]
struct QuoteResponse {
    /// Expected output amount, as a decimal string in the out mint's base units.
    #[serde(rename = "outAmount")]
    out_amount: String,
    /// The chosen route. Empty/absent means no liquidity path was found.
    #[serde(rename = "routePlan", default)]
    route_plan: Vec<serde_json::Value>,
    /// Present when Jupiter rejects the request (e.g. no route, bad mint).
    #[serde(rename = "error", default)]
    error: Option<String>,
}

/// Body of the `POST /v6/swap` request.
#[derive(Debug, Serialize)]
struct SwapRequestBody<'a> {
    /// The exact quote object returned by `/v6/quote`, echoed back verbatim.
    #[serde(rename = "quoteResponse")]
    quote_response: &'a serde_json::Value,
    /// The fresh ephemeral address that signs and pays for the swap.
    #[serde(rename = "userPublicKey")]
    user_public_key: String,
    /// The relayer's fee token account for the output mint. Jupiter credits the
    /// `platformFeeBps` cut here. Omitted when no platform fee is configured.
    #[serde(rename = "feeAccount", skip_serializing_if = "Option::is_none")]
    fee_account: Option<String>,
    /// Let Jupiter wrap/unwrap SOL as needed so a native-SOL leg just works.
    #[serde(rename = "wrapAndUnwrapSol")]
    wrap_and_unwrap_sol: bool,
    /// Ask Jupiter for a legacy transaction (no Address Lookup Tables). Skipped
    /// from the body when false so mainnet keeps the default versioned tx.
    #[serde(rename = "asLegacyTransaction", skip_serializing_if = "is_false")]
    as_legacy_transaction: bool,
}

/// serde helper: omit a `bool` field when it is `false`.
fn is_false(b: &bool) -> bool {
    !*b
}

/// The `/v6/swap` response: a base64 versioned transaction, ready to sign.
#[derive(Debug, Clone, Deserialize)]
struct SwapTxResponse {
    #[serde(rename = "swapTransaction")]
    swap_transaction: String,
}

/// Transport seam for Jupiter's HTTP API.
///
/// Splitting the network out behind this trait lets the quote/swap parsing and
/// the no-route path be unit-tested with canned JSON. [`ReqwestJupiterClient`]
/// is the production impl; tests use an in-memory canned client.
#[async_trait::async_trait]
pub trait JupiterHttpClient: Send + Sync {
    /// `GET /v6/quote?<query>` — returns the raw JSON body.
    async fn get_quote(&self, query: &str) -> Result<serde_json::Value>;
    /// `POST /v6/swap` with `body` — returns the raw JSON body.
    async fn post_swap(&self, body: &serde_json::Value) -> Result<serde_json::Value>;
}

/// On-chain submission seam: sign the Jupiter swap transaction with the fresh
/// ephemeral keypair and push it through an RPC, returning the transaction
/// signature. Behind a trait so the sign+submit step is mockable in tests and
/// the real [`RpcSwapSubmitter`] (which needs a live validator) is the only
/// network-touching part.
#[async_trait::async_trait]
pub trait SwapSubmitter: Send + Sync {
    /// Sign `transaction` with `signer` and submit it; return the signature.
    async fn sign_and_submit(
        &self,
        transaction: VersionedTransaction,
        signer: &Keypair,
    ) -> Result<String>;

    /// The realized output-token balance on `owner`'s associated token account
    /// after the swap settled, or `None` when it can't be read cheaply (the
    /// default). A Jupiter quote is computed against current liquidity; the
    /// executed swap can land a different amount — slippage on mainnet, or
    /// frozen-pool drift on a mainnet fork cloned at an earlier slot — so
    /// reading the balance back lets the caller re-shield exactly what arrived
    /// instead of the estimate. The default keeps mock submitters quote-driven.
    async fn realized_output(&self, _owner: &Pubkey, _mint: &Pubkey) -> Result<Option<u64>> {
        Ok(None)
    }

    /// The realized native (lamport) balance of `owner` after a swap whose
    /// output is SOL, or `None` when it can't be read cheaply (the default).
    /// Unlike an SPL output there is no token account to read, and the lamport
    /// balance doubles as the fee asset — so the caller re-shields this balance
    /// minus a small reserve rather than the quote, which an over-quote would
    /// push above the actual balance and strand on a failed re-deposit.
    async fn realized_native(&self, _owner: &Pubkey) -> Result<Option<u64>> {
        Ok(None)
    }
}

/// Lamports left at the ephemeral address when re-depositing a native-SOL swap
/// output, to cover the re-deposit transaction's own fee. The realized balance
/// minus this reserve is what gets re-shielded.
const NATIVE_DEPOSIT_RESERVE_LAMPORTS: u64 = 10_000;

/// Production [`JupiterHttpClient`] over `reqwest`, talking to a configurable
/// base URL.
pub struct ReqwestJupiterClient {
    http: reqwest::Client,
    base_url: String,
}

impl ReqwestJupiterClient {
    /// Build a client against `base_url` (e.g. [`DEFAULT_JUPITER_BASE_URL`]).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
        }
    }
}

#[async_trait::async_trait]
impl JupiterHttpClient for ReqwestJupiterClient {
    async fn get_quote(&self, query: &str) -> Result<serde_json::Value> {
        let url = format!("{}/quote?{}", self.base_url, query);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| RelayerError::HttpError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RelayerError::HttpError(format!(
                "quote returned HTTP {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| RelayerError::HttpError(e.to_string()))
    }

    async fn post_swap(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
        let url = format!("{}/swap", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| RelayerError::HttpError(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(RelayerError::HttpError(format!(
                "swap returned HTTP {}",
                resp.status()
            )));
        }
        resp.json()
            .await
            .map_err(|e| RelayerError::HttpError(e.to_string()))
    }
}

/// Production [`SwapSubmitter`] over a Solana [`RpcClient`]. Signs the versioned
/// transaction with the fresh keypair (replacing the unsigned placeholder
/// signature Jupiter leaves for `userPublicKey`) and confirms it.
///
/// [`RpcClient`] is blocking, so the call is run on a blocking thread to avoid
/// stalling the async runtime.
pub struct RpcSwapSubmitter {
    rpc_url: String,
}

impl RpcSwapSubmitter {
    /// Submitter against the JSON-RPC endpoint at `rpc_url`.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
        }
    }
}

#[async_trait::async_trait]
impl SwapSubmitter for RpcSwapSubmitter {
    async fn sign_and_submit(
        &self,
        transaction: VersionedTransaction,
        signer: &Keypair,
    ) -> Result<String> {
        use solana_client::rpc_client::RpcClient;
        use solana_sdk::commitment_config::CommitmentConfig;

        let rpc_url = self.rpc_url.clone();
        let signer = signer.insecure_clone();
        let mut message = transaction.message.clone();

        tokio::task::spawn_blocking(move || {
            let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
            // Jupiter stamps the swap tx with a blockhash from its own RPC, which
            // a custom or forked validator will not recognize ("Blockhash not
            // found"). Refresh it against the submitting RPC before signing so
            // the tx is valid wherever we land it; on mainnet this just renews an
            // already-valid hash, guarding against expiry between quote and send.
            let blockhash = client.get_latest_blockhash().map_err(|e| {
                RelayerError::SubmissionFailed(format!("blockhash fetch failed: {e}"))
            })?;
            message.set_recent_blockhash(blockhash);
            // Re-sign the message with the fresh keypair: Jupiter builds the tx
            // for `userPublicKey` but leaves the signature for the caller to fill.
            let signed = VersionedTransaction::try_new(message, &[&signer])
                .map_err(|e| RelayerError::SubmissionFailed(format!("signing failed: {e}")))?;
            client
                .send_and_confirm_transaction(&signed)
                .map(|sig| sig.to_string())
                .map_err(|e| RelayerError::SubmissionFailed(e.to_string()))
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("join error: {e}")))?
    }

    async fn realized_output(&self, owner: &Pubkey, mint: &Pubkey) -> Result<Option<u64>> {
        use solana_client::rpc_client::RpcClient;
        use solana_sdk::commitment_config::CommitmentConfig;

        let rpc_url = self.rpc_url.clone();
        let ata = crate::bridge::solana::derive_associated_token_address(owner, mint);
        tokio::task::spawn_blocking(move || {
            let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
            // A missing/unreadable ATA yields None, not an error: the caller then
            // falls back to the quote estimate rather than aborting the swap.
            match client.get_token_account_balance(&ata) {
                Ok(bal) => Ok(Some(bal.amount.parse::<u64>().unwrap_or(0))),
                Err(_) => Ok(None),
            }
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("join error: {e}")))?
    }

    async fn realized_native(&self, owner: &Pubkey) -> Result<Option<u64>> {
        use solana_client::rpc_client::RpcClient;
        use solana_sdk::commitment_config::CommitmentConfig;

        let rpc_url = self.rpc_url.clone();
        let owner = *owner;
        tokio::task::spawn_blocking(move || {
            let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
            // An unreadable balance yields None, not an error: the caller then
            // falls back to the quote estimate rather than aborting the swap.
            match client.get_balance(&owner) {
                Ok(lamports) => Ok(Some(lamports)),
                Err(_) => Ok(None),
            }
        })
        .await
        .map_err(|e| RelayerError::SubmissionFailed(format!("join error: {e}")))?
    }
}

/// Jupiter v6 [`SwapProvider`]: quotes and executes the public swap leg over
/// real Solana liquidity. Generic over the HTTP and submission seams so it is
/// fully unit-testable without network or RPC. See the module docs for the call
/// sequence, fee model, and the devnet no-route caveat.
pub struct JupiterSwapProvider<H: JupiterHttpClient, S: SwapSubmitter> {
    http: H,
    submitter: S,
    /// Slippage tolerance in basis points, passed to the quote as `slippageBps`.
    slippage_bps: u16,
    /// Relayer's platform fee in basis points (`platformFeeBps`). 0 disables it.
    platform_fee_bps: u16,
    /// Relayer fee token account (`feeAccount`) crediting the platform fee.
    /// Required whenever `platform_fee_bps > 0`.
    fee_account: Option<String>,
    /// Restrict quotes to single-hop routes (`onlyDirectRoutes`). Off by default
    /// so mainnet picks the cheapest multi-hop route; turn it on in environments
    /// (e.g. a mainnet fork) where only a couple of pools have been cloned.
    direct_routes_only: bool,
    /// Force a legacy (non-versioned) swap transaction (`asLegacyTransaction`).
    /// Off by default so mainnet uses Address Lookup Tables; turn it on where the
    /// referenced ALT accounts are not present (again, a mainnet fork).
    legacy_transaction: bool,
    /// Optional `dexes` allow-list pinning the route to specific AMMs (e.g.
    /// `"Whirlpool"`). None lets Jupiter use any venue; set it on a fork so the
    /// route only touches the pools/programs that were actually cloned.
    dexes: Option<String>,
}

impl<H: JupiterHttpClient, S: SwapSubmitter> JupiterSwapProvider<H, S> {
    /// Build a provider over an HTTP client and a submitter.
    ///
    /// `slippage_bps` bounds price movement on the route. `platform_fee_bps` +
    /// `fee_account` are the relayer's cut taken inside the route by Jupiter; a
    /// non-zero fee with no account is rejected at construction.
    pub fn new(
        http: H,
        submitter: S,
        slippage_bps: u16,
        platform_fee_bps: u16,
        fee_account: Option<String>,
    ) -> Result<Self> {
        if platform_fee_bps > 0 && fee_account.is_none() {
            return Err(RelayerError::SwapFailed(
                "platform_fee_bps > 0 requires a fee_account".into(),
            ));
        }
        if platform_fee_bps > 10_000 {
            return Err(RelayerError::FeeTooHigh(platform_fee_bps));
        }
        Ok(Self {
            http,
            submitter,
            slippage_bps,
            platform_fee_bps,
            fee_account,
            direct_routes_only: false,
            legacy_transaction: false,
            dexes: None,
        })
    }

    /// Opt into ALT-free routing: single-hop quotes plus a legacy swap
    /// transaction. Intended for partial-clone environments (a mainnet fork)
    /// where multi-hop routes or Address Lookup Tables reference accounts that
    /// have not been cloned. Leave it off against real mainnet.
    pub fn with_legacy_routing(mut self) -> Self {
        self.direct_routes_only = true;
        self.legacy_transaction = true;
        self
    }

    /// Pin routing to a specific AMM allow-list (Jupiter's `dexes` param, e.g.
    /// `"Whirlpool"`). On a mainnet fork this keeps the route inside the venues
    /// whose programs and pools were cloned; unset against real mainnet.
    pub fn with_dexes(mut self, dexes: impl Into<String>) -> Self {
        self.dexes = Some(dexes.into());
        self
    }

    /// Build the `/v6/quote` query string for the given pair/amount, folding in
    /// the configured slippage and platform fee.
    fn quote_query(&self, input_mint: &str, output_mint: &str, amount: u64) -> String {
        let mut q = format!(
            "inputMint={}&outputMint={}&amount={}&slippageBps={}",
            input_mint, output_mint, amount, self.slippage_bps
        );
        if self.platform_fee_bps > 0 {
            q.push_str(&format!("&platformFeeBps={}", self.platform_fee_bps));
        }
        if self.direct_routes_only {
            q.push_str("&onlyDirectRoutes=true");
        }
        if let Some(dexes) = &self.dexes {
            q.push_str(&format!("&dexes={}", dexes));
        }
        q
    }

    /// Parse a `/v6/quote` body into the realized gross output, treating an
    /// `error` field or an empty `routePlan` as [`RelayerError::NoRoute`].
    fn parse_quote(raw: &serde_json::Value) -> Result<u64> {
        let quote: QuoteResponse = serde_json::from_value(raw.clone())
            .map_err(|e| RelayerError::SwapFailed(format!("malformed quote: {e}")))?;
        if let Some(err) = quote.error {
            return Err(RelayerError::NoRoute(err));
        }
        if quote.route_plan.is_empty() {
            return Err(RelayerError::NoRoute("empty routePlan".into()));
        }
        let out_amount_u128 = quote.out_amount.parse::<u128>().map_err(|e| {
            RelayerError::SwapFailed(format!("bad outAmount '{}': {e}", quote.out_amount))
        })?;
        u64::try_from(out_amount_u128).map_err(|_| RelayerError::AmountOverflow(out_amount_u128))
    }

    /// Decode Jupiter's base64 `swapTransaction` into a [`VersionedTransaction`].
    fn decode_swap_tx(raw: &serde_json::Value) -> Result<VersionedTransaction> {
        let resp: SwapTxResponse = serde_json::from_value(raw.clone())
            .map_err(|e| RelayerError::SwapFailed(format!("malformed swap response: {e}")))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(resp.swap_transaction.as_bytes())
            .map_err(|e| RelayerError::SwapFailed(format!("base64 decode failed: {e}")))?;
        bincode::deserialize::<VersionedTransaction>(&bytes)
            .map_err(|e| RelayerError::SwapFailed(format!("tx deserialize failed: {e}")))
    }
}

#[async_trait::async_trait]
impl<H: JupiterHttpClient, S: SwapSubmitter> SwapProvider for JupiterSwapProvider<H, S> {
    async fn swap(
        &self,
        asset_in: AssetId,
        asset_out: AssetId,
        amount: u64,
        signer: &Keypair,
    ) -> Result<SwapResult> {
        if amount == 0 {
            return Err(RelayerError::InvalidAmount(0));
        }
        let input_mint = asset_to_mint(asset_in);
        let output_mint = asset_to_mint(asset_out);

        // 1. Quote.
        let query = self.quote_query(&input_mint, &output_mint, amount);
        let quote_raw = self.http.get_quote(&query).await?;
        let out_amount = Self::parse_quote(&quote_raw)?;

        // 2. Swap: ask Jupiter to build the transaction for the fresh address,
        //    routing the platform fee to the relayer's fee account.
        let body = SwapRequestBody {
            quote_response: &quote_raw,
            user_public_key: signer.pubkey().to_string(),
            fee_account: self.fee_account.clone(),
            wrap_and_unwrap_sol: true,
            as_legacy_transaction: self.legacy_transaction,
        };
        let body_value = serde_json::to_value(&body)
            .map_err(|e| RelayerError::SwapFailed(format!("encode swap body: {e}")))?;
        let swap_raw = self.http.post_swap(&body_value).await?;
        let transaction = Self::decode_swap_tx(&swap_raw)?;

        // 3. Execute: sign with the fresh keypair and submit.
        self.submitter.sign_and_submit(transaction, signer).await?;

        // 4. Prefer the realized on-chain output over the quote estimate, so the
        //    re-shield leg deposits exactly what the swap delivered, not a stale
        //    figure that an over-quote would push above the actual balance and
        //    strand on a failed re-deposit (audit).
        let out_amount = if asset_out == NATIVE_SOL_ASSET {
            // Native output: re-shield the ephemeral's actual lamport balance
            // minus a reserve for the re-deposit fee, falling back to the quote
            // only when the balance can't be read.
            match self.submitter.realized_native(&signer.pubkey()).await? {
                Some(bal) => bal.saturating_sub(NATIVE_DEPOSIT_RESERVE_LAMPORTS),
                None => out_amount,
            }
        } else {
            let mint = Pubkey::from_str(&output_mint)
                .map_err(|e| RelayerError::SwapFailed(format!("bad output mint: {e}")))?;
            self.submitter
                .realized_output(&signer.pubkey(), &mint)
                .await?
                .unwrap_or(out_amount)
        };

        Ok(SwapResult { out_amount })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // --- AssetId -> mint conversion -------------------------------------

    #[test]
    fn native_sol_maps_to_wrapped_sol_mint() {
        assert_eq!(asset_to_mint(NATIVE_SOL_ASSET), WRAPPED_SOL_MINT);
    }

    #[test]
    fn spl_mint_round_trips_to_base58() {
        // A known mint's bytes encode back to its base58 string.
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let bytes: [u8; 32] = bs58::decode(usdc).into_vec().unwrap().try_into().unwrap();
        assert_eq!(asset_to_mint(bytes), usdc);
    }

    // --- Canned HTTP client seam ---------------------------------------

    /// Records the quote query / swap body it was handed and replays canned
    /// responses, so the full provider flow runs with no network.
    struct CannedClient {
        quote: serde_json::Value,
        swap: serde_json::Value,
        seen_query: Mutex<Option<String>>,
        seen_body: Mutex<Option<serde_json::Value>>,
    }

    impl CannedClient {
        fn new(quote: serde_json::Value, swap: serde_json::Value) -> Self {
            Self {
                quote,
                swap,
                seen_query: Mutex::new(None),
                seen_body: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl JupiterHttpClient for CannedClient {
        async fn get_quote(&self, query: &str) -> Result<serde_json::Value> {
            *self.seen_query.lock().unwrap() = Some(query.to_string());
            Ok(self.quote.clone())
        }
        async fn post_swap(&self, body: &serde_json::Value) -> Result<serde_json::Value> {
            *self.seen_body.lock().unwrap() = Some(body.clone());
            Ok(self.swap.clone())
        }
    }

    /// Submitter that records the keypair it signed with and returns a fixed
    /// signature, so the execute step needs no validator.
    #[derive(Default)]
    struct RecordingSubmitter {
        signed_pubkey: Mutex<Option<String>>,
    }

    #[async_trait::async_trait]
    impl SwapSubmitter for RecordingSubmitter {
        async fn sign_and_submit(
            &self,
            _transaction: VersionedTransaction,
            signer: &Keypair,
        ) -> Result<String> {
            *self.signed_pubkey.lock().unwrap() = Some(signer.pubkey().to_string());
            Ok("mock-swap-signature".into())
        }
    }

    /// A recorded `/v6/swap` body whose `swapTransaction` is a real base64
    /// versioned transaction (a transfer), so `decode_swap_tx` succeeds.
    fn sample_swap_tx_json() -> serde_json::Value {
        use solana_sdk::message::{Message, VersionedMessage};
        #[allow(deprecated)]
        use solana_sdk::system_instruction;
        let payer = Keypair::new();
        #[allow(deprecated)]
        let ix = system_instruction::transfer(&payer.pubkey(), &Keypair::new().pubkey(), 1);
        let msg = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = VersionedTransaction {
            signatures: vec![Default::default()],
            message: VersionedMessage::Legacy(msg),
        };
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        serde_json::json!({ "swapTransaction": b64 })
    }

    // --- Quote JSON parsing --------------------------------------------

    #[test]
    fn parses_out_amount_from_recorded_quote() {
        // Trimmed but realistic Jupiter v6 quote shape.
        let quote = serde_json::json!({
            "inputMint": WRAPPED_SOL_MINT,
            "outAmount": "12345678",
            "outputMint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "slippageBps": 50,
            "routePlan": [ { "swapInfo": { "label": "Orca" }, "percent": 100 } ]
        });
        assert_eq!(
            JupiterSwapProvider::<CannedClient, RecordingSubmitter>::parse_quote(&quote).unwrap(),
            12_345_678
        );
    }

    #[test]
    fn quote_out_amount_overflow_is_reported_explicitly() {
        let too_large = u64::MAX as u128 + 1;
        let quote = serde_json::json!({
            "outAmount": too_large.to_string(),
            "routePlan": [ { "swapInfo": { "label": "Orca" }, "percent": 100 } ]
        });

        let err = JupiterSwapProvider::<CannedClient, RecordingSubmitter>::parse_quote(&quote)
            .unwrap_err();
        assert!(matches!(err, RelayerError::AmountOverflow(v) if v == too_large));
    }

    #[test]
    fn empty_route_plan_is_no_route() {
        let quote = serde_json::json!({ "outAmount": "0", "routePlan": [] });
        let err = JupiterSwapProvider::<CannedClient, RecordingSubmitter>::parse_quote(&quote)
            .unwrap_err();
        assert!(matches!(err, RelayerError::NoRoute(_)));
    }

    #[test]
    fn explicit_error_field_is_no_route() {
        let quote = serde_json::json!({
            "outAmount": "0",
            "routePlan": [],
            "error": "Could not find any route"
        });
        let err = JupiterSwapProvider::<CannedClient, RecordingSubmitter>::parse_quote(&quote)
            .unwrap_err();
        match err {
            RelayerError::NoRoute(msg) => assert!(msg.contains("route")),
            other => panic!("expected NoRoute, got {other:?}"),
        }
    }

    // --- Slippage / fee plumbing ---------------------------------------

    #[test]
    fn slippage_and_fee_are_threaded_into_the_quote_query() {
        let http = CannedClient::new(serde_json::json!({}), serde_json::json!({}));
        let provider = JupiterSwapProvider::new(
            http,
            RecordingSubmitter::default(),
            75,
            30,
            Some("FeeAccount1111111111111111111111111111111111".into()),
        )
        .unwrap();
        let q = provider.quote_query(WRAPPED_SOL_MINT, "OutMint", 1_000);
        assert!(q.contains("slippageBps=75"), "query: {q}");
        assert!(q.contains("platformFeeBps=30"), "query: {q}");
        assert!(q.contains("amount=1000"), "query: {q}");
    }

    #[test]
    fn legacy_routing_adds_direct_routes_to_query() {
        let http = CannedClient::new(serde_json::json!({}), serde_json::json!({}));
        let provider =
            JupiterSwapProvider::new(http, RecordingSubmitter::default(), 50, 0, None).unwrap();
        // Off by default: mainnet keeps multi-hop, ALT-backed routes.
        assert!(!provider
            .quote_query("In", "Out", 1)
            .contains("onlyDirectRoutes"));
        // On after opting in: single-hop only, for partial-clone forks.
        let forked = provider.with_legacy_routing();
        assert!(forked
            .quote_query("In", "Out", 1)
            .contains("onlyDirectRoutes=true"));
        // A dex filter pins the route to a named AMM allow-list; off by default.
        assert!(!forked.quote_query("In", "Out", 1).contains("dexes="));
        let pinned = forked.with_dexes("Whirlpool");
        assert!(pinned
            .quote_query("In", "Out", 1)
            .contains("dexes=Whirlpool"));
    }

    #[test]
    fn legacy_routing_flags_the_swap_body_and_default_omits_it() {
        let quote = serde_json::json!({});
        let plain = SwapRequestBody {
            quote_response: &quote,
            user_public_key: "User1111".into(),
            fee_account: None,
            wrap_and_unwrap_sol: true,
            as_legacy_transaction: false,
        };
        let v = serde_json::to_value(&plain).unwrap();
        assert!(v.get("asLegacyTransaction").is_none(), "default omits flag");

        let legacy = SwapRequestBody {
            as_legacy_transaction: true,
            ..plain
        };
        let v = serde_json::to_value(&legacy).unwrap();
        assert_eq!(v["asLegacyTransaction"], serde_json::json!(true));
    }

    #[test]
    fn zero_platform_fee_omits_fee_param() {
        let http = CannedClient::new(serde_json::json!({}), serde_json::json!({}));
        let provider =
            JupiterSwapProvider::new(http, RecordingSubmitter::default(), 50, 0, None).unwrap();
        let q = provider.quote_query("In", "Out", 42);
        assert!(!q.contains("platformFeeBps"), "query: {q}");
    }

    #[test]
    fn nonzero_fee_without_account_is_rejected() {
        let http = CannedClient::new(serde_json::json!({}), serde_json::json!({}));
        // `JupiterSwapProvider` isn't `Debug`, so match the result rather than
        // `unwrap_err()`.
        match JupiterSwapProvider::new(http, RecordingSubmitter::default(), 50, 30, None) {
            Err(RelayerError::SwapFailed(_)) => {}
            Err(other) => panic!("expected SwapFailed, got {other:?}"),
            Ok(_) => panic!("expected construction to fail"),
        }
    }

    // --- Full swap flow over the seams (no network) --------------------

    #[tokio::test]
    async fn swap_quotes_executes_and_returns_out_amount() {
        let quote = serde_json::json!({
            "outAmount": "987654",
            "routePlan": [ { "percent": 100 } ]
        });
        let http = CannedClient::new(quote, sample_swap_tx_json());
        let submitter = RecordingSubmitter::default();
        let provider = JupiterSwapProvider::new(
            http,
            submitter,
            50,
            25,
            Some("FeeAcct11111111111111111111111111111111111".into()),
        )
        .unwrap();

        let ephemeral = Keypair::new();
        let out = provider
            .swap(NATIVE_SOL_ASSET, [0x11u8; 32], 1_000_000, &ephemeral)
            .await
            .expect("swap executes over canned seams");
        assert_eq!(out.out_amount, 987_654);

        // The swap body was built for the fresh address and routed the fee.
        let body = provider.http.seen_body.lock().unwrap().clone().unwrap();
        assert_eq!(body["userPublicKey"], ephemeral.pubkey().to_string());
        assert!(body["feeAccount"].is_string());
        // The submitter signed with the fresh ephemeral keypair.
        assert_eq!(
            provider.submitter.signed_pubkey.lock().unwrap().clone(),
            Some(ephemeral.pubkey().to_string())
        );
    }

    #[tokio::test]
    async fn native_output_reshields_realized_balance_not_the_quote() {
        // Quote says 1_000_000 lamports out, but the ephemeral actually holds
        // 995_000 (slippage). The relayer must re-shield the realized balance
        // minus the deposit reserve, never the stale quote — which would exceed
        // the balance and strand the funds on a failed re-deposit.
        struct BalanceSubmitter {
            lamports: u64,
        }
        #[async_trait::async_trait]
        impl SwapSubmitter for BalanceSubmitter {
            async fn sign_and_submit(
                &self,
                _t: VersionedTransaction,
                _s: &Keypair,
            ) -> Result<String> {
                Ok("sig".into())
            }
            async fn realized_native(&self, _owner: &Pubkey) -> Result<Option<u64>> {
                Ok(Some(self.lamports))
            }
        }

        let quote = serde_json::json!({
            "outAmount": "1000000",
            "routePlan": [ { "percent": 100 } ]
        });
        let http = CannedClient::new(quote, sample_swap_tx_json());
        let provider =
            JupiterSwapProvider::new(http, BalanceSubmitter { lamports: 995_000 }, 50, 0, None)
                .unwrap();

        // SPL input, native-SOL output.
        let out = provider
            .swap([0x33u8; 32], NATIVE_SOL_ASSET, 1_000_000, &Keypair::new())
            .await
            .expect("swap executes");
        assert_eq!(out.out_amount, 995_000 - NATIVE_DEPOSIT_RESERVE_LAMPORTS);
    }

    #[tokio::test]
    async fn no_route_quote_surfaces_no_route_error_without_submitting() {
        let quote = serde_json::json!({ "outAmount": "0", "routePlan": [] });
        let http = CannedClient::new(quote, serde_json::json!({}));
        let provider =
            JupiterSwapProvider::new(http, RecordingSubmitter::default(), 50, 0, None).unwrap();
        let err = provider
            .swap(NATIVE_SOL_ASSET, [0x22u8; 32], 5_000, &Keypair::new())
            .await
            .unwrap_err();
        assert!(matches!(err, RelayerError::NoRoute(_)));
        // No swap body was ever posted — we bailed at the quote.
        assert!(provider.http.seen_body.lock().unwrap().is_none());
        assert!(provider.submitter.signed_pubkey.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn zero_amount_is_rejected_before_any_request() {
        let http = CannedClient::new(serde_json::json!({}), serde_json::json!({}));
        let provider =
            JupiterSwapProvider::new(http, RecordingSubmitter::default(), 50, 0, None).unwrap();
        let err = provider
            .swap(NATIVE_SOL_ASSET, [0x22u8; 32], 0, &Keypair::new())
            .await
            .unwrap_err();
        assert!(matches!(err, RelayerError::InvalidAmount(0)));
        assert!(provider.http.seen_query.lock().unwrap().is_none());
    }
}
