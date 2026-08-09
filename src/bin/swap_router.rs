//! Non-custodial private-swap routing service (#239).
//!
//! Serves [`paraloom::relayer::swap_router`]: `POST /swap/route` builds an
//! unsigned Jupiter swap transaction for a caller-supplied fresh address. The
//! service holds NO keys — it never signs or submits. The client signs the
//! returned transaction with the fresh key it already funded via the shielded
//! withdraw leg.
//!
//! ```sh
//! SWAP_ROUTER_ADDR=0.0.0.0:8788 \
//! JUPITER_BASE_URL=https://lite-api.jup.ag/swap/v1 \
//! SLIPPAGE_BPS=50 \
//! # optional protocol fee (needs a Paraloom fee token account per out mint):
//! # PLATFORM_FEE_BPS=25 FEE_ACCOUNT=<pubkey> \
//! cargo run --release --bin swap-router
//! ```

use paraloom::relayer::{
    JupiterSwapProvider, ReqwestJupiterClient, RpcSwapSubmitter, SwapQuoter,
    DEFAULT_JUPITER_BASE_URL,
};
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let addr: SocketAddr = std::env::var("SWAP_ROUTER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8788".to_string())
        .parse()?;
    let jupiter_base_url =
        std::env::var("JUPITER_BASE_URL").unwrap_or_else(|_| DEFAULT_JUPITER_BASE_URL.to_string());
    let slippage_bps: u16 = std::env::var("SLIPPAGE_BPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let platform_fee_bps: u16 = std::env::var("PLATFORM_FEE_BPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let fee_account = std::env::var("FEE_ACCOUNT").ok();

    // The submitter is never invoked on the routing path (the service only
    // builds unsigned transactions), but the provider type needs one; give it a
    // real RPC-backed submitter pointed at a placeholder so the type checks. The
    // routing endpoints never call it.
    let submitter = RpcSwapSubmitter::new("http://unused.invalid");
    let provider = JupiterSwapProvider::new(
        ReqwestJupiterClient::new(jupiter_base_url.clone()),
        submitter,
        slippage_bps,
        platform_fee_bps,
        fee_account.clone(),
    )?;
    let quoter: Arc<dyn SwapQuoter> = Arc::new(provider);

    log::info!(
        target: "paraloom::bin::swap_router",
        "swap-router starting: jupiter={jupiter_base_url} slippage_bps={slippage_bps} \
         platform_fee_bps={platform_fee_bps} fee_account={}",
        fee_account.as_deref().unwrap_or("<none>")
    );

    paraloom::relayer::swap_router::serve(quoter, addr).await
}
