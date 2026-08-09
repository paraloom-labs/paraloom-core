//! Off-chain relayer orchestration (#238).
//!
//! The relayer composes the existing shielded-pool primitives into
//! higher-level flows that no single on-chain instruction expresses. The
//! first such flow is the **private swap** ([`private_swap`]): spend a
//! shielded note, surface the funds at an unlinkable fresh address, swap
//! there on public liquidity, and re-shield the result.
//!
//! Everything here is pure orchestration. It changes no circuit and no
//! on-chain program; it only sequences withdraw -> swap -> deposit using
//! instruction builders and traits that already exist (or are stubbed for a
//! follow-up issue).

pub mod jupiter;
pub mod onchain;
pub mod private_swap;
pub mod swap_router;
pub mod transact_submit;

pub use jupiter::{
    asset_to_mint, mint_to_asset, JupiterHttpClient, JupiterSwapProvider, ReqwestJupiterClient,
    RpcSwapSubmitter, SwapQuote, SwapSubmitter, DEFAULT_JUPITER_BASE_URL, WRAPPED_SOL_MINT,
};
pub use onchain::OnChainSubmitter;
pub use private_swap::{
    MockSubmitter, MockSwapProvider, PrivateSwapRelayer, PrivateSwapRequest, PrivateSwapResult,
    RelayerError, SubmittedLeg, Submitter, SwapOutResult, SwapProvider, SwapResult, WithdrawLeg,
};
pub use swap_router::SwapQuoter;
