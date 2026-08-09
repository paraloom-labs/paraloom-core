//! Non-custodial private-swap routing service (#239).
//!
//! A thin HTTP endpoint the app calls to route the public leg of a private
//! swap. It builds a Jupiter swap transaction for a **caller-supplied fresh
//! address** and hands it back **unsigned** — the service holds no keys and
//! never signs or submits anything. The client (which generated the fresh key
//! and already funded it by withdrawing its shielded note there) signs the
//! returned transaction and submits it itself.
//!
//! That is the honest trust posture for a privacy relayer: a service that could
//! sign is a service that could steal. Because the withdraw-to-fresh leg funds
//! the fresh address, the swap pays its own gas from that balance, so the client
//! never needs the service to hold a key. The service's role is Jupiter routing
//! (via the hardened [`crate::relayer::jupiter`] client) plus, when configured,
//! routing the protocol's `platformFeeBps` to a Paraloom fee account — a public
//! pubkey, not a secret.
//!
//! ## Endpoints
//! - `POST /swap/route` — JSON body
//!   `{ "input_mint": str, "output_mint": str, "amount": u64,
//!      "user_public_key": base58 }`. `input_mint`/`output_mint` accept a base58
//!   mint or the literal `"SOL"` (wrapped SOL). `user_public_key` is the fresh
//!   address that will sign. Returns `200 { "out_amount": u64,
//!   "swap_transaction": base64 }` (unsigned versioned tx), `400` on malformed
//!   input, `422` when Jupiter finds no route, or `502` on an upstream failure.
//! - `GET /swap/health` — `200 "ok"`.

use async_trait::async_trait;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::privacy::types::AssetId;
use crate::relayer::jupiter::{mint_to_asset, JupiterHttpClient, SwapQuote, SwapSubmitter};
use crate::relayer::{JupiterSwapProvider, RelayerError};

/// Builds an unsigned swap for a fresh address. Abstracted behind a trait so the
/// router can be unit-tested with a stub instead of a live Jupiter client.
#[async_trait]
pub trait SwapQuoter: Send + Sync {
    /// Route `amount` of `asset_in` -> `asset_out` for `user` and return the
    /// unsigned swap transaction plus the quoted output.
    async fn quote_swap(
        &self,
        asset_in: AssetId,
        asset_out: AssetId,
        amount: u64,
        user: &Pubkey,
    ) -> Result<SwapQuote, RelayerError>;
}

#[async_trait]
impl<H: JupiterHttpClient, S: SwapSubmitter> SwapQuoter for JupiterSwapProvider<H, S> {
    async fn quote_swap(
        &self,
        asset_in: AssetId,
        asset_out: AssetId,
        amount: u64,
        user: &Pubkey,
    ) -> Result<SwapQuote, RelayerError> {
        self.build_swap(asset_in, asset_out, amount, user).await
    }
}

#[derive(Deserialize)]
struct RouteRequest {
    input_mint: String,
    output_mint: String,
    amount: u64,
    user_public_key: String,
}

#[derive(Serialize)]
struct RouteResponse {
    out_amount: u64,
    swap_transaction: String,
}

async fn route_handler(
    Extension(quoter): Extension<Arc<dyn SwapQuoter>>,
    Json(req): Json<RouteRequest>,
) -> Result<Json<RouteResponse>, (StatusCode, String)> {
    let asset_in = mint_to_asset(&req.input_mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("input_mint: {e}")))?;
    let asset_out = mint_to_asset(&req.output_mint)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("output_mint: {e}")))?;
    let user = Pubkey::from_str(&req.user_public_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("user_public_key: {e}")))?;
    if req.amount == 0 {
        return Err((StatusCode::BAD_REQUEST, "amount must be > 0".to_string()));
    }

    match quoter
        .quote_swap(asset_in, asset_out, req.amount, &user)
        .await
    {
        Ok(quote) => Ok(Json(RouteResponse {
            out_amount: quote.out_amount,
            swap_transaction: quote.swap_transaction,
        })),
        // A well-formed request that simply has no liquidity path: the input is
        // fine, so 422 rather than 400 or a 5xx.
        Err(RelayerError::NoRoute(m)) => {
            Err((StatusCode::UNPROCESSABLE_ENTITY, format!("no route: {m}")))
        }
        Err(RelayerError::InvalidAmount(a)) => {
            Err((StatusCode::BAD_REQUEST, format!("invalid amount: {a}")))
        }
        // Transport / upstream Jupiter failure — the request was valid, the
        // aggregator failed, so surface it as a bad gateway.
        Err(e) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
    }
}

/// Build the routing router. Exposed separately from [`serve`] so it can be
/// mounted under a caller's own listener or driven directly in tests.
///
/// CORS is permissive: the endpoint is public, read-only, and carries no
/// credentials or cookies, so any origin (the app, a wallet, a script) may call
/// it. There is nothing to protect with a same-origin policy.
pub fn router(quoter: Arc<dyn SwapQuoter>) -> Router {
    Router::new()
        .route("/swap/route", post(route_handler))
        .route("/swap/health", get(|| async { "ok" }))
        .layer(Extension(quoter))
        .layer(CorsLayer::permissive())
}

/// Bind the routing server on `addr` and serve until the task is dropped.
pub async fn serve(
    quoter: Arc<dyn SwapQuoter>,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        target: "paraloom::relayer::swap_router",
        "Swap routing service listening on http://{addr}"
    );
    axum::Server::bind(&addr)
        .serve(router(quoter).into_make_service())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for oneshot

    /// Stub quoter: returns a canned unsigned tx, or a chosen error, without any
    /// network — so the router's parsing and status mapping test in isolation.
    struct StubQuoter {
        outcome: Result<SwapQuote, RelayerError>,
    }

    #[async_trait]
    impl SwapQuoter for StubQuoter {
        async fn quote_swap(
            &self,
            _asset_in: AssetId,
            _asset_out: AssetId,
            _amount: u64,
            _user: &Pubkey,
        ) -> Result<SwapQuote, RelayerError> {
            self.outcome
                .as_ref()
                .map(|q| q.clone())
                .map_err(|e| match e {
                    RelayerError::NoRoute(m) => RelayerError::NoRoute(m.clone()),
                    other => RelayerError::SwapFailed(other.to_string()),
                })
        }
    }

    fn app(outcome: Result<SwapQuote, RelayerError>) -> Router {
        router(Arc::new(StubQuoter { outcome }))
    }

    fn body(json: serde_json::Value) -> Body {
        Body::from(serde_json::to_vec(&json).unwrap())
    }

    async fn post_route(app: Router, json: serde_json::Value) -> (StatusCode, String) {
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/swap/route")
                    .header("content-type", "application/json")
                    .body(body(json))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn valid_body() -> serde_json::Value {
        serde_json::json!({
            "input_mint": "SOL",
            "output_mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "amount": 50_000_000u64,
            "user_public_key": Pubkey::new_unique().to_string(),
        })
    }

    #[tokio::test]
    async fn route_returns_the_unsigned_tx_on_success() {
        let quote = SwapQuote {
            out_amount: 987_654,
            swap_transaction: "BASE64TX".to_string(),
        };
        let (status, body) = post_route(app(Ok(quote)), valid_body()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("987654"));
        assert!(body.contains("BASE64TX"));
    }

    #[tokio::test]
    async fn no_route_maps_to_422() {
        let (status, body) = post_route(
            app(Err(RelayerError::NoRoute("dry pair".into()))),
            valid_body(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("no route"));
    }

    #[tokio::test]
    async fn upstream_failure_maps_to_502() {
        let (status, _) = post_route(
            app(Err(RelayerError::HttpError("jupiter down".into()))),
            valid_body(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn zero_amount_is_400_and_never_hits_the_quoter() {
        let mut b = valid_body();
        b["amount"] = serde_json::json!(0u64);
        // The quoter would panic if called, proving the guard short-circuits.
        let (status, _) = post_route(
            app(Ok(SwapQuote {
                out_amount: 1,
                swap_transaction: "x".into(),
            })),
            b,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn bad_mint_is_400() {
        let mut b = valid_body();
        b["output_mint"] = serde_json::json!("not-base58-!!!");
        let (status, body) = post_route(
            app(Ok(SwapQuote {
                out_amount: 1,
                swap_transaction: "x".into(),
            })),
            b,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("output_mint"));
    }

    #[tokio::test]
    async fn bad_user_pubkey_is_400() {
        let mut b = valid_body();
        b["user_public_key"] = serde_json::json!("nope");
        let (status, body) = post_route(
            app(Ok(SwapQuote {
                out_amount: 1,
                swap_transaction: "x".into(),
            })),
            b,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("user_public_key"));
    }

    #[tokio::test]
    async fn health_is_ok() {
        let resp = app(Ok(SwapQuote {
            out_amount: 1,
            swap_transaction: "x".into(),
        }))
        .oneshot(
            Request::builder()
                .uri("/swap/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
