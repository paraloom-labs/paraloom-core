//! Withdrawal-verification ingress (#184).
//!
//! A small HTTP endpoint that lets a client (the wallet / CLI) hand a
//! withdrawal request to a *running* validator, which then broadcasts it into
//! the consensus mesh via `initiate_withdrawal_verification`. Without this a
//! client can only settle a withdrawal through the bridge authority directly
//! (the `paraloom wallet withdraw` / `test-withdraw` path); this is the entry
//! point for the decentralised flow where the validator network verifies the
//! proof and a quorum approves before the leader settles on-chain.
//!
//! Unlike the read-only Merkle path server (#163), this endpoint *triggers
//! consensus*, so it is a write surface: it defaults to disabled (empty
//! `bridge.withdrawal_ingress_address`) and should stay on a loopback /
//! management interface when enabled.
//!
//! ## Endpoint
//! - `POST /withdrawal/submit` — JSON body
//!   `{ "nullifier": hex32, "recipient": hex32, "proof": hex, "amount": u64, "fee": u64 }`.
//!   Returns `200 { "request_id": "..." }` once the request is accepted into
//!   the mesh, `400` on malformed input, or `503` if the node cannot start
//!   verification (e.g. no validator quorum is registered yet).

use async_trait::async_trait;
use axum::{extract::Extension, http::StatusCode, response::Json, routing::post, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::consensus::WithdrawalVerificationRequest;
use crate::node::ingress_auth::{check_bearer, IngressToken};

/// The single capability the ingress needs from a node: hand a withdrawal
/// request to the consensus mesh and return its request id. Abstracted behind
/// a trait so the router can be unit-tested with a stub instead of a fully
/// constructed, networked `Node`.
#[async_trait]
pub trait WithdrawalIngress: Send + Sync {
    async fn submit_withdrawal(
        &self,
        request: WithdrawalVerificationRequest,
    ) -> anyhow::Result<String>;
}

#[async_trait]
impl WithdrawalIngress for crate::node::Node {
    async fn submit_withdrawal(
        &self,
        request: WithdrawalVerificationRequest,
    ) -> anyhow::Result<String> {
        self.initiate_withdrawal_verification(request).await
    }
}

#[derive(Deserialize)]
struct SubmitRequest {
    nullifier: String,
    recipient: String,
    proof: String,
    amount: u64,
    #[serde(default)]
    fee: u64,
    /// The Merkle root (hex32) the wallet built its proof against — the root the
    /// path server served for the spent note. Optional for wire-compatibility;
    /// when absent the initiating node fills its own current root, which keeps
    /// the single-anchor flow working but cannot cross-verify on a divergent
    /// validator. Wallets should send it.
    #[serde(default)]
    merkle_root: Option<String>,
}

#[derive(Serialize)]
struct SubmitResponse {
    request_id: String,
}

/// Parse a 32-byte field from hex, tolerating a `0x` prefix; 400 on any
/// malformed input.
fn parse_hex32(label: &str, s: &str) -> Result<[u8; 32], (StatusCode, String)> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("{label}: invalid hex: {e}"),
        )
    })?;
    bytes
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("{label} must be 32 bytes")))
}

async fn submit_handler(
    Extension(node): Extension<Arc<dyn WithdrawalIngress>>,
    Extension(token): Extension<IngressToken>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    // This endpoint triggers consensus; reject an unauthenticated caller when a
    // token is configured, before doing any work.
    check_bearer(&headers, &token)?;

    let nullifier = parse_hex32("nullifier", &req.nullifier)?;
    let recipient = parse_hex32("recipient", &req.recipient)?;

    let proof_hex = req.proof.strip_prefix("0x").unwrap_or(&req.proof);
    let proof = hex::decode(proof_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("proof: invalid hex: {e}")))?;
    if proof.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proof must not be empty".to_string(),
        ));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Derive the request id from the FULL nullifier, not an 8-byte prefix
    // (audit #17): two distinct withdrawals submitted in the same second whose
    // nullifiers share a prefix would otherwise collide onto one request id and
    // clobber each other's verification round. The nullifier is unique per
    // spend, so the full 32 bytes make the id collision-free.
    let request_id = format!("ingress-{timestamp}-{}", hex::encode(nullifier));

    let prover_root = match req.merkle_root.as_deref() {
        Some(s) => parse_hex32("merkle_root", s)?,
        None => [0u8; 32],
    };

    let request = WithdrawalVerificationRequest {
        request_id,
        nullifier,
        amount: req.amount,
        recipient,
        proof,
        fee: req.fee,
        timestamp,
        prover_root,
    };

    let id = node
        .submit_withdrawal(request)
        .await
        // A failure here is almost always "not enough validators registered
        // yet" — a transient readiness problem, not a bad request.
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    Ok(Json(SubmitResponse { request_id: id }))
}

/// Build the ingress router. Exposed separately from [`serve`] so it can be
/// mounted under a caller's own listener or driven directly in tests.
pub fn router(node: Arc<dyn WithdrawalIngress>, token: IngressToken) -> Router {
    Router::new()
        .route("/withdrawal/submit", post(submit_handler))
        .layer(Extension(node))
        .layer(Extension(token))
}

/// Bind the ingress server on `addr` and serve until the task is
/// dropped/aborted. `token` gates the endpoint when configured (see
/// [`crate::node::ingress_auth`]).
pub async fn serve(
    node: Arc<dyn WithdrawalIngress>,
    addr: SocketAddr,
    token: IngressToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        target: "paraloom::node::withdrawal_ingress",
        "Withdrawal ingress listening on http://{}",
        addr
    );
    axum::Server::bind(&addr)
        .serve(router(node, token).into_make_service())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for oneshot

    /// Stub that accepts or rejects without any network, so the router's
    /// parsing and status mapping can be tested in isolation.
    struct StubIngress {
        accept: bool,
    }

    #[async_trait]
    impl WithdrawalIngress for StubIngress {
        async fn submit_withdrawal(
            &self,
            request: WithdrawalVerificationRequest,
        ) -> anyhow::Result<String> {
            if self.accept {
                Ok(request.request_id)
            } else {
                anyhow::bail!("insufficient validators for consensus")
            }
        }
    }

    fn post_json(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/withdrawal/submit")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn well_formed_request_is_accepted() {
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let body = format!(
            r#"{{"nullifier":"{}","recipient":"{}","proof":"{}","amount":1000000,"fee":0}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "01".repeat(192)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn malformed_nullifier_is_400() {
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let body = format!(
            r#"{{"nullifier":"nothex","recipient":"{}","proof":"{}","amount":1,"fee":0}}"#,
            "22".repeat(32),
            "01".repeat(192)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_proof_is_400() {
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let body = format!(
            r#"{{"nullifier":"{}","recipient":"{}","proof":"","amount":1,"fee":0}}"#,
            "11".repeat(32),
            "22".repeat(32)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_rejection_is_503() {
        let app = router(Arc::new(StubIngress { accept: false }), None);
        let body = format!(
            r#"{{"nullifier":"{}","recipient":"{}","proof":"{}","amount":1,"fee":0}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "01".repeat(192)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn configured_token_rejects_unauthenticated_and_accepts_authenticated() {
        let token = crate::node::ingress_auth::token_from_config("s3cret");
        let body = format!(
            r#"{{"nullifier":"{}","recipient":"{}","proof":"{}","amount":1000000,"fee":0}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "01".repeat(192)
        );

        // No bearer token → 401, and the request never reaches the node.
        let app = router(Arc::new(StubIngress { accept: true }), token.clone());
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct bearer token → handled normally (200).
        let app = router(Arc::new(StubIngress { accept: true }), token);
        let req = Request::builder()
            .method("POST")
            .uri("/withdrawal/submit")
            .header("content-type", "application/json")
            .header("authorization", "Bearer s3cret")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
