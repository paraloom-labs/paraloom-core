//! Transfer-verification ingress (#194).
//!
//! The transfer twin of [`crate::node::withdrawal_ingress`]. A small HTTP
//! endpoint that lets a client (the wallet / CLI) hand a shielded → shielded
//! transfer to a running validator, which broadcasts it into the consensus
//! mesh via `initiate_transfer_verification`. Validators verify the
//! `TransferCircuit` proof, reach a BFT quorum, and the gathering node settles
//! the `shielded_transfer` instruction on-chain.
//!
//! Like the withdrawal ingress this *triggers consensus*, so it is a write
//! surface: it defaults to disabled (empty `bridge.transfer_ingress_address`)
//! and should stay on a loopback / management interface when enabled.
//!
//! ## Endpoint
//! - `POST /transfer/submit` — JSON body
//!   `{ "nullifiers": [hex32, hex32], "output_commitments": [hex32, hex32],
//!      "new_merkle_root": hex32, "proof": hex }`.
//!   Returns `200 { "request_id": "..." }` once accepted into the mesh,
//!   `400` on malformed input, or `503` if the node cannot start verification
//!   (e.g. no validator quorum is registered yet).

use async_trait::async_trait;
use axum::{extract::Extension, http::StatusCode, response::Json, routing::post, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::consensus::TransferVerificationRequest;

/// The single capability the ingress needs: hand a transfer request to the
/// consensus mesh and return its request id. Abstracted behind a trait so the
/// router can be unit-tested with a stub instead of a networked `Node`.
#[async_trait]
pub trait TransferIngress: Send + Sync {
    async fn submit_transfer(&self, request: TransferVerificationRequest)
        -> anyhow::Result<String>;
}

#[async_trait]
impl TransferIngress for crate::node::Node {
    async fn submit_transfer(
        &self,
        request: TransferVerificationRequest,
    ) -> anyhow::Result<String> {
        self.initiate_transfer_verification(request).await
    }
}

#[derive(Deserialize)]
struct SubmitRequest {
    nullifiers: Vec<String>,
    output_commitments: Vec<String>,
    new_merkle_root: String,
    proof: String,
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

/// Parse exactly two hex-32 elements into a `[[u8; 32]; 2]`, 400 otherwise.
fn parse_hex32_pair(label: &str, items: &[String]) -> Result<[[u8; 32]; 2], (StatusCode, String)> {
    if items.len() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label} must have exactly 2 entries"),
        ));
    }
    Ok([
        parse_hex32(label, &items[0])?,
        parse_hex32(label, &items[1])?,
    ])
}

async fn submit_handler(
    Extension(node): Extension<Arc<dyn TransferIngress>>,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    let nullifiers = parse_hex32_pair("nullifiers", &req.nullifiers)?;
    let output_commitments = parse_hex32_pair("output_commitments", &req.output_commitments)?;
    let new_merkle_root = parse_hex32("new_merkle_root", &req.new_merkle_root)?;

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
    let request_id = format!("transfer-{timestamp}-{}", hex::encode(&nullifiers[0][..8]));

    let request = TransferVerificationRequest {
        request_id,
        nullifiers,
        output_commitments,
        new_merkle_root,
        proof,
        timestamp,
    };

    let id = node
        .submit_transfer(request)
        .await
        // Almost always "not enough validators registered yet" — a transient
        // readiness problem, not a bad request.
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    Ok(Json(SubmitResponse { request_id: id }))
}

/// Build the ingress router. Exposed separately from [`serve`] so it can be
/// mounted under a caller's own listener or driven directly in tests.
pub fn router(node: Arc<dyn TransferIngress>) -> Router {
    Router::new()
        .route("/transfer/submit", post(submit_handler))
        .layer(Extension(node))
}

/// Bind the ingress server on `addr` and serve until the task is dropped.
pub async fn serve(
    node: Arc<dyn TransferIngress>,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        target: "paraloom::node::transfer_ingress",
        "Transfer ingress listening on http://{}",
        addr
    );
    axum::Server::bind(&addr)
        .serve(router(node).into_make_service())
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
    impl TransferIngress for StubIngress {
        async fn submit_transfer(
            &self,
            request: TransferVerificationRequest,
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
            .uri("/transfer/submit")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    fn well_formed_body() -> String {
        format!(
            r#"{{"nullifiers":["{}","{}"],"output_commitments":["{}","{}"],"new_merkle_root":"{}","proof":"{}"}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "01".repeat(192)
        )
    }

    #[tokio::test]
    async fn well_formed_request_is_accepted() {
        let app = router(Arc::new(StubIngress { accept: true }));
        let resp = app.oneshot(post_json(&well_formed_body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_nullifier_count_is_400() {
        let app = router(Arc::new(StubIngress { accept: true }));
        let body = format!(
            r#"{{"nullifiers":["{}"],"output_commitments":["{}","{}"],"new_merkle_root":"{}","proof":"{}"}}"#,
            "11".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "01".repeat(192)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_proof_is_400() {
        let app = router(Arc::new(StubIngress { accept: true }));
        let body = format!(
            r#"{{"nullifiers":["{}","{}"],"output_commitments":["{}","{}"],"new_merkle_root":"{}","proof":""}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_rejection_is_503() {
        let app = router(Arc::new(StubIngress { accept: false }));
        let resp = app.oneshot(post_json(&well_formed_body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
