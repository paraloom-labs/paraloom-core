//! Transact-verification ingress (#350).
//!
//! The v3 unified-transact twin of [`crate::node::transfer_ingress`]. A small
//! HTTP endpoint that lets a client (the wallet / CLI) hand a 2-in/2-out
//! transact — a pure shielded transfer (`ext_amount == 0`) or a withdrawal
//! (`ext_amount < 0`) — to a running validator, which broadcasts it into the
//! consensus mesh via `initiate_transact_verification`. Validators verify the
//! `TransactCircuitV3` proof, reach a BFT quorum, and the gathering node
//! settles the `transact` instruction on-chain.
//!
//! Like the transfer ingress this *triggers consensus*, so it is a write
//! surface: it defaults to disabled (empty `bridge.transact_ingress_address`)
//! and should stay on a loopback / management interface when enabled.
//!
//! ## Endpoint
//! - `POST /transact/submit` — JSON body
//!   `{ "recipient": hex32, "nullifiers": [hex32, hex32],
//!      "output_commitments": [hex32, hex32], "root": hex32,
//!      "ext_amount": i64, "proof": hex, "ciphertexts": [hex, hex] }`.
//!   Returns `200 { "request_id": "..." }` once accepted into the mesh,
//!   `400` on malformed input (including `ext_amount > 0` — deposits go
//!   through `deposit_note`, never this ingress), or `503` if the node cannot
//!   start verification (e.g. no validator quorum is registered yet).

use async_trait::async_trait;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::consensus::transact::TransactVerificationRequest;
use crate::node::ingress_auth::{check_bearer, IngressToken};

/// A delivered encrypted output note (#196): the output commitment and the
/// opaque hex ciphertext (`EncryptedNote`) a recipient trial-decrypts. (Moved
/// here from the retired `transfer_ingress` module.)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveredNote {
    pub output_commitment: String,
    pub ciphertext: String,
}

/// The capabilities the ingress needs: hand a transact to the consensus mesh,
/// and serve the encrypted notes delivered so far for recipients to scan.
/// Abstracted behind a trait so the router can be unit-tested with a stub.
#[async_trait]
pub trait TransactIngress: Send + Sync {
    async fn submit_transact(&self, request: TransactVerificationRequest)
        -> anyhow::Result<String>;

    /// All encrypted notes this node has seen, for recipient scanning (#196).
    async fn delivered_notes(&self) -> Vec<DeliveredNote>;
}

#[async_trait]
impl TransactIngress for crate::node::Node {
    async fn submit_transact(
        &self,
        request: TransactVerificationRequest,
    ) -> anyhow::Result<String> {
        self.initiate_transact_verification(request).await
    }

    async fn delivered_notes(&self) -> Vec<DeliveredNote> {
        self.delivered_transfer_notes().await
    }
}

#[derive(Deserialize)]
struct SubmitRequest {
    recipient: String,
    nullifiers: Vec<String>,
    output_commitments: Vec<String>,
    root: String,
    ext_amount: i64,
    proof: String,
    ciphertexts: Vec<String>,
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
    Extension(node): Extension<Arc<dyn TransactIngress>>,
    Extension(token): Extension<IngressToken>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
    // This endpoint triggers consensus; reject an unauthenticated caller when a
    // token is configured, before doing any work.
    check_bearer(&headers, &token)?;

    // Deposits (`ext_amount > 0`) go through `deposit_note`, never this
    // ingress; the on-chain program rejects them anyway, so fail fast at the
    // door instead of burning a consensus round on a doomed request.
    if req.ext_amount > 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "ext_amount must be <= 0 (deposits go through deposit_note)".to_string(),
        ));
    }

    let recipient = parse_hex32("recipient", &req.recipient)?;
    let nullifiers = parse_hex32_pair("nullifiers", &req.nullifiers)?;
    let output_commitments = parse_hex32_pair("output_commitments", &req.output_commitments)?;
    let root = parse_hex32("root", &req.root)?;

    let proof_hex = req.proof.strip_prefix("0x").unwrap_or(&req.proof);
    let proof = hex::decode(proof_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("proof: invalid hex: {e}")))?;
    if proof.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proof must not be empty".to_string(),
        ));
    }

    // The ciphertexts are opaque to the node — validate only that there are
    // two non-empty hex blobs (the recipient decrypts them).
    if req.ciphertexts.len() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "ciphertexts must have exactly 2 entries".to_string(),
        ));
    }
    for (i, c) in req.ciphertexts.iter().enumerate() {
        let trimmed = c.strip_prefix("0x").unwrap_or(c);
        if hex::decode(trimmed).map(|b| b.is_empty()).unwrap_or(true) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("ciphertexts[{i}] must be non-empty hex"),
            ));
        }
    }
    let ciphertexts = [req.ciphertexts[0].clone(), req.ciphertexts[1].clone()];

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // The id is the canonical digest of the settlement-bound fields (#383), so
    // it cannot be chosen to collide two distinct transacts or poison a cache
    // entry, and an exact replay is idempotent. Set after the struct is built.
    let mut request = TransactVerificationRequest {
        request_id: String::new(),
        recipient,
        nullifiers,
        output_commitments,
        root,
        ext_amount: req.ext_amount,
        proof,
        ciphertexts,
        timestamp,
    };
    request.request_id = request.canonical_id();

    let id = node
        .submit_transact(request)
        .await
        // Almost always "not enough validators registered yet" — a transient
        // readiness problem, not a bad request.
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    Ok(Json(SubmitResponse { request_id: id }))
}

/// `GET /transact/scan` (#196) — every encrypted note this node has seen. A
/// recipient polls it and trial-decrypts each ciphertext with its viewing key,
/// keeping the ones that decrypt. Failed decrypts are silent.
async fn scan_handler(
    Extension(node): Extension<Arc<dyn TransactIngress>>,
) -> Json<Vec<DeliveredNote>> {
    Json(node.delivered_notes().await)
}

/// Build the ingress router. Exposed separately from [`serve`] so it can be
/// mounted under a caller's own listener or driven directly in tests.
pub fn router(node: Arc<dyn TransactIngress>, token: IngressToken) -> Router {
    Router::new()
        .route("/transact/submit", post(submit_handler))
        .route("/transact/scan", get(scan_handler))
        .layer(Extension(node))
        .layer(Extension(token))
}

/// Bind the ingress server on `addr` and serve until the task is dropped.
/// `token` gates the write endpoint when configured (see
/// [`crate::node::ingress_auth`]).
pub async fn serve(
    node: Arc<dyn TransactIngress>,
    addr: SocketAddr,
    token: IngressToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        target: "paraloom::node::transact_ingress",
        "Transact ingress listening on http://{}",
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
    impl TransactIngress for StubIngress {
        async fn submit_transact(
            &self,
            request: TransactVerificationRequest,
        ) -> anyhow::Result<String> {
            if self.accept {
                Ok(request.request_id)
            } else {
                anyhow::bail!("insufficient validators for consensus")
            }
        }

        async fn delivered_notes(&self) -> Vec<DeliveredNote> {
            vec![]
        }
    }

    /// Stub that records the forwarded request, so a test can assert the
    /// handler maps the JSON body onto `TransactVerificationRequest` fields.
    struct CaptureStub {
        seen: tokio::sync::Mutex<Option<TransactVerificationRequest>>,
    }

    #[async_trait]
    impl TransactIngress for CaptureStub {
        async fn submit_transact(
            &self,
            request: TransactVerificationRequest,
        ) -> anyhow::Result<String> {
            let id = request.request_id.clone();
            *self.seen.lock().await = Some(request);
            Ok(id)
        }

        async fn delivered_notes(&self) -> Vec<DeliveredNote> {
            vec![]
        }
    }

    fn post_json(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/transact/submit")
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    fn body_with_ext_amount(ext_amount: i64) -> String {
        format!(
            r#"{{"recipient":"{}","nullifiers":["{}","{}"],"output_commitments":["{}","{}"],"root":"{}","ext_amount":{},"proof":"{}","ciphertexts":["{}","{}"]}}"#,
            "66".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            ext_amount,
            "01".repeat(192),
            "ab".repeat(88),
            "cd".repeat(88)
        )
    }

    fn well_formed_body() -> String {
        body_with_ext_amount(0)
    }

    #[tokio::test]
    async fn well_formed_request_is_accepted_and_forwarded() {
        let stub = Arc::new(CaptureStub {
            seen: tokio::sync::Mutex::new(None),
        });
        let app = router(stub.clone(), None);
        let resp = app.oneshot(post_json(&well_formed_body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The response echoes the derived request id...
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let id = parsed["request_id"].as_str().unwrap();
        assert!(id.starts_with("transact-"));
        assert!(id.ends_with(&"11".repeat(32)));

        // ...and the decoded request landed on the initiator intact.
        let seen = stub.seen.lock().await.clone().expect("request forwarded");
        assert_eq!(seen.recipient, [0x66u8; 32]);
        assert_eq!(seen.nullifiers, [[0x11u8; 32], [0x22u8; 32]]);
        assert_eq!(seen.output_commitments, [[0x33u8; 32], [0x44u8; 32]]);
        assert_eq!(seen.root, [0x55u8; 32]);
        assert_eq!(seen.ext_amount, 0);
        assert_eq!(seen.proof, vec![0x01u8; 192]);
    }

    #[tokio::test]
    async fn withdrawal_ext_amount_is_accepted() {
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let resp = app
            .oneshot(post_json(&body_with_ext_amount(-1_000_000)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn positive_ext_amount_is_400() {
        // Deposits never enter through this ingress: `ext_amount > 0` is
        // rejected at the door before any consensus work.
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let resp = app
            .oneshot(post_json(&body_with_ext_amount(1)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn wrong_nullifier_count_is_400() {
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let body = format!(
            r#"{{"recipient":"{}","nullifiers":["{}"],"output_commitments":["{}","{}"],"root":"{}","ext_amount":0,"proof":"{}","ciphertexts":["{}","{}"]}}"#,
            "66".repeat(32),
            "11".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "01".repeat(192),
            "ab".repeat(88),
            "cd".repeat(88)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn empty_proof_is_400() {
        let app = router(Arc::new(StubIngress { accept: true }), None);
        let body = format!(
            r#"{{"recipient":"{}","nullifiers":["{}","{}"],"output_commitments":["{}","{}"],"root":"{}","ext_amount":0,"proof":"","ciphertexts":["{}","{}"]}}"#,
            "66".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "ab".repeat(88),
            "cd".repeat(88)
        );
        let resp = app.oneshot(post_json(&body)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn node_rejection_is_503() {
        let app = router(Arc::new(StubIngress { accept: false }), None);
        let resp = app.oneshot(post_json(&well_formed_body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn configured_token_gates_submit_but_not_scan() {
        let token = crate::node::ingress_auth::token_from_config("s3cret");

        // Submit without a bearer token → 401, never reaching the node.
        let app = router(Arc::new(StubIngress { accept: true }), token.clone());
        let resp = app.oneshot(post_json(&well_formed_body())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Submit with the correct bearer token → handled normally (200).
        let app = router(Arc::new(StubIngress { accept: true }), token.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/transact/submit")
            .header("content-type", "application/json")
            .header("authorization", "Bearer s3cret")
            .body(Body::from(well_formed_body()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The read-only scan route is not a consensus write surface, so the
        // token does not gate it: an unauthenticated GET still succeeds.
        let app = router(Arc::new(ScanStub), token);
        let req = Request::builder()
            .method("GET")
            .uri("/transact/scan")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Stub that serves a fixed delivered note, to exercise the scan route.
    struct ScanStub;
    #[async_trait]
    impl TransactIngress for ScanStub {
        async fn submit_transact(&self, _: TransactVerificationRequest) -> anyhow::Result<String> {
            anyhow::bail!("not used")
        }
        async fn delivered_notes(&self) -> Vec<DeliveredNote> {
            vec![DeliveredNote {
                output_commitment: "33".repeat(32),
                ciphertext: "ab".repeat(88),
            }]
        }
    }

    #[tokio::test]
    async fn scan_returns_delivered_notes() {
        let app = router(Arc::new(ScanStub), None);
        let req = Request::builder()
            .method("GET")
            .uri("/transact/scan")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let notes: Vec<DeliveredNote> = serde_json::from_slice(&body).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].output_commitment, "33".repeat(32));
    }
}
