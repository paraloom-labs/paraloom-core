//! Merkle path query HTTP server (#163).
//!
//! A withdrawing client needs the Merkle authentication path for the
//! note it intends to spend, plus the current root, to build the public
//! inputs for its withdrawal proof. The node already indexes on-chain
//! deposits into a [`ShieldedPool`]; this module exposes that index over
//! a small read-only HTTP endpoint so clients — the `generate-withdrawal-proof`
//! CLI, the wallet — can fetch a path without joining the libp2p mesh.
//!
//! The data served is public (commitments are already on-chain), so the
//! endpoint is unauthenticated. It binds to a node-configured address;
//! operators should keep it on a loopback or management interface rather
//! than exposing it publicly.
//!
//! ## Endpoint
//!
//! - `GET /merkle/path/:commitment` — `:commitment` is the 32-byte
//!   commitment as hex (with or without a `0x` prefix). Returns 200 with
//!   `{ root, path, indices }` (all hex except the boolean direction
//!   indices), 400 if the hex is malformed, or 404 if the commitment is
//!   not in this node's pool.

use crate::privacy::pool::ShieldedPool;
use crate::privacy::types::Commitment;
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

/// Successful path-query response. Sibling hashes and the root are
/// hex-encoded; `indices[i]` is the direction of the `i`-th sibling
/// (false = sibling is the left child, true = right), matching
/// [`crate::privacy::types::MerklePath`].
#[derive(Serialize)]
struct PathResponse {
    root: String,
    path: Vec<String>,
    indices: Vec<bool>,
}

/// Parse a 32-byte commitment from a hex string, tolerating a `0x`
/// prefix. Returns a 400 response on any malformed input.
fn parse_commitment(hex_str: &str) -> Result<Commitment, (StatusCode, String)> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes =
        hex::decode(trimmed).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "commitment must be 32 bytes".to_string(),
        )
    })?;
    Ok(Commitment::from_bytes(arr))
}

async fn path_handler(
    Extension(pool): Extension<Arc<ShieldedPool>>,
    Path(commitment_hex): Path<String>,
) -> Result<Json<PathResponse>, (StatusCode, String)> {
    let commitment = parse_commitment(&commitment_hex)?;

    let path = pool
        .path(&commitment)
        .await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    let root = pool.root().await;

    Ok(Json(PathResponse {
        root: hex::encode(root),
        path: path.path.iter().map(hex::encode).collect(),
        indices: path.indices,
    }))
}

/// Build the path-query router over a shielded pool. Exposed separately
/// from [`serve`] so it can be mounted under a caller's own listener or
/// driven directly in tests.
pub fn router(pool: Arc<ShieldedPool>) -> Router {
    Router::new()
        .route("/merkle/path/:commitment", get(path_handler))
        .layer(Extension(pool))
}

/// Bind the path-query server on `addr` and serve until the task is
/// dropped/aborted.
pub async fn serve(
    pool: Arc<ShieldedPool>,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!(
        target: "paraloom::privacy::path_server",
        "Merkle path query server listening on http://{}",
        addr
    );
    axum::Server::bind(&addr)
        .serve(router(pool).into_make_service())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::{Note, ShieldedAddress};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for oneshot

    #[tokio::test]
    async fn returns_path_for_known_commitment() {
        let pool = Arc::new(ShieldedPool::new());
        let note = Note::new_native(ShieldedAddress([3u8; 32]), 100, [1u8; 32]);
        let commitment = pool.deposit(note, 100).await.unwrap();

        let app = router(pool);
        let uri = format!("/merkle/path/{}", commitment.to_hex());
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_commitment_is_404() {
        let pool = Arc::new(ShieldedPool::new());
        let app = router(pool);
        let uri = format!("/merkle/path/{}", "11".repeat(32));
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_hex_is_400() {
        let pool = Arc::new(ShieldedPool::new());
        let app = router(pool);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/merkle/path/nothex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
