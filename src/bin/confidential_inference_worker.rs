//! The enclave-side confidential-inference worker.
//!
//! Run inside a GCP Confidential Space enclave. On startup it generates a fresh
//! channel keypair, requests an attestation token from the TEE launcher with its
//! channel public key as the nonce, and serves two endpoints:
//!
//! - `GET  /attested-key` — the channel public key plus the attestation token
//!   vouching for it, so a client can verify (`GcpConfidentialSpaceVerifier`)
//!   before sealing anything.
//! - `POST /infer` — a sealed request (`EncryptedNote`); the worker opens it
//!   inside the enclave, runs the model, and returns the result sealed to the
//!   requester. The plaintext prompt and result never leave the enclave.
//!
//! The model is served by a local `llama-server` (see `GraniteModelRunner`).
//!
//! Env: `TEE_AUDIENCE` (default `paraloom-inference`), `LLAMA_ENDPOINT` (default
//! `http://127.0.0.1:8080`), `LISTEN_ADDR` (default `0.0.0.0:9000`), `MAX_TOKENS`
//! (default 256). `TEE_ATTESTATION_TOKEN` overrides the launcher fetch for local
//! development — the token still has to satisfy the client's verifier, so this
//! is a convenience seam, not a trust bypass.

use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use paraloom::compute::{
    AttestedChannelKey, ConfidentialWorker, EnclaveChannel, GraniteModelRunner,
};
use paraloom::privacy::EncryptedNote;
use std::sync::Arc;

const TEE_TOKEN_SOCKET: &str = "/run/container_launcher/teeserver.sock";

struct AppState {
    worker: Arc<ConfidentialWorker<GraniteModelRunner>>,
    attested_key: AttestedChannelKey,
}

#[derive(serde::Serialize)]
struct AttestedKeyResponse {
    /// The enclave channel public key, hex-encoded.
    channel_pubkey: String,
    /// The attestation token (a Confidential Space JWT) vouching for the key.
    attestation: String,
}

/// Publish the channel key and its attestation for clients to verify.
async fn get_attested_key(State(state): State<Arc<AppState>>) -> Json<AttestedKeyResponse> {
    Json(AttestedKeyResponse {
        channel_pubkey: hex::encode(state.attested_key.channel_pubkey),
        attestation: String::from_utf8_lossy(&state.attested_key.attestation).into_owned(),
    })
}

/// Open a sealed request inside the enclave, run the model, seal the result.
async fn infer(
    State(state): State<Arc<AppState>>,
    Json(sealed): Json<EncryptedNote>,
) -> Result<Json<EncryptedNote>, (StatusCode, String)> {
    let worker = state.worker.clone();
    // The model call blocks; run it off the async runtime.
    let handled = tokio::task::spawn_blocking(move || worker.handle(&sealed))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("worker task: {e}"),
            )
        })?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("inference: {e}")))?;
    match handled {
        Some(result) => Ok(Json(result)),
        None => Err((
            StatusCode::BAD_REQUEST,
            "request could not be opened by this enclave".to_string(),
        )),
    }
}

/// Request an attestation token from the Confidential Space launcher, binding
/// `nonce_hex` (the channel public key) into it. Falls back to
/// `TEE_ATTESTATION_TOKEN` for local development.
async fn fetch_attestation(nonce_hex: &str, audience: &str) -> Result<Vec<u8>> {
    if let Ok(token) = std::env::var("TEE_ATTESTATION_TOKEN") {
        return Ok(token.into_bytes());
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(TEE_TOKEN_SOCKET)
        .await
        .map_err(|e| {
            anyhow!("no TEE attestation socket at {TEE_TOKEN_SOCKET} (set TEE_ATTESTATION_TOKEN for local dev): {e}")
        })?;

    let body =
        format!(r#"{{"audience":"{audience}","token_type":"OIDC","nonces":["{nonce_hex}"]}}"#);
    let request = format!(
        "POST /v1/token HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await?;

    let resp = String::from_utf8_lossy(&resp);
    let token = resp
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("attestation response had no token body"))?;
    Ok(token.into_bytes())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::try_init().ok();

    let audience = env_or("TEE_AUDIENCE", "paraloom-inference");
    let llama_endpoint = env_or("LLAMA_ENDPOINT", "http://127.0.0.1:8080");
    let listen: std::net::SocketAddr = env_or("LISTEN_ADDR", "0.0.0.0:9000").parse()?;
    let max_tokens: u32 = env_or("MAX_TOKENS", "256").parse().unwrap_or(256);

    // Fresh channel per enclave session; its public key is bound into the token.
    let channel = EnclaveChannel::generate();
    let nonce_hex = hex::encode(channel.public_key());
    let attestation = fetch_attestation(&nonce_hex, &audience).await?;
    let attested_key = AttestedChannelKey {
        channel_pubkey: channel.public_key(),
        attestation,
    };
    log::info!("attested channel key ready: {nonce_hex}");

    let model = GraniteModelRunner::new(llama_endpoint).with_max_tokens(max_tokens);
    let state = Arc::new(AppState {
        worker: Arc::new(ConfidentialWorker::new(channel, model)),
        attested_key,
    });

    let app = Router::new()
        .route("/attested-key", get(get_attested_key))
        .route("/infer", post(infer))
        .with_state(state);

    log::info!("confidential-inference worker listening on {listen}");
    axum::Server::bind(&listen)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}
