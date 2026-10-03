use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use paraloom::consensus::transact::TransactVerificationRequest;
use paraloom::node::transact_ingress::{router, DeliveredNote, TransactIngress};
use paraloom::privacy::{ProofSuite, GROTH16_BN254_COMPRESSED_LEN};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

struct CaptureIngress {
    seen: Mutex<Option<TransactVerificationRequest>>,
}

#[async_trait]
impl TransactIngress for CaptureIngress {
    async fn submit_transact(&self, request: TransactVerificationRequest) -> anyhow::Result<String> {
        let id = request.request_id.clone();
        *self.seen.lock().await = Some(request);
        Ok(id)
    }

    async fn delivered_notes(&self) -> Vec<DeliveredNote> {
        vec![]
    }
}

fn v1_ciphertext_hex(fill: u8) -> String {
    let mut bytes = vec![paraloom::privacy::note_crypto::ENVELOPE_TAG_V1];
    bytes.extend_from_slice(&[fill; 32]);
    bytes.extend_from_slice(&[fill; 24]);
    bytes.extend_from_slice(&[fill; 16]);
    hex::encode(bytes)
}

fn submit_body_with_proof(proof_hex: String) -> String {
    format!(
        r#"{{"recipient":"{}","nullifiers":["{}","{}"],"output_commitments":["{}","{}"],"root":"{}","ext_amount":0,"proof":"{}","ciphertexts":["{}","{}"]}}"#,
        "66".repeat(32),
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
        proof_hex,
        v1_ciphertext_hex(0xab),
        v1_ciphertext_hex(0xcd),
    )
}

#[tokio::test]
async fn oversized_tagged_proof_is_rejected_at_ingress() {
    let expected_len = 1 + GROTH16_BN254_COMPRESSED_LEN;
    let mut malformed = vec![ProofSuite::Groth16Bn254TransactV3.tag()];
    malformed.extend_from_slice(&vec![0u8; GROTH16_BN254_COMPRESSED_LEN + 1]);
    assert_eq!(malformed.len(), expected_len + 1);
    assert!(
        paraloom::privacy::split_tagged_proof(&malformed).is_err(),
        "the proof envelope has the right suite tag but a non-canonical body length"
    );

    let stub = Arc::new(CaptureIngress {
        seen: Mutex::new(None),
    });
    let app = router(stub.clone(), None);
    let req = Request::builder()
        .method("POST")
        .uri("/transact/submit")
        .header("content-type", "application/json")
        .body(Body::from(submit_body_with_proof(hex::encode(&malformed))))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "the write ingress must reject a malformed tagged proof with HTTP 400"
    );

    assert!(
        stub.seen.lock().await.is_none(),
        "malformed proof must not be forwarded into consensus work"
    );
}
