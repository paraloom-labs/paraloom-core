//! Settlement co-signing protocol (#260).
//!
//! When an off-chain BFT round approves a withdrawal or shielded transfer, the
//! on-chain program now requires a quorum of registered validators to co-sign
//! the settlement transaction (see `programs/paraloom/src/quorum.rs`). The
//! leader for that round assembles the unsigned Solana transaction and uses
//! this request-response protocol to collect each co-signer's signature: it
//! sends every validator that voted to approve a [`CoSignRequest`] carrying the
//! serialized transaction message, and each validator returns a
//! [`CoSignResponse`] with its ed25519 signature over that message.
//!
//! This module is the wire protocol only — the codec, the message shapes, and
//! the bounded reader. The validator-side verify-then-sign handler and the
//! leader-side collect-and-assemble round build on it.
//!
//! Structurally a sibling of `heartbeat`: same bounded-read discipline and
//! bincode codec, duplicated rather than shared because the payloads and size
//! budgets are independent.

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{Behaviour as RequestResponse, Codec, Config, ProtocolSupport};
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;

/// Protocol name used by libp2p request-response.
pub const COSIGN_PROTOCOL: &str = "/paraloom/cosign/1.0.0";

/// Cap on a single co-sign payload. A settlement transaction message is only a
/// couple of kilobytes, so the same generous 4 MiB ceiling used elsewhere is
/// far above any real request while still stopping a misbehaving peer from
/// pinning our heap with an unbounded stream.
pub const MAX_COSIGN_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Which settlement path a co-sign request covers, so the validator-side
/// handler can match it against the right pending-approval set before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementKind {
    /// A v3 `transact` settlement (#350): unified 2-in/2-out spend against the
    /// program's on-chain incremental tree, covering both a withdrawal
    /// (`ext_amount < 0`) and a pure shielded transfer (`ext_amount == 0`).
    /// This is the sole settlement kind — the legacy off-chain-root
    /// `Withdrawal` / `Transfer` / `UpdateMerkleRoot` kinds were removed.
    Transact,
}

/// Leader → validator: please co-sign this settlement transaction.
///
/// `message` is the serialized Solana transaction message the leader assembled
/// for the approved settlement. A validator must independently rebuild and
/// verify it against the settlement it voted to approve — keyed by
/// `request_id` — and sign only if it matches; it must never blindly sign
/// opaque bytes. `kind` routes the lookup to the withdrawal or transfer
/// coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoSignRequest {
    /// Consensus round identifier the settlement belongs to.
    pub request_id: String,
    /// Which settlement path this covers.
    pub kind: SettlementKind,
    /// Serialized Solana transaction message to be signed.
    pub message: Vec<u8>,
}

/// Validator → leader: the signature over the request's `message`.
///
/// `wallet_pubkey` is the base58 Solana wallet the signature was produced with,
/// so the leader can place the signature at the matching account position in
/// the assembled multi-sig transaction. `signature` is `None` when the
/// validator declines — for example because the message did not match an
/// approved settlement it had voted on — which the leader treats the same as a
/// non-response (it simply does not count toward the quorum).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoSignResponse {
    /// Echoes the request's `request_id` for correlation.
    pub request_id: String,
    /// Base58 wallet pubkey the signature was produced with.
    pub wallet_pubkey: String,
    /// 64-byte ed25519 signature over `message`, or `None` if declined.
    pub signature: Option<Vec<u8>>,
}

/// Read at most [`MAX_COSIGN_PAYLOAD_BYTES`] from `io` into a freshly-allocated
/// buffer. Mirrors the bounded readers used by the result and heartbeat
/// protocols.
async fn read_size_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(MAX_COSIGN_PAYLOAD_BYTES as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > MAX_COSIGN_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cosign payload exceeds {} bytes", MAX_COSIGN_PAYLOAD_BYTES),
        ));
    }
    Ok(buf)
}

/// Bincode-backed codec, structurally identical to `HeartbeatCodec`.
#[derive(Debug, Clone, Default)]
pub struct CoSignCodec;

#[async_trait]
impl Codec for CoSignCodec {
    type Protocol = &'static str;
    type Request = CoSignRequest;
    type Response = CoSignResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_size_bounded(io).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_size_bounded(io).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data =
            bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&data).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data =
            bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&data).await?;
        io.close().await
    }
}

/// Build the libp2p request-response behaviour for the co-sign protocol.
///
/// The 10s request timeout gives a validator room to rebuild and verify the
/// transaction message and produce a signature, while staying well inside a
/// Solana blockhash's validity window so the leader can still land the
/// assembled transaction after collecting signatures.
pub fn create_cosign_protocol() -> RequestResponse<CoSignCodec> {
    let protocols = [(COSIGN_PROTOCOL, ProtocolSupport::Full)];
    let cfg = Config::default().with_request_timeout(Duration::from_secs(10));
    RequestResponse::with_codec(CoSignCodec, protocols.iter().cloned(), cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[tokio::test]
    async fn read_size_bounded_accepts_payload_under_limit() {
        let payload = vec![0xABu8; 1024];
        let mut cursor = Cursor::new(payload.clone());
        let read = read_size_bounded(&mut cursor)
            .await
            .expect("under-limit payload");
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn read_size_bounded_rejects_payload_over_limit() {
        let payload = vec![0xCDu8; MAX_COSIGN_PAYLOAD_BYTES + 1];
        let mut cursor = Cursor::new(payload);
        let err = read_size_bounded(&mut cursor)
            .await
            .expect_err("over-limit payload must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn cosign_request_round_trips_through_bincode() {
        let request = CoSignRequest {
            request_id: "round-42".to_string(),
            kind: SettlementKind::Transact,
            message: vec![0x01, 0x02, 0x03, 0x04],
        };
        let encoded = bincode::serialize(&request).expect("serialize");
        let decoded: CoSignRequest = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.kind, request.kind);
        assert_eq!(decoded.message, request.message);
    }

    #[test]
    fn cosign_response_round_trips_with_signature() {
        let response = CoSignResponse {
            request_id: "round-42".to_string(),
            wallet_pubkey: "Hky4Zx2WaLLet".to_string(),
            signature: Some(vec![0xEEu8; 64]),
        };
        let encoded = bincode::serialize(&response).expect("serialize");
        let decoded: CoSignResponse = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.request_id, response.request_id);
        assert_eq!(decoded.wallet_pubkey, response.wallet_pubkey);
        assert_eq!(decoded.signature, Some(vec![0xEEu8; 64]));
    }

    #[test]
    fn cosign_response_round_trips_when_declined() {
        let response = CoSignResponse {
            request_id: "round-7".to_string(),
            wallet_pubkey: "DeCLineD".to_string(),
            signature: None,
        };
        let encoded = bincode::serialize(&response).expect("serialize");
        let decoded: CoSignResponse = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.signature, None);
        assert_eq!(decoded.request_id, response.request_id);
    }

    #[test]
    fn settlement_kind_transact_round_trips() {
        let kind = SettlementKind::Transact;
        let encoded = bincode::serialize(&kind).expect("serialize");
        let decoded: SettlementKind = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded, kind);
    }
}
