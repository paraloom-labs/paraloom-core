//! Coordinator HA heartbeat protocol.
//!
//! Carries the primary's `CoordinatorSnapshot` to its standbys so
//! they can mirror state and watch for liveness. The payload is the
//! snapshot itself rather than a separate "heartbeat then fetch"
//! handshake: the snapshot is small in practice, the cost difference
//! is negligible at the heartbeat frequencies we care about, and
//! folding it in keeps the standby-side state machine simple.

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{Behaviour as RequestResponse, Codec, Config, ProtocolSupport};
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;

use crate::coordinator::CoordinatorSnapshot;
use crate::types::NodeId;

/// Protocol name used by libp2p request-response.
pub const HEARTBEAT_PROTOCOL: &str = "/paraloom/heartbeat/1.0.0";

/// Cap on a single heartbeat payload. Same shape and rationale as
/// `MAX_RESULT_PAYLOAD_BYTES` in `req_resp`: large enough that no
/// realistic snapshot trips it, small enough that a misbehaving peer
/// cannot pin our heap by streaming an unbounded payload.
pub const MAX_HEARTBEAT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Heartbeat from primary to standby. Carries the primary's identity,
/// a monotonically increasing sequence number for ordering and replay
/// detection, and the canonical state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub primary: NodeId,
    pub sequence: u64,
    pub snapshot: CoordinatorSnapshot,
}

/// Acknowledgement from standby. `accepted` is `false` if the standby
/// rejected this heartbeat (for example because it just promoted
/// itself and is now a primary). `last_applied_sequence` is the
/// highest sequence number the standby has now mirrored locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub accepted: bool,
    pub last_applied_sequence: u64,
}

/// Read at most [`MAX_HEARTBEAT_PAYLOAD_BYTES`] from `io` into a
/// freshly-allocated buffer. Mirrors the bounded reader used by the
/// result protocol; duplicated rather than shared because the two
/// callers have independent size budgets and are otherwise unrelated.
async fn read_size_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(MAX_HEARTBEAT_PAYLOAD_BYTES as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > MAX_HEARTBEAT_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "heartbeat payload exceeds {} bytes",
                MAX_HEARTBEAT_PAYLOAD_BYTES
            ),
        ));
    }
    Ok(buf)
}

/// Bincode-backed codec, structurally identical to `ResultCodec`.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatCodec;

#[async_trait]
impl Codec for HeartbeatCodec {
    type Protocol = &'static str;
    type Request = HeartbeatRequest;
    type Response = HeartbeatResponse;

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

/// Build the libp2p request-response behaviour for the heartbeat
/// protocol. Request timeout is shorter than the result protocol's
/// 60s: a heartbeat that takes longer than a few seconds is
/// indistinguishable from a stall, and we want the standby to give
/// up and start watching its own clock instead.
pub fn create_heartbeat_protocol() -> RequestResponse<HeartbeatCodec> {
    let protocols = [(HEARTBEAT_PROTOCOL, ProtocolSupport::Full)];
    let cfg = Config::default().with_request_timeout(Duration::from_secs(5));
    RequestResponse::with_codec(HeartbeatCodec, protocols.iter().cloned(), cfg)
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
        let payload = vec![0xCDu8; MAX_HEARTBEAT_PAYLOAD_BYTES + 1];
        let mut cursor = Cursor::new(payload);
        let err = read_size_bounded(&mut cursor)
            .await
            .expect_err("over-limit payload must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn heartbeat_request_round_trips_through_bincode() {
        let request = HeartbeatRequest {
            primary: NodeId(vec![0x01, 0x02, 0x03]),
            sequence: 42,
            snapshot: CoordinatorSnapshot::default(),
        };
        let encoded = bincode::serialize(&request).expect("serialize");
        let decoded: HeartbeatRequest = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.primary, request.primary);
        assert_eq!(decoded.sequence, request.sequence);
        assert_eq!(
            decoded.snapshot.validators.len(),
            request.snapshot.validators.len()
        );
    }

    #[test]
    fn heartbeat_response_round_trips_through_bincode() {
        let response = HeartbeatResponse {
            accepted: true,
            last_applied_sequence: 99,
        };
        let encoded = bincode::serialize(&response).expect("serialize");
        let decoded: HeartbeatResponse = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded.accepted, response.accepted);
        assert_eq!(
            decoded.last_applied_sequence,
            response.last_applied_sequence
        );
    }
}
