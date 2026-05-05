//! Request-Response protocol for reliable result collection

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{Behaviour as RequestResponse, Codec, Config, ProtocolSupport};
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;

use crate::task::TaskResult;

/// Protocol name for result collection
pub const RESULT_PROTOCOL: &str = "/paraloom/result/1.0.0";

/// Maximum bytes the codec will accept for a single request or
/// response payload. The previous version used `read_to_end()` with no
/// upper bound, so a misbehaving (or compromised) peer could pin the
/// coordinator's heap by streaming an arbitrarily large message — the
/// audit (#69, follow-up to #58) flagged this as a denial-of-service
/// vector.
///
/// 4 MiB is generously above what a real \`TaskResult\` payload should
/// produce: a Groth16 proof is ~190 bytes, output bytes are bounded
/// elsewhere, and the surrounding bincode overhead is small. Tighten
/// when production telemetry confirms a smaller bound is safe; loosen
/// only when a measured regression demands it.
pub const MAX_RESULT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Read at most [`MAX_RESULT_PAYLOAD_BYTES`] bytes from `io` into
/// `buf`. Returns `InvalidData` if the peer streams more than the
/// limit, instead of silently truncating or growing the buffer
/// without bound.
async fn read_size_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    // The +1 sentinel lets us distinguish "exactly at the limit" from
    // "above the limit": if `take` returns more than the limit's worth
    // of bytes, we know the peer was trying to send beyond the cap.
    let mut buf = Vec::new();
    let mut limited = io.take(MAX_RESULT_PAYLOAD_BYTES as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > MAX_RESULT_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "request-response payload exceeds {} bytes",
                MAX_RESULT_PAYLOAD_BYTES
            ),
        ));
    }
    Ok(buf)
}

/// Request: TaskResult from validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultRequest {
    pub result: TaskResult,
}

/// Response: Acknowledgment from coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultResponse {
    pub success: bool,
    pub message: String,
}

/// Codec for result protocol
#[derive(Debug, Clone, Default)]
pub struct ResultCodec;

#[async_trait]
impl Codec for ResultCodec {
    type Protocol = &'static str;
    type Request = ResultRequest;
    type Response = ResultResponse;

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

/// Create a new RequestResponse behavior for result collection
pub fn create_result_protocol() -> RequestResponse<ResultCodec> {
    let protocols = [(RESULT_PROTOCOL, ProtocolSupport::Full)];
    let cfg = Config::default().with_request_timeout(Duration::from_secs(60));

    RequestResponse::with_codec(ResultCodec, protocols.iter().cloned(), cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    /// A reasonably sized payload deserialises cleanly. Establishes
    /// the happy-path baseline for the bounded reader.
    #[tokio::test]
    async fn read_size_bounded_accepts_payload_under_limit() {
        let payload = vec![0xABu8; 1024];
        let mut cursor = Cursor::new(payload.clone());
        let read = read_size_bounded(&mut cursor)
            .await
            .expect("under-limit payload");
        assert_eq!(read, payload);
    }

    /// A payload of exactly the limit is accepted; this pins the
    /// boundary so a future tightening of the limit is a deliberate
    /// breaking change rather than an off-by-one drift.
    #[tokio::test]
    async fn read_size_bounded_accepts_payload_at_limit() {
        let payload = vec![0xCDu8; MAX_RESULT_PAYLOAD_BYTES];
        let mut cursor = Cursor::new(payload.clone());
        let read = read_size_bounded(&mut cursor)
            .await
            .expect("limit-sized payload");
        assert_eq!(read.len(), MAX_RESULT_PAYLOAD_BYTES);
    }

    /// A payload of \`limit + 1\` bytes is the regression case the
    /// audit (#69) cares about: previously \`read_to_end\` would
    /// happily allocate the full attacker-supplied size, OOMing the
    /// coordinator. The bounded reader must surface
    /// \`InvalidData\` instead.
    #[tokio::test]
    async fn read_size_bounded_rejects_payload_over_limit() {
        let payload = vec![0xEFu8; MAX_RESULT_PAYLOAD_BYTES + 1];
        let mut cursor = Cursor::new(payload);
        let err = read_size_bounded(&mut cursor)
            .await
            .expect_err("over-limit payload must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Empty input returns an empty buffer; bincode will then surface
    /// the deserialisation error with its own actionable message.
    #[tokio::test]
    async fn read_size_bounded_handles_empty_input() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let read = read_size_bounded(&mut cursor)
            .await
            .expect("empty input is OK");
        assert!(read.is_empty());
    }
}
