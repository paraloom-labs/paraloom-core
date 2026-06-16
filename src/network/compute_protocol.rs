//! Request-Response protocol for compute jobs
//!
//! This module provides network protocols for:
//! - Submitting compute jobs to validators
//! - Querying job status and results

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::Codec;
use serde::{Deserialize, Serialize};
use std::io;

use crate::compute::{JobId, JobResult, JobStatus, ResourceLimits};

/// Protocol name for compute job submission
pub const COMPUTE_JOB_PROTOCOL: &str = "/paraloom/compute/1.0.0";

/// Protocol name for compute result queries
pub const COMPUTE_QUERY_PROTOCOL: &str = "/paraloom/compute/query/1.0.0";

/// Cap on a single compute payload. The sibling protocols (`req_resp`,
/// `heartbeat`, `cosign`) all bound their reads to stop a peer pinning our heap
/// with an unbounded stream; this codec read unbounded. Generous enough for a
/// real wasm job, far below an OOM. (audit)
pub const MAX_COMPUTE_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Read at most [`MAX_COMPUTE_PAYLOAD_BYTES`] from `io`, erroring on a larger
/// stream. Mirrors the bounded readers in the sibling request-response codecs.
async fn read_size_bounded<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    let mut limited = io.take(MAX_COMPUTE_PAYLOAD_BYTES as u64 + 1);
    limited.read_to_end(&mut buf).await?;
    if buf.len() > MAX_COMPUTE_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "compute payload exceeds {} bytes",
                MAX_COMPUTE_PAYLOAD_BYTES
            ),
        ));
    }
    Ok(buf)
}

/// Request to submit a compute job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJobRequest {
    pub job_id: JobId,
    pub wasm_code: Vec<u8>,
    pub input_data: Vec<u8>,
    pub limits: ResourceLimits,
}

/// Response to compute job submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJobResponse {
    pub job_id: JobId,
    pub accepted: bool,
    pub message: String,
}

/// Request to query job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeQueryRequest {
    pub job_id: JobId,
}

/// Response with job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeQueryResponse {
    pub job_id: JobId,
    pub status: JobStatus,
    pub result: Option<JobResult>,
}

/// Codec for compute job protocol
#[derive(Debug, Clone, Default)]
pub struct ComputeJobCodec;

#[async_trait]
impl Codec for ComputeJobCodec {
    type Protocol = &'static str;
    type Request = ComputeJobRequest;
    type Response = ComputeJobResponse;

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

/// Codec for compute query protocol
#[derive(Debug, Clone, Default)]
pub struct ComputeQueryCodec;

#[async_trait]
impl Codec for ComputeQueryCodec {
    type Protocol = &'static str;
    type Request = ComputeQueryRequest;
    type Response = ComputeQueryResponse;

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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;

    #[tokio::test]
    async fn read_size_bounded_accepts_payload_under_limit() {
        let payload = vec![0xABu8; 4096];
        let mut cursor = Cursor::new(payload.clone());
        let read = read_size_bounded(&mut cursor)
            .await
            .expect("under-limit payload");
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn read_size_bounded_rejects_payload_over_limit() {
        let payload = vec![0xCDu8; MAX_COMPUTE_PAYLOAD_BYTES + 1];
        let mut cursor = Cursor::new(payload);
        let err = read_size_bounded(&mut cursor)
            .await
            .expect_err("over-limit payload must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
