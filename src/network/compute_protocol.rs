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
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
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
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
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
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
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
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
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
