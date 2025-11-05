//! Request-Response protocol for reliable result collection

use libp2p::request_response::{ProtocolSupport, RequestResponse, RequestResponseCodec};
use serde::{Deserialize, Serialize};
use std::io;
use async_trait::async_trait;
use futures::prelude::*;

use crate::task::TaskResult;

/// Protocol name for result collection
pub const RESULT_PROTOCOL: &str = "/paraloom/result/1.0.0";

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
#[derive(Debug, Clone)]
pub struct ResultCodec;

#[async_trait]
impl RequestResponseCodec for ResultCodec {
    type Protocol = String;
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
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
        bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
        let data = bincode::serialize(&req)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
        let data = bincode::serialize(&res)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        io.write_all(&data).await?;
        io.close().await
    }
}

/// Create a new RequestResponse behavior for result collection
pub fn create_result_protocol() -> RequestResponse<ResultCodec> {
    RequestResponse::new(
        ResultCodec,
        std::iter::once((RESULT_PROTOCOL.to_string(), ProtocolSupport::Full)),
        Default::default(),
    )
}
