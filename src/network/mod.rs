//! P2P networking module

pub mod compute_protocol;
mod discovery;
mod message;
pub mod protocol;
pub mod req_resp;

pub use compute_protocol::{
    ComputeJobCodec, ComputeJobRequest, ComputeJobResponse, ComputeQueryCodec, ComputeQueryRequest,
    ComputeQueryResponse, COMPUTE_JOB_PROTOCOL, COMPUTE_QUERY_PROTOCOL,
};
pub use message::Message;
pub use protocol::NetworkManager;
pub use req_resp::{ResultRequest, ResultResponse};
