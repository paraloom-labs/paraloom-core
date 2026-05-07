//! P2P networking module

pub mod compute_protocol;
pub mod discovery;
pub mod heartbeat;
mod message;
pub mod protocol;
pub mod req_resp;

pub use compute_protocol::{
    ComputeJobCodec, ComputeJobRequest, ComputeJobResponse, ComputeQueryCodec, ComputeQueryRequest,
    ComputeQueryResponse, COMPUTE_JOB_PROTOCOL, COMPUTE_QUERY_PROTOCOL,
};
pub use discovery::{PeerCounts, PeerRegistry, PeerState, PeerSummary, RECONNECT_BACKOFF};
pub use heartbeat::{
    create_heartbeat_protocol, HeartbeatCodec, HeartbeatRequest, HeartbeatResponse,
    HEARTBEAT_PROTOCOL, MAX_HEARTBEAT_PAYLOAD_BYTES,
};
pub use message::Message;
pub use protocol::NetworkManager;
pub use req_resp::{ResultRequest, ResultResponse};
