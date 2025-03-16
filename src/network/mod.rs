//! P2P networking module

pub mod protocol;
mod discovery;
mod message;

pub use protocol::NetworkManager;
pub use message::Message;