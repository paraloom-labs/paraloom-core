//! P2P networking module

mod discovery;
mod message;
pub mod protocol;

pub use message::Message;
pub use protocol::NetworkManager;
