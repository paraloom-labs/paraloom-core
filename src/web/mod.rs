//! Web dashboard module

pub mod api;
pub mod server;

pub use api::create_api_router;
pub use server::{start_dashboard_server, DashboardState};
