//! Web dashboard module

pub mod api;
pub mod server;

pub use server::{DashboardState, start_dashboard_server};
pub use api::create_api_router;
