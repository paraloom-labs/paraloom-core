//! Web dashboard server

use axum::{
    extract::Extension,
    response::{Html, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

use crate::types::{NodeInfo, ResourceContribution};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub total_nodes: usize,
    pub active_connections: usize,
    pub total_cpu_cores: u32,
    pub total_memory_mb: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebNodeInfo {
    pub id: String,
    pub node_type: String,
    pub status: String,
    pub resources: ResourceContribution,
    pub address: String,
    pub uptime: u64,
}

#[derive(Debug, Clone)]
pub struct DashboardState {
    pub nodes: Arc<Mutex<HashMap<String, WebNodeInfo>>>,
    pub start_time: std::time::Instant,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn add_node(&self, info: &NodeInfo) {
        let web_info = WebNodeInfo {
            id: format!("{}", info.id),
            node_type: format!("{:?}", info.node_type),
            status: "active".to_string(),
            resources: info.resources.clone(),
            address: info.address.clone(),
            uptime: self.start_time.elapsed().as_secs(),
        };

        let mut nodes = self.nodes.lock().unwrap();
        nodes.insert(web_info.id.clone(), web_info);
    }

    pub fn clear_nodes(&self) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.clear();
    }

    pub fn get_stats(&self) -> NetworkStats {
        let nodes = self.nodes.lock().unwrap();

        let total_cpu_cores: u32 = nodes.values().map(|n| n.resources.cpu_cores as u32).sum();
        let total_memory_mb: u64 = nodes.values().map(|n| n.resources.memory_mb).sum();

        NetworkStats {
            total_nodes: nodes.len(),
            active_connections: if nodes.len() > 1 { nodes.len() - 1 } else { 0 },
            total_cpu_cores,
            total_memory_mb,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }
}

// API Handlers
async fn get_stats(Extension(state): Extension<DashboardState>) -> Json<NetworkStats> {
    Json(state.get_stats())
}

async fn get_nodes(Extension(state): Extension<DashboardState>) -> Json<Vec<WebNodeInfo>> {
    let nodes = state.nodes.lock().unwrap();
    Json(nodes.values().cloned().collect())
}

async fn dashboard() -> Html<String> {
    let html = std::fs::read_to_string("web/dashboard.html").unwrap_or_else(|_| {
        r#"<!DOCTYPE html>
<html><head><title>Paraloom Dashboard</title></head>
<body style="background: #000; color: #0f0; font-family: monospace; padding: 20px;">
<h1>Paraloom Dashboard</h1>
<p>Dashboard file not found: web/dashboard.html</p>
<p>Please create the dashboard HTML file.</p>
</body></html>"#
            .to_string()
    });
    Html(html)
}

pub async fn start_dashboard_server(
    state: DashboardState,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(get_stats))
        .route("/api/nodes", get(get_nodes))
        .layer(Extension(state))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("Dashboard: http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

pub async fn start_dashboard_with_coordinator(
    state: DashboardState,
    coordinator: std::sync::Arc<crate::coordinator::Coordinator>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::web::api::create_api_router;

    let api_router = create_api_router(coordinator);

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(get_stats))
        .route("/api/nodes", get(get_nodes))
        .merge(api_router)
        .layer(Extension(state))
        .layer(CorsLayer::permissive());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("Dashboard with API: http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
