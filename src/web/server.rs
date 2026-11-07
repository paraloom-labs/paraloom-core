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

/// Upper bound on retained dashboard node entries so repeated registrations
/// cannot grow in-memory state without bound.
const MAX_DASHBOARD_NODES: usize = 1024;

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
        if !nodes.contains_key(&web_info.id) && nodes.len() >= MAX_DASHBOARD_NODES {
            if let Some(victim) = nodes.keys().min().cloned() {
                nodes.remove(&victim);
            }
        }
        nodes.insert(web_info.id.clone(), web_info);
    }

    pub fn clear_nodes(&self) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.clear();
    }

    pub fn get_stats(&self) -> NetworkStats {
        let nodes = self.nodes.lock().unwrap();

        let total_cpu_cores: u32 = nodes.values().fold(0u32, |acc, n| {
            acc.saturating_add(n.resources.cpu_cores as u32)
        });
        let total_memory_mb: u64 = nodes
            .values()
            .fold(0u64, |acc, n| acc.saturating_add(n.resources.memory_mb));

        NetworkStats {
            total_nodes: nodes.len(),
            active_connections: nodes.len().saturating_sub(1),
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
    let uptime = state.start_time.elapsed().as_secs();
    let nodes = state.nodes.lock().unwrap();
    let mut list: Vec<WebNodeInfo> = nodes
        .values()
        .cloned()
        .map(|mut n| {
            n.uptime = uptime;
            n
        })
        .collect();
    list.sort_by(|a, b| a.id.cmp(&b.id));
    Json(list)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NodeId, NodeType};

    fn make_node_info(id: Vec<u8>, cpu_cores: u8, memory_mb: u64) -> NodeInfo {
        NodeInfo {
            id: NodeId(id),
            node_type: NodeType::ResourceProvider,
            resources: ResourceContribution {
                cpu_cores,
                memory_mb,
                storage_mb: 1024,
                bandwidth_kbps: 1000,
            },
            address: "/ip4/127.0.0.1/tcp/9000".to_string(),
            wallet_pubkey: None,
        }
    }

    #[test]
    fn get_stats_saturates_instead_of_panicking_on_u64_overflow() {
        let state = DashboardState::new();
        state.add_node(&make_node_info(vec![1], 16, u64::MAX - 10));
        state.add_node(&make_node_info(vec![2], 32, 100));

        let stats = state.get_stats();
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_cpu_cores, 48);
        assert_eq!(stats.total_memory_mb, u64::MAX);
    }

    #[test]
    fn add_node_bounds_retained_entries() {
        let state = DashboardState::new();
        for i in 0..(MAX_DASHBOARD_NODES + 10) {
            state.add_node(&make_node_info((i as u32).to_be_bytes().to_vec(), 4, 1024));
        }
        assert_eq!(state.get_stats().total_nodes, MAX_DASHBOARD_NODES);
    }
}
