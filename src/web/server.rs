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

pub const MAX_DASHBOARD_NODES: usize = 1024;

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
        let node_id = format!("{}", info.id);
        let mut nodes = self.nodes.lock().unwrap();
        if nodes.len() >= MAX_DASHBOARD_NODES && !nodes.contains_key(&node_id) {
            return;
        }

        let web_info = WebNodeInfo {
            id: node_id.clone(),
            node_type: format!("{:?}", info.node_type),
            status: "active".to_string(),
            resources: info.resources.clone(),
            address: info.address.clone(),
            uptime: self.start_time.elapsed().as_secs(),
        };

        nodes.insert(node_id, web_info);
    }

    pub fn clear_nodes(&self) {
        let mut nodes = self.nodes.lock().unwrap();
        nodes.clear();
    }

    pub fn get_stats(&self) -> NetworkStats {
        let nodes = self.nodes.lock().unwrap();

        let total_cpu_cores: u32 = nodes
            .values()
            .fold(0u32, |acc, n| acc.saturating_add(n.resources.cpu_cores as u32));
        let total_memory_mb: u64 = nodes
            .values()
            .fold(0u64, |acc, n| acc.saturating_add(n.resources.memory_mb));

        NetworkStats {
            total_nodes: nodes.len(),
            active_connections: if nodes.len() > 1 { nodes.len() - 1 } else { 0 },
            total_cpu_cores,
            total_memory_mb,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    pub fn get_nodes(&self) -> Vec<WebNodeInfo> {
        let current_uptime = self.start_time.elapsed().as_secs();
        let nodes = self.nodes.lock().unwrap();
        let mut out: Vec<WebNodeInfo> = nodes
            .values()
            .cloned()
            .map(|mut n| {
                n.uptime = current_uptime;
                n
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

// API Handlers
async fn get_stats(Extension(state): Extension<DashboardState>) -> Json<NetworkStats> {
    Json(state.get_stats())
}

async fn get_nodes(Extension(state): Extension<DashboardState>) -> Json<Vec<WebNodeInfo>> {
    Json(state.get_nodes())
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
    use crate::types::{NodeId, NodeType, ResourceContribution};

    fn make_node(id_bytes: Vec<u8>, cpu: u8, mem: u64) -> crate::types::NodeInfo {
        crate::types::NodeInfo {
            id: NodeId(id_bytes),
            node_type: NodeType::ResourceProvider,
            address: "127.0.0.1:8000".to_string(),
            resources: ResourceContribution {
                cpu_cores: cpu,
                memory_mb: mem,
                storage_mb: 100,
                bandwidth_kbps: 1000,
            },
            wallet_pubkey: None,
        }
    }

    #[test]
    fn get_stats_saturates_without_overflow_panic() {
        let state = DashboardState::new();
        state.add_node(&make_node(vec![0x01], 255, u64::MAX));
        state.add_node(&make_node(vec![0x02], 255, u64::MAX));

        let stats = state.get_stats();
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.total_cpu_cores, 510);
        assert_eq!(stats.total_memory_mb, u64::MAX);
    }

    #[test]
    fn max_dashboard_nodes_cap_enforced() {
        let state = DashboardState::new();
        for i in 0..MAX_DASHBOARD_NODES {
            let b1 = (i >> 8) as u8;
            let b2 = (i & 0xff) as u8;
            state.add_node(&make_node(vec![b1, b2], 1, 1024));
        }
        assert_eq!(state.get_stats().total_nodes, MAX_DASHBOARD_NODES);

        // Trying to add 1 more node must be ignored
        state.add_node(&make_node(vec![0xff, 0xff, 0x01], 1, 1024));
        assert_eq!(state.get_stats().total_nodes, MAX_DASHBOARD_NODES);

        // Updating an existing node still succeeds
        state.add_node(&make_node(vec![0, 0], 2, 2048));
        assert_eq!(state.get_stats().total_nodes, MAX_DASHBOARD_NODES);
    }

    #[test]
    fn get_nodes_sorts_deterministically_by_id() {
        let state = DashboardState::new();
        state.add_node(&make_node(vec![0xcc], 1, 100));
        state.add_node(&make_node(vec![0xaa], 1, 100));
        state.add_node(&make_node(vec![0xbb], 1, 100));

        let nodes = state.get_nodes();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].id, "aa");
        assert_eq!(nodes[1].id, "bb");
        assert_eq!(nodes[2].id, "cc");
    }
}
