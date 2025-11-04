//! Standalone dashboard server

use paraloom::web::{DashboardState, start_dashboard_server};
use paraloom::types::{NodeId, NodeInfo, NodeType, ResourceContribution};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("Paraloom Dashboard Server");
    
 
    let state = DashboardState::new();
    
   
    let demo_node = NodeInfo {
        id: NodeId(vec![1, 2, 3, 4]),
        node_type: NodeType::ResourceProvider,
        resources: ResourceContribution {
            cpu_cores: 8,
            memory_mb: 16384,
            storage_mb: 100000,
            bandwidth_kbps: 1000,
        },
        address: "127.0.0.1:8080".to_string(),
    };
    
    state.add_node(&demo_node);
    

    let demo_node2 = NodeInfo {
        id: NodeId(vec![5, 6, 7, 8]),
        node_type: NodeType::Coordinator,
        resources: ResourceContribution {
            cpu_cores: 16,
            memory_mb: 32768,
            storage_mb: 200000,
            bandwidth_kbps: 2000,
        },
        address: "127.0.0.1:8081".to_string(),
    };
    
    state.add_node(&demo_node2);
    
    println!("Demo dashboard starting with 2 nodes...");
    println!("Open: http://localhost:3000");
    println!("API endpoints:");
    println!("http://localhost:3000/api/stats");
    println!("http://localhost:3000/api/nodes");
    
    start_dashboard_server(state, 3000).await?;
    
    Ok(())
}