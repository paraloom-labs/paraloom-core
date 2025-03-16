//! System resource monitoring

use anyhow::Result;
use log::{info, warn};
use sysinfo::{System, SystemExt, CpuExt, DiskExt, NetworkExt};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

use crate::types::ResourceContribution;

/// Monitors system resources
pub struct ResourceMonitor {
    system: Arc<Mutex<System>>,
    contribution: Arc<Mutex<ResourceContribution>>,
    max_cpu_usage: u8,
    max_memory_usage: u8,
    max_storage_usage: u64,
}

impl ResourceMonitor {
    /// Create a new resource monitor
    pub fn new(max_cpu_usage: u8, max_memory_usage: u8, max_storage_usage: u64) -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        
        let contribution = ResourceContribution {
            cpu_cores: system.cpus().len() as u8,
            memory_mb: 0,  // Will be updated later
            storage_mb: 0,  // Will be updated later
            bandwidth_kbps: 0,  // Will be measured later
        };
        
        ResourceMonitor {
            system: Arc::new(Mutex::new(system)),
            contribution: Arc::new(Mutex::new(contribution)),
            max_cpu_usage,
            max_memory_usage,
            max_storage_usage,
        }
    }
    
    /// Get current resource contribution
    pub fn get_contribution(&self) -> ResourceContribution {
        self.contribution.lock().unwrap().clone()
    }
    
    /// Start the resource monitor
    pub async fn start(&self) -> Result<()> {
        let system = self.system.clone();
        let contribution = self.contribution.clone();
        let max_cpu_usage = self.max_cpu_usage;
        let max_memory_usage = self.max_memory_usage;
        let max_storage_usage = self.max_storage_usage;
        
        // Start the monitoring task
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                // Update system information
                {
                    let mut sys = system.lock().unwrap();
                    sys.refresh_all();
                }
                
                // Update contribution metrics
                Self::update_contribution(
                    system.clone(), 
                    contribution.clone(), 
                    max_cpu_usage, 
                    max_memory_usage, 
                    max_storage_usage
                ).await;
                
                // Log current status
                let current = contribution.lock().unwrap().clone();
                info!(
                    "System resources: CPU Cores: {}, RAM: {} MB, Disk: {} MB, Bandwidth: {} Kbps",
                    current.cpu_cores, current.memory_mb, current.storage_mb, current.bandwidth_kbps
                );
            }
        });
        
        Ok(())
    }
    
    /// Update contribution metrics
    async fn update_contribution(
        system: Arc<Mutex<System>>,
        contribution: Arc<Mutex<ResourceContribution>>,
        max_cpu_usage: u8,
        max_memory_usage: u8,
        max_storage_usage: u64,
    ) {
        let sys = system.lock().unwrap();
        let mut contrib = contribution.lock().unwrap();
        
        // CPU information
        contrib.cpu_cores = sys.cpus().len() as u8;
        
        // RAM information - Calculate based on total memory and max usage percentage
        let total_memory_kb = sys.total_memory();
        let memory_limit_kb = (total_memory_kb as f64 * (max_memory_usage as f64 / 100.0)) as u64;
        contrib.memory_mb = memory_limit_kb / 1024; // KB to MB conversion
        
        // Disk information - Calculate based on available space and max usage limit
        let mut total_available_mb = 0;
        for disk in sys.disks() {
            total_available_mb += disk.available_space() / (1024 * 1024); // Bytes to MB conversion
        }
        
        contrib.storage_mb = std::cmp::min(total_available_mb, max_storage_usage);
        
        // Bandwidth estimation (a more complex method would be needed for actual measurement)
        // For now, we assume 10 Mbps (10000 Kbps), real testing to be added later
        contrib.bandwidth_kbps = 10000;
    }
    
    /// Check for GPU information (if available)
    pub fn check_gpu(&self) -> Option<String> {
        // This function can be extended, currently provides basic GPU detection
        #[cfg(target_os = "linux")]
        {
            // Try running lspci command on Linux
            if let Ok(output) = std::process::Command::new("lspci").output() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains("VGA") || output_str.contains("3D") {
                    // Filter lines that contain GPU information
                    for line in output_str.lines() {
                        if line.contains("VGA") || line.contains("3D") {
                            return Some(line.trim().to_string());
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // WMI usage should be added for Windows (more complex)
            // For now we return a simple message
            return Some("GPU detection not implemented for Windows yet".to_string());
        }
        
        #[cfg(target_os = "macos")]
        {
            // Use system profiler for macOS
            if let Ok(output) = std::process::Command::new("system_profiler")
                .arg("SPDisplaysDataType")
                .output() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                return Some(output_str.to_string());
            }
        }
        
        None
    }
}