//! Settings for the Paraloom node

use crate::bridge::BridgeConfig;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Node settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    /// Network settings
    pub network: NetworkSettings,
    /// Node settings
    pub node: NodeSettings,
    /// Storage settings
    pub storage: StorageSettings,
    /// Coordinator high-availability settings. Optional: an
    /// existing TOML config without an `[ha]` section parses
    /// cleanly using `HaSettings::default()`, so the failover work
    /// in #66 stays opt-in until operators explicitly turn it on.
    #[serde(default)]
    pub ha: HaSettings,
    /// Solana bridge / deposit-listener settings. Optional like
    /// `[ha]`: a config without a `[bridge]` section parses using
    /// `BridgeConfig::default()`, which is env-var driven and leaves
    /// the bridge disabled unless `enabled = true`. When enabled on a
    /// validator- or bridge-class node, the node spawns the deposit
    /// `EventListener` and owns a `ShieldedPool` indexed from on-chain
    /// deposits (#163).
    #[serde(default)]
    pub bridge: BridgeConfig,
}

/// Network settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Listening address
    pub listen_address: String,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
}

/// Node settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSettings {
    /// Node type
    pub node_type: String,
    /// Maximum CPU usage in percentage
    pub max_cpu_usage: u8,
    /// Maximum memory usage in percentage
    pub max_memory_usage: u8,
    /// Maximum storage usage in MB
    pub max_storage_usage: u64,
}

/// Storage settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Path to data directory
    pub data_dir: String,
}

/// Coordinator high-availability settings.
///
/// Drives the failover work tracked in #66. Two roles are
/// expressible:
///
/// - **Primary** (the default when `primary` is `None`): if
///   `standbys` is non-empty, this node broadcasts heartbeats to
///   the listed standbys at `heartbeat_interval_ms` cadence.
/// - **Standby** (when `primary` is `Some(...)`): this node
///   constructs its coordinator in the Standby role mirroring the
///   given primary, runs the stall watchdog at
///   `watchdog_interval_ms`, and self-promotes after
///   `stall_threshold_ms` of silence.
///
/// All NodeId values are hex-encoded byte strings matching the
/// `Display` impl on `NodeId` (lowercase hex, no `0x` prefix).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HaSettings {
    /// Hex-encoded NodeId of the primary this node is mirroring.
    /// `None` means this node is itself a primary (or has no HA
    /// involvement at all).
    #[serde(default)]
    pub primary: Option<String>,

    /// Hex-encoded NodeIds of standbys this node should broadcast
    /// heartbeats to. Only meaningful when `primary` is `None`
    /// (i.e. this node is the primary).
    #[serde(default)]
    pub standbys: Vec<String>,

    /// Heartbeat broadcast cadence in milliseconds. Default 5s.
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u64,

    /// Standby self-promotes after this much silence in
    /// milliseconds. Default 30s; matches the under-30s RTO
    /// target in the #66 acceptance criteria.
    #[serde(default = "default_stall_threshold_ms")]
    pub stall_threshold_ms: u64,

    /// Standby watchdog poll interval in milliseconds. Should be
    /// substantially smaller than `stall_threshold_ms` so worst-
    /// case detection latency is one watchdog interval. Default
    /// 5s, giving a 6:1 ratio against the default stall threshold.
    #[serde(default = "default_watchdog_interval_ms")]
    pub watchdog_interval_ms: u64,
}

fn default_heartbeat_interval_ms() -> u64 {
    5_000
}

fn default_stall_threshold_ms() -> u64 {
    30_000
}

fn default_watchdog_interval_ms() -> u64 {
    5_000
}

impl Default for HaSettings {
    fn default() -> Self {
        Self {
            primary: None,
            standbys: Vec::new(),
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            stall_threshold_ms: default_stall_threshold_ms(),
            watchdog_interval_ms: default_watchdog_interval_ms(),
        }
    }
}

impl Settings {
    /// Load settings from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let settings = toml::from_str(&content)?;
        Ok(settings)
    }

    /// Create development settings
    pub fn development() -> Self {
        Settings {
            network: NetworkSettings {
                listen_address: "/ip4/127.0.0.1/tcp/0".to_string(),
                bootstrap_nodes: vec![],
                enable_mdns: true,
            },
            node: NodeSettings {
                node_type: "ResourceProvider".to_string(),
                max_cpu_usage: 80,
                max_memory_usage: 70,
                max_storage_usage: 10240, // 10 GB
            },
            storage: StorageSettings {
                data_dir: "./data".to_string(),
            },
            ha: HaSettings::default(),
            bridge: BridgeConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ha_settings_defaults_match_documented_values() {
        let ha = HaSettings::default();
        assert!(ha.primary.is_none());
        assert!(ha.standbys.is_empty());
        assert_eq!(ha.heartbeat_interval_ms, 5_000);
        assert_eq!(ha.stall_threshold_ms, 30_000);
        assert_eq!(ha.watchdog_interval_ms, 5_000);
    }

    #[test]
    fn settings_without_ha_section_parses_with_defaults() {
        // A pre-#66 TOML config has no `[ha]` table. The
        // `#[serde(default)]` on `Settings::ha` must let it parse
        // cleanly so we never break operators on upgrade.
        let toml_text = r#"
            [network]
            listen_address = "/ip4/127.0.0.1/tcp/0"
            bootstrap_nodes = []
            enable_mdns = false

            [node]
            node_type = "Coordinator"
            max_cpu_usage = 80
            max_memory_usage = 70
            max_storage_usage = 1024

            [storage]
            data_dir = "./data"
        "#;
        let settings: Settings = toml::from_str(toml_text).expect("parses without [ha]");
        assert!(settings.ha.primary.is_none());
        assert!(settings.ha.standbys.is_empty());
        assert_eq!(settings.ha.stall_threshold_ms, 30_000);
    }

    #[test]
    fn ha_settings_parse_partial_overrides() {
        // An operator who wants to tighten the stall threshold
        // alone should not have to repeat every default.
        let toml_text = r#"
            [network]
            listen_address = "/ip4/127.0.0.1/tcp/0"
            bootstrap_nodes = []
            enable_mdns = false

            [node]
            node_type = "Coordinator"
            max_cpu_usage = 80
            max_memory_usage = 70
            max_storage_usage = 1024

            [storage]
            data_dir = "./data"

            [ha]
            stall_threshold_ms = 10000
            standbys = ["aabb", "ccdd"]
        "#;
        let settings: Settings = toml::from_str(toml_text).expect("parses with partial [ha]");
        assert_eq!(settings.ha.stall_threshold_ms, 10_000);
        assert_eq!(settings.ha.heartbeat_interval_ms, 5_000); // default still
        assert_eq!(settings.ha.standbys.len(), 2);
        assert!(settings.ha.primary.is_none());
    }
}
