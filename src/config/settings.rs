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
    /// Confidential-compute authorization settings (F3). Optional like
    /// `[ha]`/`[bridge]`: a config without a `[compute]` section uses
    /// `ComputeSettings::default()`, which leaves job submission open to any
    /// peer while still bounding every job by the built-in per-job resource
    /// ceiling. Set `authorized_submitters` to restrict who may submit.
    #[serde(default)]
    pub compute: ComputeSettings,
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
    /// Run a circuit-relay v2 *server* on this node (#226). A public,
    /// dialable node (the bootstrap anchor) sets this `true` so peers
    /// behind a NAT can reserve a relay slot and become reachable
    /// through it. Leave `false` on NATed validators — they have
    /// nothing to relay and gain only attack surface by accepting
    /// reservations. Optional in TOML: defaults to the
    /// `ENABLE_RELAY_SERVER` env var (parsed as bool) and otherwise
    /// `false`, mirroring the `[bridge] enabled` pattern so existing
    /// configs upgrade without edits.
    #[serde(default = "default_enable_relay_server")]
    pub enable_relay_server: bool,
    /// This node's own publicly-reachable multiaddr, if it has one
    /// (#226). Declared as a confirmed external address at startup.
    /// Set this on a relay server (the anchor): a reservation it
    /// grants a NATed peer carries only the relay's external
    /// addresses, so without one the peer cannot build a usable
    /// `/p2p-circuit` listen address. Typically the node's public
    /// `listen_address` with the real IP, e.g.
    /// `/ip4/203.0.113.5/tcp/9300`. `None` (default) leaves address
    /// discovery to AutoNAT.
    #[serde(default)]
    pub external_address: Option<String>,
    /// Multiaddr of a circuit-relay v2 *server* to reserve a slot on
    /// (#226). Set this on a node that sits behind a NAT: the node
    /// dials the relay and listens on the relay's `/p2p-circuit`
    /// address so peers can reach it through the relay even though no
    /// inbound dial to the node itself can land. Must include the
    /// relay's `/p2p/<peer_id>` suffix. `None` (the default) means no
    /// relay reservation — correct for a publicly dialable node.
    /// Harmless to set on a public node: the reservation simply goes
    /// unused.
    #[serde(default)]
    pub relay_address: Option<String>,
    /// Path to a libp2p identity key (protobuf-encoded). When set, the
    /// network manager loads the keypair from this file on startup so the
    /// PeerId is stable across restarts; if the file is missing, a fresh
    /// ed25519 keypair is generated and persisted to the path. Required for
    /// any node whose multiaddr is published (bootstrap anchors, named
    /// validators) — without it every restart rotates the PeerId, breaking
    /// any `/p2p/<peerid>` reference others rely on.
    #[serde(default)]
    pub identity_path: Option<String>,
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

/// Confidential-compute authorization settings (F3). Optional like `[ha]`: an
/// absent `[compute]` section leaves submission open with the built-in ceiling.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ComputeSettings {
    /// Hex-encoded NodeIds (lowercase, matching `NodeId`'s Display form)
    /// permitted to submit compute jobs. Empty (the default) leaves submission
    /// open to any peer; a non-empty list restricts submission to exactly these
    /// peers. An entry that is not valid hex is ignored at startup.
    #[serde(default)]
    pub authorized_submitters: Vec<String>,
    /// Per-job memory ceiling in bytes. `None` uses the built-in default.
    #[serde(default)]
    pub max_memory_bytes: Option<u64>,
    /// Per-job instruction (fuel) ceiling. `None` uses the built-in default.
    #[serde(default)]
    pub max_instructions: Option<u64>,
    /// Per-job timeout ceiling in seconds. `None` uses the built-in default.
    #[serde(default)]
    pub max_timeout_secs: Option<u64>,
}

/// Default for [`NetworkSettings::enable_relay_server`]. Reads the
/// `ENABLE_RELAY_SERVER` env var (parsed as bool) so the anchor can
/// flip relay on without a config edit, falling back to `false`.
fn default_enable_relay_server() -> bool {
    std::env::var("ENABLE_RELAY_SERVER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(false)
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
                enable_relay_server: false,
                external_address: None,
                relay_address: None,
                identity_path: None,
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
            compute: ComputeSettings::default(),
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
        // No `[compute]` section → open submission with built-in ceiling.
        assert!(settings.compute.authorized_submitters.is_empty());
        assert!(settings.compute.max_memory_bytes.is_none());
    }

    #[test]
    fn compute_settings_parse_an_allowlist_and_ceiling_override() {
        let toml_text = r#"
            [network]
            listen_address = "/ip4/127.0.0.1/tcp/0"
            bootstrap_nodes = []
            enable_mdns = false

            [node]
            node_type = "ResourceProvider"
            max_cpu_usage = 80
            max_memory_usage = 70
            max_storage_usage = 1024

            [storage]
            data_dir = "./data"

            [compute]
            authorized_submitters = ["aabb", "ccdd"]
            max_memory_bytes = 134217728
        "#;
        let settings: Settings = toml::from_str(toml_text).expect("parses [compute]");
        assert_eq!(
            settings.compute.authorized_submitters,
            vec!["aabb".to_string(), "ccdd".to_string()]
        );
        assert_eq!(settings.compute.max_memory_bytes, Some(134_217_728));
        assert!(settings.compute.max_instructions.is_none());
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

    #[test]
    fn network_without_relay_field_defaults_off() {
        // A pre-#226 `[network]` table has no `enable_relay_server`
        // key. The `#[serde(default = ...)]` must let it parse and
        // leave relay-server off, so existing validator configs
        // upgrade without edits and don't accidentally start relaying.
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
        let settings: Settings = toml::from_str(toml_text).expect("parses without relay field");
        assert!(
            !settings.network.enable_relay_server,
            "relay server must default off"
        );
    }

    #[test]
    fn network_relay_field_parses_when_set() {
        // A public anchor opts in explicitly; the flag round-trips.
        let toml_text = r#"
            [network]
            listen_address = "/ip4/0.0.0.0/tcp/9300"
            bootstrap_nodes = []
            enable_mdns = false
            enable_relay_server = true

            [node]
            node_type = "Coordinator"
            max_cpu_usage = 80
            max_memory_usage = 70
            max_storage_usage = 1024

            [storage]
            data_dir = "./data"
        "#;
        let settings: Settings = toml::from_str(toml_text).expect("parses with relay field");
        assert!(settings.network.enable_relay_server);
    }

    #[test]
    fn relay_client_fields_default_none_and_round_trip() {
        // The relay *client* fields (#226 PR-B) are optional. A config
        // without them leaves both None; a NATed node opts in by
        // setting relay_address, and a relay server declares its public
        // multiaddr via external_address.
        let bare = r#"
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
        let s: Settings = toml::from_str(bare).expect("parses without relay-client fields");
        assert!(s.network.relay_address.is_none());
        assert!(s.network.external_address.is_none());

        let configured = r#"
            [network]
            listen_address = "/ip4/0.0.0.0/tcp/9300"
            bootstrap_nodes = []
            enable_mdns = false
            external_address = "/ip4/203.0.113.5/tcp/9300"
            relay_address = "/ip4/203.0.113.5/tcp/9300/p2p/12D3KooWtest"

            [node]
            node_type = "Coordinator"
            max_cpu_usage = 80
            max_memory_usage = 70
            max_storage_usage = 1024

            [storage]
            data_dir = "./data"
        "#;
        let s: Settings = toml::from_str(configured).expect("parses with relay-client fields");
        assert_eq!(
            s.network.external_address.as_deref(),
            Some("/ip4/203.0.113.5/tcp/9300")
        );
        assert_eq!(
            s.network.relay_address.as_deref(),
            Some("/ip4/203.0.113.5/tcp/9300/p2p/12D3KooWtest")
        );
    }
}
