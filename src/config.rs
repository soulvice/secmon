use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub socket_path: String,
    pub log_level: String,
    pub watches: Vec<WatchConfig>,
    #[serde(default)]
    pub notifications: NotificationConfig,
    #[serde(default)]
    pub triggers: Vec<EventTrigger>,
    #[serde(default)]
    pub network_ids: NetworkIDSConfig,
    #[serde(default)]
    pub display_local_time: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIDSConfig {
    pub enabled: bool,
    pub port_scan_threshold: usize,
    pub scan_window_seconds: u64,
    pub ping_threshold: usize,
    pub monitor_icmp: bool,
    pub alert_on_discovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    pub path: String,
    pub description: String,
    pub enabled: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub pattern: bool, // If true, treat path as a glob pattern
    #[serde(default)]
    pub auto_discover: bool, // If true, automatically discover devices
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub dbus_enabled: bool,
    pub min_severity: String, // "Low", "Medium", "High", "Critical"
    pub timeout_ms: u32, // Notification timeout in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTrigger {
    pub name: String,
    pub enabled: bool,
    pub event_types: Vec<String>, // ["CameraAccess", "SshAccess", etc.]
    pub min_severity: String,
    pub command: String, // Command to execute
    pub args: Vec<String>, // Command arguments
    #[serde(default)]
    pub run_async: bool, // Don't wait for command completion
    #[serde(default)]
    pub cooldown_seconds: u64, // Minimum time between executions
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dbus_enabled: true,
            min_severity: "Medium".to_string(),
            timeout_ms: 5000,
        }
    }
}

impl Default for NetworkIDSConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port_scan_threshold: 10,        // Alert after 10+ ports scanned
            scan_window_seconds: 60,        // Within 60 seconds
            ping_threshold: 5,              // Alert after 5+ pings in short time
            monitor_icmp: false,            // Disabled by default (requires root)
            alert_on_discovery: true,       // Alert on network discovery attempts
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let socket_path = std::env::var("XDG_RUNTIME_DIR")
            .map(|dir| format!("{}/secmon.sock", dir))
            .unwrap_or_else(|_| format!("/tmp/secmon-{}.sock", std::env::var("USER").unwrap_or_else(|_| "user".to_string())));

        Self {
            socket_path,
            log_level: "info".to_string(),
            notifications: NotificationConfig::default(),
            display_local_time: true,
            triggers: vec![
                EventTrigger {
                    name: "Camera Access Alert".to_string(),
                    enabled: true,
                    event_types: vec!["CameraAccess".to_string()],
                    min_severity: "High".to_string(),
                    command: "notify-send".to_string(),
                    args: vec![
                        "-u".to_string(),
                        "critical".to_string(),
                        "Security Alert".to_string(),
                        "Camera access detected!".to_string(),
                    ],
                    run_async: true,
                    cooldown_seconds: 5,
                },
                EventTrigger {
                    name: "SSH Access Alert".to_string(),
                    enabled: true,
                    event_types: vec!["SshAccess".to_string()],
                    min_severity: "Critical".to_string(),
                    command: "notify-send".to_string(),
                    args: vec![
                        "-u".to_string(),
                        "critical".to_string(),
                        "Security Alert".to_string(),
                        "SSH key access detected!".to_string(),
                    ],
                    run_async: true,
                    cooldown_seconds: 10,
                },
                EventTrigger {
                    name: "Port Scan Alert".to_string(),
                    enabled: true,
                    event_types: vec!["PortScanDetected".to_string()],
                    min_severity: "High".to_string(),
                    command: "notify-send".to_string(),
                    args: vec![
                        "-u".to_string(),
                        "critical".to_string(),
                        "Security Alert".to_string(),
                        "Port scan detected from external source!".to_string(),
                    ],
                    run_async: true,
                    cooldown_seconds: 30,
                },
                EventTrigger {
                    name: "Network Discovery Alert".to_string(),
                    enabled: true,
                    event_types: vec!["NetworkDiscovery".to_string()],
                    min_severity: "Medium".to_string(),
                    command: "logger".to_string(),
                    args: vec![
                        "-p".to_string(),
                        "security.warning".to_string(),
                        "Network discovery attempt detected".to_string(),
                    ],
                    run_async: true,
                    cooldown_seconds: 60,
                },
            ],
            watches: vec![
                // Auto-discover all camera devices
                WatchConfig {
                    path: "/dev/video*".to_string(),
                    description: "All camera/video devices (auto-discovered)".to_string(),
                    enabled: true,
                    recursive: false,
                    pattern: true,
                    auto_discover: true,
                },
                // Auto-discover all microphone/audio devices
                WatchConfig {
                    path: "/dev/snd/*".to_string(),
                    description: "All ALSA audio devices (auto-discovered)".to_string(),
                    enabled: true,
                    recursive: true,
                    pattern: true,
                    auto_discover: true,
                },
                WatchConfig {
                    path: "/tmp/.pulse*".to_string(),
                    description: "PulseAudio devices (auto-discovered)".to_string(),
                    enabled: true,
                    recursive: true,
                    pattern: true,
                    auto_discover: true,
                },
                WatchConfig {
                    path: "/run/user/*/pulse".to_string(),
                    description: "User PulseAudio runtime directories".to_string(),
                    enabled: true,
                    recursive: true,
                    pattern: true,
                    auto_discover: true,
                },
                // SSH monitoring
                WatchConfig {
                    path: "/home".to_string(),
                    description: "Home directories for SSH key monitoring".to_string(),
                    enabled: true,
                    recursive: true,
                    pattern: false,
                    auto_discover: false,
                },
                WatchConfig {
                    path: "/etc/ssh".to_string(),
                    description: "SSH daemon configuration".to_string(),
                    enabled: true,
                    recursive: true,
                    pattern: false,
                    auto_discover: false,
                },
                WatchConfig {
                    path: "/var/log/auth.log".to_string(),
                    description: "SSH authentication logs".to_string(),
                    enabled: true,
                    recursive: false,
                    pattern: false,
                    auto_discover: false,
                },
            ],
            network_ids: NetworkIDSConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        if !std::path::Path::new(path).exists() {
            println!("Config file not found, creating default at: {}", path);
            let config = Self::default();
            config.save(path)?;
            return Ok(config);
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))?;

        Ok(config)
    }

    pub fn save(&self, path: &str) -> Result<()> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path))?;

        Ok(())
    }
}