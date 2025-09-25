use anyhow::{Context, Result};
use log::{debug, error, warn};
use procfs::net::{TcpNetEntry, UdpNetEntry};
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};

use crate::{EventType, SecurityEvent, EventDetails, Severity};
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::Utc;

pub struct NetworkMonitor {
    event_sender: broadcast::Sender<SecurityEvent>,
    known_connections: HashSet<SocketAddr>,
    poll_interval: Duration,
}

impl NetworkMonitor {
    pub fn new(event_sender: broadcast::Sender<SecurityEvent>) -> Self {
        Self {
            event_sender,
            known_connections: HashSet::new(),
            poll_interval: Duration::from_secs(2),
        }
    }

    pub async fn start_monitoring(&mut self) -> Result<()> {
        let mut interval_timer = interval(self.poll_interval);

        // Initialize with current connections to avoid spam on startup
        if let Err(e) = self.initialize_known_connections().await {
            error!("Failed to initialize network connections: {}", e);
        }

        loop {
            interval_timer.tick().await;

            if let Err(e) = self.check_new_connections().await {
                error!("Error checking network connections: {}", e);
            }
        }
    }

    async fn initialize_known_connections(&mut self) -> Result<()> {
        // Get current TCP connections
        if let Ok(tcp_entries) = procfs::net::tcp() {
            for entry in tcp_entries {
                self.known_connections.insert(entry.remote_address);
            }
        }

        // Get current TCP6 connections
        if let Ok(tcp6_entries) = procfs::net::tcp6() {
            for entry in tcp6_entries {
                self.known_connections.insert(entry.remote_address);
            }
        }

        debug!("Initialized with {} known connections", self.known_connections.len());
        Ok(())
    }

    async fn check_new_connections(&mut self) -> Result<()> {
        let mut current_connections = HashSet::new();

        // Check TCP connections
        if let Ok(tcp_entries) = procfs::net::tcp() {
            for entry in tcp_entries {
                let remote_addr = entry.remote_address;
                current_connections.insert(remote_addr);

                if !self.known_connections.contains(&remote_addr) && !remote_addr.ip().is_loopback() {
                    self.emit_network_event(&entry, "TCP").await;
                }
            }
        }

        // Check TCP6 connections
        if let Ok(tcp6_entries) = procfs::net::tcp6() {
            for entry in tcp6_entries {
                let remote_addr = entry.remote_address;
                current_connections.insert(remote_addr);

                if !self.known_connections.contains(&remote_addr) && !remote_addr.ip().is_loopback() {
                    self.emit_network_event(&entry, "TCP6").await;
                }
            }
        }

        // Update known connections
        self.known_connections = current_connections;
        Ok(())
    }

    async fn emit_network_event(&self, entry: &TcpNetEntry, protocol: &str) {
        let severity = self.classify_connection_severity(&entry.remote_address.to_string());

        let mut metadata = HashMap::new();
        metadata.insert("protocol".to_string(), protocol.to_string());
        metadata.insert("local_address".to_string(), entry.local_address.to_string());
        metadata.insert("remote_address".to_string(), entry.remote_address.to_string());
        metadata.insert("state".to_string(), format!("{:?}", entry.state));

        metadata.insert("inode".to_string(), entry.inode.to_string());

        let event = SecurityEvent {
            timestamp: Utc::now(),
            event_type: EventType::NetworkConnection,
            path: PathBuf::from("/proc/net/tcp"),
            details: EventDetails {
                severity,
                description: format!("New {} connection to {}", protocol, entry.remote_address),
                metadata,
            },
        };

        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send network event: {}", e);
        }
    }

    fn classify_connection_severity(&self, remote_addr: &str) -> Severity {
        if let Ok(socket_addr) = remote_addr.parse::<SocketAddr>() {
            let ip = socket_addr.ip();

            // Local connections are low severity
            if ip.is_loopback() {
                return Severity::Low;
            }

            // Private network ranges are medium severity
            match ip {
                std::net::IpAddr::V4(ipv4) if ipv4.is_private() => return Severity::Medium,
                std::net::IpAddr::V6(ipv6) if ipv6.is_loopback() => return Severity::Low,
                _ => {}
            }

            // Public internet connections are higher severity
            // Check for known suspicious ports or patterns
            let port = socket_addr.port();
            match port {
                22 => Severity::High,     // SSH
                443 | 80 => Severity::Low, // HTTPS/HTTP (common)
                21 | 23 => Severity::High, // FTP/Telnet
                3389 => Severity::High,    // RDP
                _ if port < 1024 => Severity::Medium, // System ports
                _ => Severity::Low,
            }
        } else {
            Severity::Low
        }
    }
}