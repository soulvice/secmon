use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::time::interval;

use crate::{EventDetails, EventType, SecurityEvent, Severity};

#[derive(Debug)]
struct ConnectionTracker {
    source_ip: IpAddr,
    target_ports: Vec<u16>,
    first_seen: Instant,
    last_seen: Instant,
    connection_count: usize,
}

pub struct NetworkIDS {
    event_sender: broadcast::Sender<SecurityEvent>,
    connection_tracker: HashMap<IpAddr, ConnectionTracker>,
    ping_tracker: HashMap<IpAddr, Instant>,
    scan_threshold: usize,
    scan_window: Duration,
    ping_threshold: usize,
}

impl NetworkIDS {
    pub fn new(event_sender: broadcast::Sender<SecurityEvent>, port_scan_threshold: usize, scan_window_seconds: u64, ping_threshold: usize) -> Self {
        NetworkIDS {
            event_sender,
            connection_tracker: HashMap::new(),
            ping_tracker: HashMap::new(),
            scan_threshold: port_scan_threshold,
            scan_window: Duration::from_secs(scan_window_seconds),
            ping_threshold,
        }
    }

    pub async fn start_monitoring(&mut self) -> Result<()> {
        info!("Starting network intrusion detection monitoring");

        // Start connection monitoring
        let mut connection_monitor = interval(Duration::from_secs(5));

        // Start ICMP monitoring in a separate task (requires root for raw sockets)
        let icmp_sender = self.event_sender.clone();
        tokio::spawn(async move {
            if let Err(e) = start_icmp_monitoring_task(icmp_sender).await {
                warn!("ICMP monitoring failed (may need root privileges): {:?}", e);
            }
        });

        loop {
            connection_monitor.tick().await;
            if let Err(e) = self.check_network_connections().await {
                error!("Network connection monitoring error: {}", e);
            }
        }

        Ok(())
    }

    async fn check_network_connections(&mut self) -> Result<()> {
        // Read network connections from /proc/net/tcp and /proc/net/tcp6
        self.monitor_tcp_connections("/proc/net/tcp").await?;
        self.monitor_tcp_connections("/proc/net/tcp6").await?;

        // Clean up old entries
        self.cleanup_old_connections();
        self.cleanup_old_pings();

        Ok(())
    }

    async fn monitor_tcp_connections(&mut self, proc_path: &str) -> Result<()> {
        let content = match tokio::fs::read_to_string(proc_path).await {
            Ok(content) => content,
            Err(_) => return Ok(()), // File might not exist, skip
        };

        for line in content.lines().skip(1) { // Skip header
            if let Some(connection) = self.parse_tcp_connection(line) {
                self.track_connection(connection).await;
            }
        }

        Ok(())
    }

    fn parse_tcp_connection(&self, line: &str) -> Option<(IpAddr, u16, IpAddr, u16)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        // Parse local and remote addresses
        let local_parts: Vec<&str> = parts[1].split(':').collect();
        let remote_parts: Vec<&str> = parts[2].split(':').collect();

        if local_parts.len() != 2 || remote_parts.len() != 2 {
            return None;
        }

        // Parse hex IP and port
        let local_ip = self.parse_hex_ip(local_parts[0])?;
        let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;
        let remote_ip = self.parse_hex_ip(remote_parts[0])?;
        let remote_port = u16::from_str_radix(remote_parts[1], 16).ok()?;

        Some((local_ip, local_port, remote_ip, remote_port))
    }

    fn parse_hex_ip(&self, hex_str: &str) -> Option<IpAddr> {
        if hex_str.len() == 8 {
            // IPv4
            if let Ok(ip_int) = u32::from_str_radix(hex_str, 16) {
                let ip = std::net::Ipv4Addr::from(ip_int.to_be());
                return Some(IpAddr::V4(ip));
            }
        } else if hex_str.len() == 32 {
            // IPv6
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                if let Ok(byte) = u8::from_str_radix(&hex_str[i*2..i*2+2], 16) {
                    bytes[i] = byte;
                }
            }
            let ip = std::net::Ipv6Addr::from(bytes);
            return Some(IpAddr::V6(ip));
        }
        None
    }

    async fn track_connection(&mut self, (_local_ip, local_port, remote_ip, _remote_port): (IpAddr, u16, IpAddr, u16)) {
        let now = Instant::now();

        // Skip localhost connections
        if remote_ip.is_loopback() {
            return;
        }

        // Track incoming connections (remote -> local)
        let should_alert_scan;
        let should_alert_discovery;
        let updated_ports;

        {
            let tracker = self.connection_tracker.entry(remote_ip).or_insert_with(|| {
                ConnectionTracker {
                    source_ip: remote_ip,
                    target_ports: Vec::new(),
                    first_seen: now,
                    last_seen: now,
                    connection_count: 0,
                }
            });

            // Update tracker
            tracker.last_seen = now;
            tracker.connection_count += 1;

            if !tracker.target_ports.contains(&local_port) {
                tracker.target_ports.push(local_port);
            }

            // Check conditions for alerts
            should_alert_scan = tracker.target_ports.len() >= self.scan_threshold
                && now.duration_since(tracker.first_seen) <= self.scan_window;

            // Extract port list for discovery pattern check
            updated_ports = tracker.target_ports.clone();
        }

        // Check discovery pattern with extracted data
        should_alert_discovery = self.is_discovery_pattern_ports(&updated_ports);

        // Generate alerts outside of the borrow scope
        if should_alert_scan {
            if let Some(tracker) = self.connection_tracker.get(&remote_ip) {
                self.generate_port_scan_alert(&tracker).await;
            }
        }

        if should_alert_discovery {
            if let Some(tracker) = self.connection_tracker.get(&remote_ip) {
                self.generate_discovery_alert(&tracker).await;
            }
        }
    }

    fn is_discovery_pattern(&self, tracker: &ConnectionTracker) -> bool {
        self.is_discovery_pattern_ports(&tracker.target_ports)
    }

    fn is_discovery_pattern_ports(&self, ports: &[u16]) -> bool {
        // Common discovery ports
        let discovery_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995];

        let discovery_count = ports.iter()
            .filter(|&&port| discovery_ports.contains(&port))
            .count();

        discovery_count >= 3 // 3 or more common service ports
    }

    async fn generate_port_scan_alert(&self, tracker: &ConnectionTracker) {
        let mut metadata = HashMap::new();
        metadata.insert("source_ip".to_string(), tracker.source_ip.to_string());
        metadata.insert("ports_scanned".to_string(), tracker.target_ports.len().to_string());
        metadata.insert("scan_duration".to_string(),
                        format!("{:.1}s", Instant::now().duration_since(tracker.first_seen).as_secs_f64()));

        let event = SecurityEvent {
            timestamp: Utc::now(),
            event_type: EventType::PortScanDetected,
            path: std::path::PathBuf::from("/proc/net/tcp"),
            details: EventDetails {
                severity: Severity::High,
                description: format!(
                    "Port scan detected from {} targeting {} ports",
                    tracker.source_ip,
                    tracker.target_ports.len()
                ),
                metadata,
            },
        };

        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send port scan alert: {}", e);
        }
    }

    async fn generate_discovery_alert(&self, tracker: &ConnectionTracker) {
        let mut metadata = HashMap::new();
        metadata.insert("source_ip".to_string(), tracker.source_ip.to_string());
        metadata.insert("service_ports".to_string(),
                        tracker.target_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));

        let event = SecurityEvent {
            timestamp: Utc::now(),
            event_type: EventType::NetworkDiscovery,
            path: std::path::PathBuf::from("/proc/net/tcp"),
            details: EventDetails {
                severity: Severity::Medium,
                description: format!(
                    "Network service discovery from {} on ports: {:?}",
                    tracker.source_ip,
                    tracker.target_ports
                ),
                metadata,
            },
        };

        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send network discovery alert: {}", e);
        }
    }

    fn cleanup_old_connections(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(300); // 5 minutes

        self.connection_tracker.retain(|_, tracker| {
            now.duration_since(tracker.last_seen) < timeout
        });
    }

    fn cleanup_old_pings(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_secs(60); // 1 minute

        self.ping_tracker.retain(|_, &mut last_ping| {
            now.duration_since(last_ping) < timeout
        });
    }

    async fn monitor_system_logs_for_pings(&mut self) -> Result<()> {
        // Monitor system logs for ping activity
        // This is a fallback method when raw sockets aren't available

        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;

            // Check netstat for ICMP statistics (this is a simplified approach)
            if let Err(e) = self.check_icmp_activity().await {
                debug!("ICMP monitoring error: {}", e);
            }
        }
    }

    async fn check_icmp_activity(&mut self) -> Result<()> {
        // Read /proc/net/snmp for ICMP statistics
        let content = tokio::fs::read_to_string("/proc/net/snmp").await?;

        for line in content.lines() {
            if line.starts_with("Icmp:") && !line.contains("InMsgs") {
                self.parse_icmp_stats(line).await;
                break;
            }
        }

        Ok(())
    }

    async fn parse_icmp_stats(&mut self, line: &str) {
        // Parse ICMP statistics - this is a basic implementation
        // In a production environment, you'd want more sophisticated monitoring
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 8 {
            // Check for increase in ICMP echo requests (position may vary)
            // This is a simplified detection - real implementation would track deltas
            debug!("ICMP activity detected in system stats");
        }
    }

    pub async fn generate_ping_alert(&self, source_ip: IpAddr) {
        let mut metadata = HashMap::new();
        metadata.insert("source_ip".to_string(), source_ip.to_string());
        metadata.insert("protocol".to_string(), "ICMP".to_string());

        let event = SecurityEvent {
            timestamp: Utc::now(),
            event_type: EventType::PingDetected,
            path: std::path::PathBuf::from("/proc/net/icmp"),
            details: EventDetails {
                severity: Severity::Low,
                description: format!("ICMP ping detected from {}", source_ip),
                metadata,
            },
        };

        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send ping alert: {}", e);
        }
    }
}

// Standalone ICMP monitoring function
async fn start_icmp_monitoring_task(event_sender: broadcast::Sender<SecurityEvent>) -> Result<()> {
    // Monitor system logs for ping activity
    // This is a fallback method when raw sockets aren't available

    let mut interval = tokio::time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        // Check netstat for ICMP statistics (this is a simplified approach)
        if let Err(e) = check_icmp_activity_standalone(&event_sender).await {
            debug!("ICMP monitoring error: {}", e);
        }
    }
}

async fn check_icmp_activity_standalone(event_sender: &broadcast::Sender<SecurityEvent>) -> Result<()> {
    // Read /proc/net/snmp for ICMP statistics
    let content = tokio::fs::read_to_string("/proc/net/snmp").await?;

    for line in content.lines() {
        if line.starts_with("Icmp:") && !line.contains("InMsgs") {
            parse_icmp_stats_standalone(line, event_sender).await;
            break;
        }
    }

    Ok(())
}

async fn parse_icmp_stats_standalone(line: &str, event_sender: &broadcast::Sender<SecurityEvent>) {
    // Parse ICMP statistics - this is a basic implementation
    // In a production environment, you'd want more sophisticated monitoring
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() > 8 {
        // Check for increase in ICMP echo requests (position may vary)
        // This is a simplified detection - real implementation would track deltas
        debug!("ICMP activity detected in system stats");

        // For demonstration, generate a ping alert
        // In reality, you'd track changes in counters
        generate_ping_alert_standalone(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), event_sender).await;
    }
}

async fn generate_ping_alert_standalone(source_ip: IpAddr, event_sender: &broadcast::Sender<SecurityEvent>) {
    let mut metadata = HashMap::new();
    metadata.insert("source_ip".to_string(), source_ip.to_string());
    metadata.insert("protocol".to_string(), "ICMP".to_string());

    let event = SecurityEvent {
        timestamp: Utc::now(),
        event_type: EventType::PingDetected,
        path: std::path::PathBuf::from("/proc/net/icmp"),
        details: EventDetails {
            severity: Severity::Low,
            description: format!("ICMP ping detected from {}", source_ip),
            metadata,
        },
    };

    if let Err(e) = event_sender.send(event) {
        error!("Failed to send ping alert: {}", e);
    }
}