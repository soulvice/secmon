use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use chrono::{DateTime, Utc};
use log::{info, error, warn};
use std::os::unix::fs::FileTypeExt;

// For daemon control
extern crate libc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub path: PathBuf,
    pub details: EventDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventType {
    FileAccess,
    FileModify,
    FileCreate,
    FileDelete,
    DirectoryAccess,
    CameraAccess,
    SshAccess,
    MicrophoneAccess,
    NetworkConnection,
    UsbDeviceInserted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetails {
    pub severity: Severity,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_client_help();
        return Ok(());
    }

    let command = &args[1];
    match command.as_str() {
        "start" => {
            let config_path = args.get(2).cloned();
            daemon_start(config_path).await
        }
        "stop" => {
            daemon_stop().await
        }
        "restart" => {
            let config_path = args.get(2).cloned();
            daemon_restart(config_path).await
        }
        "status" => {
            daemon_status().await
        }
        "logs" => {
            let lines = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
            daemon_logs(lines).await
        }
        "monitor" => {
            let mut socket_path = "/tmp/secmon.sock".to_string();
            let mut json_mode = false;
            let mut filter_severity: Option<Severity> = None;

            // Parse arguments starting from index 2
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--json" | "-j" => json_mode = true,
                    "--severity-low" => filter_severity = Some(Severity::Low),
                    "--severity-medium" => filter_severity = Some(Severity::Medium),
                    "--severity-high" => filter_severity = Some(Severity::High),
                    "--severity-critical" => filter_severity = Some(Severity::Critical),
                    arg if !arg.starts_with("--") && !arg.starts_with("-") => {
                        // This is the socket path
                        socket_path = arg.to_string();
                    }
                    _ => {}
                }
                i += 1;
            }

            monitor_events(&socket_path, json_mode, filter_severity).await
        }
        "--help" | "-h" => {
            print_client_help();
            Ok(())
        }
        _ => {
            // Backward compatibility: if first arg looks like a socket path, use old behavior
            if command.starts_with('/') || command.starts_with('.') {
                monitor_events(command, false, None).await
            } else {
                eprintln!("Error: Unknown command '{}'", command);
                print_client_help();
                std::process::exit(1);
            }
        }
    }
}

fn print_client_help() {
    println!("secmon-client - Security Monitor Client");
    println!();
    println!("USAGE:");
    println!("    secmon-client <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    start [CONFIG]     Start the daemon");
    println!("    stop               Stop the daemon");
    println!("    restart [CONFIG]   Restart the daemon");
    println!("    status             Show daemon status");
    println!("    logs [LINES]       Show daemon logs (default: 50 lines)");
    println!("    monitor [SOCKET] [--json]  Monitor security events (default: /tmp/secmon.sock)");
    println!("    help, --help, -h   Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    secmon-client start                    # Start daemon with default config");
    println!("    secmon-client start /path/config.toml  # Start with custom config");
    println!("    secmon-client stop                     # Stop the daemon");
    println!("    secmon-client status                   # Check daemon status");
    println!("    secmon-client logs                     # Show last 50 log lines");
    println!("    secmon-client logs 100                 # Show last 100 log lines");
    println!("    secmon-client monitor                  # Monitor events (human readable)");
    println!("    secmon-client monitor /tmp/secmon.sock --json  # Monitor events (JSON output)");
}

async fn monitor_events(socket_path: &str, json_mode: bool, filter_severity: Option<Severity>) -> Result<()> {
    info!("Connecting to secmon daemon at: {}", socket_path);

    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("Failed to connect to socket: {}", socket_path))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    if json_mode {
        info!("Connected! Streaming JSON events...");
        // In JSON mode, output events directly without headers
    } else {
        info!("Connected! Listening for security events...");
        println!("Timestamp | Severity | Type | Path | Description");
        println!("---------|----------|------|------|-------------");
    }

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("Connection closed by daemon");
                break;
            }
            Ok(_) => {
                match serde_json::from_str::<SecurityEvent>(&line.trim()) {
                    Ok(event) => {
                        // Apply severity filter if specified
                        if let Some(min_severity) = &filter_severity {
                            let event_severity_level = match event.details.severity {
                                Severity::Low => 1,
                                Severity::Medium => 2,
                                Severity::High => 3,
                                Severity::Critical => 4,
                            };
                            let min_severity_level = match min_severity {
                                Severity::Low => 1,
                                Severity::Medium => 2,
                                Severity::High => 3,
                                Severity::Critical => 4,
                            };

                            // Skip events below the minimum severity
                            if event_severity_level < min_severity_level {
                                continue;
                            }
                        }

                        if json_mode {
                            handle_json_event(&event);
                        } else {
                            handle_security_event(&event);
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse event: {} - Line: {}", e, line.trim());
                    }
                }
            }
            Err(e) => {
                error!("Failed to read from socket: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn daemon_start(config_path: Option<String>) -> Result<()> {
    // Check if daemon is already running
    if is_daemon_running().await? {
        println!("Daemon is already running");
        return Ok(());
    }

    // Build command to start daemon
    let daemon_path = get_daemon_path()?;
    let mut cmd = std::process::Command::new(&daemon_path);
    cmd.arg("--daemon");

    if let Some(config) = config_path {
        cmd.arg(config);
    }

    println!("Starting secmon daemon...");
    match cmd.spawn() {
        Ok(mut child) => {
            // Wait a moment to see if it started successfully
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

            if let Ok(Some(status)) = child.try_wait() {
                if !status.success() {
                    eprintln!("Failed to start daemon (exit code: {})", status.code().unwrap_or(-1));
                    return Err(anyhow::anyhow!("Daemon startup failed"));
                }
            }

            // Check if it's actually running
            if is_daemon_running().await? {
                println!("Daemon started successfully");
            } else {
                eprintln!("Daemon may have failed to start properly");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to start daemon: {}", e);
            Err(anyhow::anyhow!("Failed to start daemon: {}", e))
        }
    }
}

async fn daemon_stop() -> Result<()> {
    let pid = match read_daemon_pid().await? {
        Some(pid) => pid,
        None => {
            println!("Daemon is not running");
            return Ok(());
        }
    };

    println!("Stopping secmon daemon (PID: {})...", pid);

    // Send SIGTERM
    unsafe {
        if libc::kill(pid as i32, libc::SIGTERM) == 0 {
            // Wait for daemon to stop
            for _ in 0..30 {  // Wait up to 3 seconds
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !is_daemon_running().await? {
                    println!("Daemon stopped successfully");
                    return Ok(());
                }
            }

            // If still running, force kill
            eprintln!("Daemon didn't stop gracefully, forcing termination...");
            if libc::kill(pid as i32, libc::SIGKILL) == 0 {
                println!("Daemon force-stopped");
            } else {
                eprintln!("Failed to force-stop daemon");
            }
        } else {
            eprintln!("Failed to send stop signal to daemon");
        }
    }

    Ok(())
}

async fn daemon_restart(config_path: Option<String>) -> Result<()> {
    println!("Restarting secmon daemon...");
    daemon_stop().await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    daemon_start(config_path).await
}

async fn daemon_status() -> Result<()> {
    match read_daemon_pid().await? {
        Some(pid) => {
            if is_process_running(pid) {
                println!("Daemon is running (PID: {})", pid);

                // Show additional info if available
                if let Ok(socket_exists) = tokio::fs::metadata("/tmp/secmon.sock").await {
                    if socket_exists.file_type().is_socket() {
                        println!("Socket: /tmp/secmon.sock (active)");
                    }
                } else {
                    println!("Socket: /tmp/secmon.sock (not found)");
                }

                if let Ok(log_metadata) = tokio::fs::metadata("/tmp/secmon.log").await {
                    println!("Log file: /tmp/secmon.log ({} bytes)", log_metadata.len());
                }
            } else {
                println!("Daemon is not running (stale PID file)");
                // Clean up stale PID file
                let _ = tokio::fs::remove_file("/tmp/secmon.pid").await;
            }
        }
        None => {
            println!("Daemon is not running");
        }
    }
    Ok(())
}

async fn daemon_logs(lines: usize) -> Result<()> {
    let log_path = "/tmp/secmon.log";

    match tokio::fs::read_to_string(log_path).await {
        Ok(content) => {
            let log_lines: Vec<&str> = content.lines().collect();
            let start_line = if log_lines.len() > lines {
                log_lines.len() - lines
            } else {
                0
            };

            println!("Last {} lines from {}:", lines, log_path);
            println!("----------------------------------------");
            for line in &log_lines[start_line..] {
                println!("{}", line);
            }
        }
        Err(e) => {
            eprintln!("Failed to read log file {}: {}", log_path, e);
            eprintln!("Make sure the daemon is running in daemon mode");
        }
    }
    Ok(())
}

async fn is_daemon_running() -> Result<bool> {
    match read_daemon_pid().await? {
        Some(pid) => Ok(is_process_running(pid)),
        None => Ok(false),
    }
}

async fn read_daemon_pid() -> Result<Option<u32>> {
    match tokio::fs::read_to_string("/tmp/secmon.pid").await {
        Ok(content) => {
            match content.trim().parse::<u32>() {
                Ok(pid) => Ok(Some(pid)),
                Err(_) => {
                    // Invalid PID file
                    let _ = tokio::fs::remove_file("/tmp/secmon.pid").await;
                    Ok(None)
                }
            }
        }
        Err(_) => Ok(None),
    }
}

fn is_process_running(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

fn get_daemon_path() -> Result<String> {
    // Try to find the daemon binary in the same directory as the client
    let current_exe = std::env::current_exe()
        .context("Failed to get current executable path")?;

    let daemon_path = current_exe
        .parent()
        .context("Failed to get executable directory")?
        .join("secmon-daemon");

    if daemon_path.exists() {
        Ok(daemon_path.to_string_lossy().to_string())
    } else {
        // Fall back to looking in PATH
        Ok("secmon-daemon".to_string())
    }
}

fn handle_json_event(event: &SecurityEvent) {
    // Output raw JSON with additional metadata for streaming
    let json_event = serde_json::json!({
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "path": event.path,
        "severity": event.details.severity,
        "description": event.details.description,
        "metadata": event.details.metadata,
        "formatted_timestamp": event.timestamp.format("%H:%M:%S%.3f").to_string(),
        "iso_timestamp": event.timestamp.to_rfc3339(),
        "severity_level": match event.details.severity {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        },
        "event_category": match event.event_type {
            EventType::FileAccess | EventType::FileModify | EventType::FileCreate | EventType::FileDelete => "filesystem",
            EventType::DirectoryAccess => "filesystem",
            EventType::CameraAccess => "privacy",
            EventType::MicrophoneAccess => "privacy",
            EventType::SshAccess => "network",
            EventType::NetworkConnection => "network",
            EventType::UsbDeviceInserted => "hardware",
        }
    });

    println!("{}", json_event);

    // Still log critical events to alert file in JSON mode
    match (&event.event_type, &event.details.severity) {
        (EventType::CameraAccess, _) |
        (EventType::MicrophoneAccess, _) |
        (_, Severity::Critical) => {
            send_alert(&event);
        }
        _ => {}
    }
}

fn handle_security_event(event: &SecurityEvent) {
    let severity_color = match event.details.severity {
        Severity::Low => "\x1b[32m",      // Green
        Severity::Medium => "\x1b[33m",   // Yellow
        Severity::High => "\x1b[31m",     // Red
        Severity::Critical => "\x1b[35m", // Magenta
    };
    let reset_color = "\x1b[0m";

    let timestamp = event.timestamp.format("%H:%M:%S");
    let event_type = format!("{:?}", event.event_type);

    println!(
        "{} | {}{:8}{} | {:12} | {} | {}",
        timestamp,
        severity_color,
        format!("{:?}", event.details.severity),
        reset_color,
        event_type,
        event.path.display(),
        event.details.description
    );

    // Take actions based on event type and severity
    match (&event.event_type, &event.details.severity) {
        (EventType::CameraAccess, _) => {
            warn!("🎥 CAMERA ACCESS DETECTED: {}", event.details.description);
            send_alert(&event);
        }
        (EventType::MicrophoneAccess, _) => {
            warn!("🎤 MICROPHONE ACCESS DETECTED: {}", event.details.description);
            send_alert(&event);
        }
        (EventType::UsbDeviceInserted, Severity::Critical) => {
            warn!("🚨 SUSPICIOUS USB DEVICE: {}", event.details.description);
            send_alert(&event);
        }
        (EventType::UsbDeviceInserted, Severity::High) => {
            warn!("🔌 HIGH-RISK USB DEVICE: {}", event.details.description);
        }
        (EventType::NetworkConnection, Severity::High) => {
            warn!("🌐 SUSPICIOUS NETWORK CONNECTION: {}", event.details.description);
        }
        (_, Severity::Critical) => {
            warn!("🚨 CRITICAL SECURITY EVENT: {}", event.details.description);
            send_alert(&event);
        }
        (_, Severity::High) => {
            warn!("⚠️  High severity event: {}", event.details.description);
        }
        _ => {}
    }
}

fn send_alert(event: &SecurityEvent) {
    // Example: Log critical events to a separate file
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/secmon-alerts.log")
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "[{}] CRITICAL: {} - {}",
                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                event.path.display(),
                event.details.description
            )
        })
    {
        error!("Failed to write alert log: {}", e);
    }

    // Example: Send desktop notification (requires notify-send)
    let _ = std::process::Command::new("notify-send")
        .arg("Security Alert")
        .arg(format!("Critical event: {}", event.details.description))
        .arg("--urgency=critical")
        .spawn();
}