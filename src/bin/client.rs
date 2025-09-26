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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use regex::Regex;
use toml::Value;

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

// Global state for notification cooldowns and rate limiting
lazy_static::lazy_static! {
    static ref NOTIFICATION_COOLDOWNS: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref NOTIFICATION_RATE_LIMITER: Arc<Mutex<Vec<Instant>>> = Arc::new(Mutex::new(Vec::new()));
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
            let mut cli_socket_path: Option<String> = None;
            let mut json_mode = false;
            let mut filter_severity: Option<Severity> = None;

            // Parse arguments starting from index 2
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--socket" | "-s" => {
                        if i + 1 < args.len() {
                            cli_socket_path = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --socket requires a value");
                            std::process::exit(1);
                        }
                    }
                    "--json" | "-j" => {
                        json_mode = true;
                        i += 1;
                    }
                    "--severity-low" => {
                        filter_severity = Some(Severity::Low);
                        i += 1;
                    }
                    "--severity-medium" => {
                        filter_severity = Some(Severity::Medium);
                        i += 1;
                    }
                    "--severity-high" => {
                        filter_severity = Some(Severity::High);
                        i += 1;
                    }
                    "--severity-critical" => {
                        filter_severity = Some(Severity::Critical);
                        i += 1;
                    }
                    arg if !arg.starts_with("--") && !arg.starts_with("-") => {
                        // Backward compatibility: positional socket path
                        cli_socket_path = Some(arg.to_string());
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            let socket_path = resolve_socket_path(cli_socket_path.as_ref());
            monitor_events(&socket_path, json_mode, filter_severity).await
        }
        "listen" => {
            let mut cli_socket_path: Option<String> = None;
            let mut json_mode = false;
            let mut filter_severity: Option<Severity> = None;

            // Parse arguments starting from index 2
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--socket" | "-s" => {
                        if i + 1 < args.len() {
                            cli_socket_path = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --socket requires a value");
                            std::process::exit(1);
                        }
                    }
                    "--json" | "-j" => {
                        json_mode = true;
                        i += 1;
                    }
                    "--severity-low" => {
                        filter_severity = Some(Severity::Low);
                        i += 1;
                    }
                    "--severity-medium" => {
                        filter_severity = Some(Severity::Medium);
                        i += 1;
                    }
                    "--severity-high" => {
                        filter_severity = Some(Severity::High);
                        i += 1;
                    }
                    "--severity-critical" => {
                        filter_severity = Some(Severity::Critical);
                        i += 1;
                    }
                    arg if !arg.starts_with("--") && !arg.starts_with("-") => {
                        // Backward compatibility: positional socket path
                        cli_socket_path = Some(arg.to_string());
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            let socket_path = resolve_socket_path(cli_socket_path.as_ref());
            listen_events(&socket_path, json_mode, filter_severity).await
        }
        "config" => {
            if args.len() < 3 {
                print_config_help();
                return Ok(());
            }

            match args[2].as_str() {
                "validate" => {
                    let default_config = "/etc/secmon/config.toml".to_string();
                    let config_path = args.get(3).unwrap_or(&default_config);
                    config_validate(config_path).await
                }
                "show" => config_show().await,
                "reload" => config_reload().await,
                _ => {
                    eprintln!("Error: Unknown config command '{}'", args[2]);
                    print_config_help();
                    std::process::exit(1);
                }
            }
        }
        "stats" => {
            let mut since = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--since" => {
                        if i + 1 < args.len() {
                            since = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --since requires a value");
                            std::process::exit(1);
                        }
                    }
                    _ => i += 1,
                }
            }
            stats_show(since).await
        }
        "search" => {
            let mut path_filter = None;
            let mut since = None;
            let mut event_type = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--path" => {
                        if i + 1 < args.len() {
                            path_filter = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --path requires a value");
                            std::process::exit(1);
                        }
                    }
                    "--since" => {
                        if i + 1 < args.len() {
                            since = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --since requires a value");
                            std::process::exit(1);
                        }
                    }
                    "--type" => {
                        if i + 1 < args.len() {
                            event_type = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --type requires a value");
                            std::process::exit(1);
                        }
                    }
                    _ => i += 1,
                }
            }
            search_events(path_filter, since, event_type).await
        }
        "tui" => {
            let mut cli_socket_path: Option<String> = None;

            // Parse arguments starting from index 2
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--socket" | "-s" => {
                        if i + 1 < args.len() {
                            cli_socket_path = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            eprintln!("Error: --socket requires a value");
                            std::process::exit(1);
                        }
                    }
                    arg if !arg.starts_with("--") && !arg.starts_with("-") => {
                        // Backward compatibility: positional socket path
                        cli_socket_path = Some(arg.to_string());
                        i += 1;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            let socket_path = resolve_socket_path(cli_socket_path.as_ref());
            run_tui_with_socket(&socket_path).await
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
    println!("    monitor [--socket PATH] [--json]  Monitor security events (includes buffered events)");
    println!("    listen [--socket PATH] [--json]   Listen for new security events only (from connection time)");
    println!("    config <validate|show|reload>  Configuration management");
    println!("    stats [--since TIME]       Show event statistics");
    println!("    search [--path P] [--since T] [--type TYPE]  Search events");
    println!("    tui [--socket PATH]        Interactive terminal interface");
    println!("    help, --help, -h   Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    secmon-client start                    # Start daemon with default config");
    println!("    secmon-client start /path/config.toml  # Start with custom config");
    println!("    secmon-client stop                     # Stop the daemon");
    println!("    secmon-client status                   # Check daemon status");
    println!("    secmon-client logs                     # Show last 50 log lines");
    println!("    secmon-client logs 100                 # Show last 100 log lines");
    println!("    secmon-client monitor                  # Monitor events (uses config/default socket)");
    println!("    secmon-client monitor --socket /custom/path --json  # Monitor with custom socket");
    println!("    secmon-client listen                   # Listen for new events only");
    println!("    secmon-client listen --socket /tmp/secmon.sock --json # Listen with JSON output");
    println!("    secmon-client config validate          # Validate config file");
    println!("    secmon-client stats --since 1h         # Show stats from last hour");
    println!("    secmon-client search --path /home      # Search events by path");
    println!("    secmon-client tui --socket /custom/socket # Interactive monitoring with custom socket");
    println!();
    println!("SOCKET PATH RESOLUTION:");
    println!("    1. Command line --socket argument (highest priority)");
    println!("    2. socket_path setting in config file");
    println!("    3. Default: /tmp/secmon.sock");
    println!();
    println!("CONFIG FILE LOCATIONS (checked in order):");
    println!("    /etc/secmon/config.toml");
    println!("    ./config.toml");
    println!("    config.toml");
}

fn print_config_help() {
    println!("secmon-client config - Configuration Management");
    println!();
    println!("USAGE:");
    println!("    secmon-client config <SUBCOMMAND> [OPTIONS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("    validate [CONFIG]  Validate configuration file syntax");
    println!("    show               Show current daemon configuration");
    println!("    reload             Reload daemon configuration without restart");
    println!();
    println!("EXAMPLES:");
    println!("    secmon-client config validate /etc/secmon/config.toml");
    println!("    secmon-client config show");
    println!("    secmon-client config reload");
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

async fn listen_events(socket_path: &str, json_mode: bool, filter_severity: Option<Severity>) -> Result<()> {
    info!("Connecting to secmon daemon at: {}", socket_path);

    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("Failed to connect to socket: {}", socket_path))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    // Get connection timestamp to filter out old events
    let connection_time = chrono::Utc::now();

    if json_mode {
        info!("Connected! Listening for new JSON events (from connection time)...");
        // In JSON mode, output events directly without headers
    } else {
        info!("Connected! Listening for new security events (from connection time)...");
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
                        // Filter out events that occurred before we connected
                        if event.timestamp <= connection_time {
                            continue;
                        }

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
                            handle_json_event_listen(&event);
                        } else {
                            handle_security_event_listen(&event);
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

// Config management functions
async fn config_validate(config_path: &str) -> Result<()> {
    println!("Validating configuration file: {}", config_path);

    match std::fs::read_to_string(config_path) {
        Ok(content) => {
            match toml::from_str::<toml::Value>(&content) {
                Ok(_) => {
                    println!("✓ Configuration file syntax is valid");
                    Ok(())
                }
                Err(e) => {
                    eprintln!("✗ Configuration file has syntax errors:");
                    eprintln!("  {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("✗ Failed to read configuration file: {}", e);
            std::process::exit(1);
        }
    }
}

async fn config_show() -> Result<()> {
    println!("Current daemon configuration:");

    let config_paths = ["/etc/secmon/config.toml", "./config.toml"];

    for path in &config_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            println!("Configuration from {}:", path);
            println!("{}", content);
            return Ok(());
        }
    }

    eprintln!("No configuration file found in common locations");
    Ok(())
}

async fn config_reload() -> Result<()> {
    println!("Reloading daemon configuration...");
    println!("Note: Config reload requires daemon support (not yet implemented)");
    println!("Recommendation: Use 'secmon-client restart' for now");
    Ok(())
}

// Statistics and reporting functions
async fn stats_show(since: Option<String>) -> Result<()> {
    println!("Event Statistics");
    if let Some(time) = &since {
        println!("Since: {}", time);
    }
    println!("==================");

    match std::fs::read_to_string("/tmp/secmon-alerts.log") {
        Ok(content) => {
            let mut stats = std::collections::HashMap::new();
            let lines: Vec<&str> = content.lines().collect();

            let since_timestamp = if let Some(time_str) = since {
                parse_time_duration(&time_str)
            } else {
                None
            };

            for line in lines {
                if let Some(event_type) = extract_event_type_from_log(line) {
                    if let Some(since_ts) = since_timestamp {
                        if let Some(log_time) = extract_timestamp_from_log(line) {
                            if log_time < since_ts {
                                continue;
                            }
                        }
                    }

                    *stats.entry(event_type).or_insert(0) += 1;
                }
            }

            if stats.is_empty() {
                println!("No events found");
            } else {
                for (event_type, count) in stats.iter() {
                    println!("{:20} : {}", event_type, count);
                }
            }
        }
        Err(_) => {
            println!("No event log found. Make sure the daemon is running and has generated events.");
        }
    }

    Ok(())
}

// Search and filtering functions
async fn search_events(path_filter: Option<String>, since: Option<String>, event_type: Option<String>) -> Result<()> {
    println!("Searching events...");

    if let Some(path) = &path_filter {
        println!("Path filter: {}", path);
    }
    if let Some(time) = &since {
        println!("Since: {}", time);
    }
    if let Some(evt_type) = &event_type {
        println!("Event type: {}", evt_type);
    }

    println!("Results:");
    println!("========");

    match std::fs::read_to_string("/tmp/secmon-alerts.log") {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            let mut matches = 0;

            let path_regex = if let Some(path) = path_filter {
                Some(Regex::new(&path).unwrap_or_else(|_| Regex::new(&regex::escape(&path)).unwrap()))
            } else {
                None
            };

            let since_timestamp = if let Some(time_str) = since {
                parse_time_duration(&time_str)
            } else {
                None
            };

            for line in lines {
                let mut should_include = true;

                if let Some(ref regex) = path_regex {
                    if !regex.is_match(line) {
                        should_include = false;
                    }
                }

                if let Some(since_ts) = since_timestamp {
                    if let Some(log_time) = extract_timestamp_from_log(line) {
                        if log_time < since_ts {
                            should_include = false;
                        }
                    }
                }

                if let Some(ref filter_type) = event_type {
                    if let Some(log_event_type) = extract_event_type_from_log(line) {
                        if !log_event_type.to_lowercase().contains(&filter_type.to_lowercase()) {
                            should_include = false;
                        }
                    }
                }

                if should_include {
                    println!("{}", line);
                    matches += 1;
                }
            }

            println!();
            println!("Found {} matching events", matches);
        }
        Err(_) => {
            println!("No event log found. Make sure the daemon is running and has generated events.");
        }
    }

    Ok(())
}

// Helper functions for parsing
fn parse_time_duration(time_str: &str) -> Option<chrono::DateTime<Utc>> {
    let now = Utc::now();

    if time_str.ends_with('h') {
        if let Ok(hours) = time_str.trim_end_matches('h').parse::<i64>() {
            return Some(now - chrono::Duration::hours(hours));
        }
    } else if time_str.ends_with('m') {
        if let Ok(minutes) = time_str.trim_end_matches('m').parse::<i64>() {
            return Some(now - chrono::Duration::minutes(minutes));
        }
    } else if time_str.ends_with('d') {
        if let Ok(days) = time_str.trim_end_matches('d').parse::<i64>() {
            return Some(now - chrono::Duration::days(days));
        }
    }

    None
}

fn extract_event_type_from_log(line: &str) -> Option<String> {
    if line.contains("Camera") || line.contains("camera") {
        Some("CameraAccess".to_string())
    } else if line.contains("Microphone") || line.contains("microphone") || line.contains("audio") {
        Some("MicrophoneAccess".to_string())
    } else if line.contains("SSH") || line.contains("ssh") {
        Some("SshAccess".to_string())
    } else if line.contains("USB") || line.contains("usb") {
        Some("UsbDeviceInserted".to_string())
    } else if line.contains("Network") || line.contains("network") {
        Some("NetworkConnection".to_string())
    } else {
        Some("FileSystem".to_string())
    }
}

fn extract_timestamp_from_log(line: &str) -> Option<chrono::DateTime<Utc>> {
    if let Some(start) = line.find('[') {
        if let Some(end) = line.find(']') {
            let timestamp_str = &line[start+1..end];
            if let Ok(timestamp) = chrono::DateTime::parse_from_str(timestamp_str, "%Y-%m-%d %H:%M:%S") {
                return Some(timestamp.with_timezone(&Utc));
            }
        }
    }
    None
}

// Socket path resolution with priority: CLI argument > config file > default
fn resolve_socket_path(cli_socket: Option<&String>) -> String {
    // 1. Command line argument takes highest priority
    if let Some(socket) = cli_socket {
        return socket.clone();
    }

    // 2. Try to read from config file
    if let Some(config_socket) = get_socket_from_config() {
        return config_socket;
    }

    // 3. Default fallback
    "/tmp/secmon.sock".to_string()
}

fn get_socket_from_config() -> Option<String> {
    let config_paths = [
        "/etc/secmon/config.toml",
        "./config.toml",
        "config.toml"
    ];

    for config_path in &config_paths {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(config) = toml::from_str::<Value>(&content) {
                if let Some(socket_path) = config.get("socket_path") {
                    if let Some(path_str) = socket_path.as_str() {
                        return Some(path_str.to_string());
                    }
                }
            }
        }
    }

    None
}

// Terminal UI implementation
async fn run_tui_with_socket(socket_path: &str) -> Result<()> {
    use crossterm::{
        event::{DisableMouseCapture, EnableMouseCapture},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        Terminal,
    };
    use std::io;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App {
        events: Vec::new(),
        list_state: ratatui::widgets::ListState::default(),
        should_quit: false,
        connected: false,
        _error_message: None,
    };

    // Create channels for events and connection status
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<SecurityEvent>();
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();

    // Spawn task to connect to daemon and receive events
    let event_task = {
        let event_tx_clone = event_tx.clone();
        let status_tx_clone = status_tx.clone();
        let socket_path = socket_path.to_string();
        tokio::spawn(async move {
            let status_tx_for_error = status_tx_clone.clone();
            match connect_and_receive_events_with_status(event_tx_clone, status_tx_clone, &socket_path).await {
                Ok(_) => {},
                Err(e) => {
                    error!("Failed to connect to daemon: {}", e);
                    let _ = status_tx_for_error.send(false);
                }
            }
        })
    };

    // Main event loop
    let res = tokio::select! {
        _ = event_task => Ok(()),
        result = run_tui_loop(&mut terminal, &mut app, &mut event_rx, &mut status_rx) => result,
    };

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

async fn connect_and_receive_events_with_status(
    event_tx: tokio::sync::mpsc::UnboundedSender<SecurityEvent>,
    status_tx: tokio::sync::mpsc::UnboundedSender<bool>,
    socket_path: &str
) -> Result<()> {
    let stream = UnixStream::connect(socket_path).await
        .with_context(|| format!("Failed to connect to socket: {}", socket_path))?;

    // Send connection success status immediately
    let _ = status_tx.send(true);

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // Connection closed
                let _ = status_tx.send(false);
                break;
            }
            Ok(_) => {
                if let Ok(event) = serde_json::from_str::<SecurityEvent>(&line.trim()) {
                    if event_tx.send(event).is_err() {
                        break; // Receiver dropped
                    }
                }
            }
            Err(e) => {
                error!("Failed to read from socket: {}", e);
                let _ = status_tx.send(false);
                break;
            }
        }
    }

    Ok(())
}

struct App {
    events: Vec<SecurityEvent>,
    list_state: ratatui::widgets::ListState,
    should_quit: bool,
    connected: bool,
    _error_message: Option<String>,
}

async fn run_tui_loop<B>(
    terminal: &mut ratatui::Terminal<B>,
    app: &mut App,
    event_rx: &mut tokio::sync::mpsc::UnboundedReceiver<SecurityEvent>,
    status_rx: &mut tokio::sync::mpsc::UnboundedReceiver<bool>,
) -> Result<()>
where
    B: ratatui::backend::Backend,
{
    use crossterm::event::{Event, KeyCode, KeyEventKind};
    use std::time::Duration;

    loop {
        // Draw UI
        terminal.draw(|f| ui(f, app))?;

        // Handle events with timeout
        let timeout = Duration::from_millis(100);
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = crossterm::event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.should_quit = true;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if !app.events.is_empty() {
                                let i = match app.list_state.selected() {
                                    Some(i) => {
                                        if i >= app.events.len() - 1 {
                                            0
                                        } else {
                                            i + 1
                                        }
                                    }
                                    None => 0,
                                };
                                app.list_state.select(Some(i));
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if !app.events.is_empty() {
                                let i = match app.list_state.selected() {
                                    Some(i) => {
                                        if i == 0 {
                                            app.events.len() - 1
                                        } else {
                                            i - 1
                                        }
                                    }
                                    None => 0,
                                };
                                app.list_state.select(Some(i));
                            }
                        }
                        KeyCode::Char('c') => {
                            app.events.clear();
                            app.list_state.select(None);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Check for connection status updates
        while let Ok(connected) = status_rx.try_recv() {
            app.connected = connected;
        }

        // Check for new events from daemon
        while let Ok(event) = event_rx.try_recv() {
            app.events.push(event);
            // Keep only last 1000 events
            if app.events.len() > 1000 {
                app.events.remove(0);
            }
            // Auto-select newest event if none selected
            if app.list_state.selected().is_none() && !app.events.is_empty() {
                app.list_state.select(Some(app.events.len() - 1));
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn ui(f: &mut ratatui::Frame, app: &mut App) {
    use ratatui::{
        layout::{Constraint, Direction, Layout},
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, Paragraph},
    };

    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Header
    let header = Paragraph::new("Security Monitor - Terminal UI")
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    // Event list
    let events: Vec<ListItem> = app
        .events
        .iter()
        .enumerate()
        .map(|(_i, event)| {
            let severity_color = match event.details.severity {
                Severity::Low => Color::Green,
                Severity::Medium => Color::Yellow,
                Severity::High => Color::Red,
                Severity::Critical => Color::Magenta,
            };

            let line = Line::from(vec![
                Span::styled(
                    format!("[{}] ", event.timestamp.format("%H:%M:%S")),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    format!("{:8}", format!("{:?}", event.details.severity)),
                    Style::default().fg(severity_color).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("{:12}", format!("{:?}", event.event_type)),
                    Style::default().fg(Color::Blue),
                ),
                Span::raw(" "),
                Span::raw(format!("{} - {}", event.path.display(), event.details.description)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let event_list = List::new(events)
        .block(Block::default().borders(Borders::ALL).title("Security Events"))
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("> ");

    f.render_stateful_widget(event_list, chunks[1], &mut app.list_state);

    // Footer with controls
    let status = if app.connected {
        "🟢 Connected to daemon"
    } else if app.events.is_empty() {
        "🟡 Connecting to daemon..."
    } else {
        "🔴 Disconnected from daemon"
    };

    let footer_text = format!(
        "{} | Events: {} | Controls: j/k=navigate, c=clear, q=quit",
        status,
        app.events.len()
    );

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);
}

fn handle_json_event_listen(event: &SecurityEvent) {
    // Output raw JSON with additional metadata for streaming (no notifications)
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
}

fn handle_security_event_listen(event: &SecurityEvent) {
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

    // No notifications or alerts in listen mode - just display
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
    // Log critical events to a separate file
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

    // Check if we should send a desktop notification (with cooldown and rate limiting)
    if should_send_notification(event) {
        let _ = std::process::Command::new("notify-send")
            .arg("Security Alert")
            .arg(format!("Critical event: {}", event.details.description))
            .arg("--urgency=critical")
            .spawn();
    }
}

fn should_send_notification(event: &SecurityEvent) -> bool {
    let now = Instant::now();

    // Create a cooldown key based on event type and path
    let cooldown_key = format!("{:?}:{}", event.event_type, event.path.display());

    // Check event-specific cooldown (prevent duplicate notifications for same event)
    {
        let mut cooldowns = NOTIFICATION_COOLDOWNS.lock().unwrap();

        // Clean up old entries (older than 5 minutes)
        cooldowns.retain(|_, &mut last_time| now.duration_since(last_time) < Duration::from_secs(300));

        // Check if we're still in cooldown for this specific event
        if let Some(&last_notification) = cooldowns.get(&cooldown_key) {
            let cooldown_duration = match event.event_type {
                EventType::MicrophoneAccess => Duration::from_secs(60), // 1 minute for microphone
                EventType::CameraAccess => Duration::from_secs(60),     // 1 minute for camera
                _ => Duration::from_secs(30),                           // 30 seconds for others
            };

            if now.duration_since(last_notification) < cooldown_duration {
                return false; // Still in cooldown
            }
        }

        // Update the cooldown time
        cooldowns.insert(cooldown_key, now);
    }

    // Check global rate limiting (max 5 notifications per minute)
    {
        let mut rate_limiter = NOTIFICATION_RATE_LIMITER.lock().unwrap();

        // Remove notifications older than 1 minute
        rate_limiter.retain(|&notification_time| now.duration_since(notification_time) < Duration::from_secs(60));

        // Check if we've exceeded the rate limit
        if rate_limiter.len() >= 5 {
            warn!("Notification rate limit exceeded, skipping notification for: {}", event.details.description);
            return false;
        }

        // Add this notification to the rate limiter
        rate_limiter.push(now);
    }

    true
}