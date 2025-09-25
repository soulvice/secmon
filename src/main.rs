use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use inotify::{Inotify, WatchMask, WatchDescriptor};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::StreamExt;

mod config;
mod error;
mod network_monitor;
mod usb_monitor;
mod device_discovery;

use config::{Config, WatchConfig, EventTrigger, NotificationConfig};
use error::SecmonError;
use network_monitor::NetworkMonitor;
use usb_monitor::UsbMonitor;
use device_discovery::DeviceDiscovery;

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

pub struct SecurityMonitor {
    config: Arc<Config>,
    event_sender: broadcast::Sender<SecurityEvent>,
    #[allow(dead_code)]
    _event_receiver: broadcast::Receiver<SecurityEvent>,
    inotify: Inotify,
    watched_paths: HashMap<WatchDescriptor, PathBuf>,
    pub socket_path: String,
    trigger_cooldowns: Arc<tokio::sync::Mutex<HashMap<String, std::time::Instant>>>,
}

impl SecurityMonitor {
    pub fn new(config: Config) -> Result<Self> {
        let (event_sender, event_receiver) = broadcast::channel(1000);
        let inotify = Inotify::init().context("Failed to initialize inotify")?;
        let socket_path = config.socket_path.clone();

        Ok(SecurityMonitor {
            config: Arc::new(config),
            event_sender,
            _event_receiver: event_receiver,
            inotify,
            watched_paths: HashMap::new(),
            socket_path,
            trigger_cooldowns: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        self.setup_watches()?;

        let socket_path = &self.config.socket_path;
        if std::path::Path::new(socket_path).exists() {
            // Try to connect to check if it's stale
            if tokio::net::UnixStream::connect(socket_path).await.is_ok() {
                return Err(anyhow::anyhow!(
                    "Another instance is already running on socket: {}", socket_path
                ));
            } else {
                // Socket exists but no one is listening - it's stale, remove it
                std::fs::remove_file(socket_path)
                    .context("Failed to remove stale socket")?;
                info!("Removed stale socket: {}", socket_path);
            }
        }

        let listener = UnixListener::bind(socket_path)
            .context("Failed to bind Unix socket")?;

        // Set socket permissions to allow all users to connect (when running as root)
        if let Err(e) = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666)) {
            warn!("Failed to set socket permissions (may not work for non-root users): {}", e);
        }

        info!("Security monitor started, listening on {}", socket_path);

        let event_sender_socket = self.event_sender.clone();
        let socket_task = tokio::spawn(async move {
            Self::handle_socket_connections(listener, event_sender_socket).await
        });

        // Start network monitoring
        let event_sender_network = self.event_sender.clone();
        let network_task = tokio::spawn(async move {
            let mut network_monitor = NetworkMonitor::new(event_sender_network);
            if let Err(e) = network_monitor.start_monitoring().await {
                error!("Network monitoring error: {}", e);
            }
        });

        // Start USB monitoring in a separate task using spawn_blocking
        let event_sender_usb = self.event_sender.clone();
        let usb_task = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let usb_monitor_result = UsbMonitor::new(event_sender_usb);
                match usb_monitor_result {
                    Ok(mut usb_monitor) => {
                        if let Err(e) = usb_monitor.start_monitoring().await {
                            error!("USB monitoring error: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to initialize USB monitoring (may require root): {}", e);
                    }
                }
            })
        });

        // Run filesystem monitoring in the main task
        let filesystem_task = async {
            if let Err(e) = self.monitor_events().await {
                error!("Filesystem monitoring error: {}", e);
            }
            Ok::<(), anyhow::Error>(())
        };

        // Wait for all tasks - using select to handle them concurrently
        tokio::select! {
            result = socket_task => {
                if let Err(e) = result {
                    error!("Socket task error: {}", e);
                }
            },
            result = network_task => {
                if let Err(e) = result {
                    error!("Network task error: {}", e);
                }
            },
            result = usb_task => {
                if let Err(e) = result {
                    error!("USB task error: {}", e);
                }
            },
            result = filesystem_task => {
                if let Err(e) = result {
                    error!("Filesystem task error: {}", e);
                }
            }
        }
        Ok(())
    }

    fn setup_watches(&mut self) -> Result<()> {
        let watches = self.config.watches.clone();
        for watch_config in &watches {
            if !watch_config.enabled {
                debug!("Skipping disabled watch: {}", watch_config.path);
                continue;
            }

            if watch_config.auto_discover {
                self.setup_auto_discovered_watches(watch_config)?;
            } else if watch_config.pattern {
                self.setup_pattern_watches(watch_config)?;
            } else {
                self.setup_single_watch(&watch_config.path, &watch_config.description)?;
            }
        }

        Ok(())
    }

    fn setup_auto_discovered_watches(&mut self, watch_config: &WatchConfig) -> Result<()> {
        // Use device discovery for auto-discovery patterns
        if watch_config.path.contains("video") {
            let video_devices = DeviceDiscovery::discover_video_devices()
                .unwrap_or_else(|e| {
                    warn!("Failed to discover video devices: {}", e);
                    Vec::new()
                });

            for device in video_devices {
                self.setup_single_watch(
                    &device.to_string_lossy(),
                    &format!("Auto-discovered video device: {}", device.display())
                )?;
            }
        }

        if watch_config.path.contains("snd") || watch_config.path.contains("pulse") {
            let audio_devices = DeviceDiscovery::discover_audio_devices()
                .unwrap_or_else(|e| {
                    warn!("Failed to discover audio devices: {}", e);
                    Vec::new()
                });

            for device in audio_devices {
                self.setup_single_watch(
                    &device.to_string_lossy(),
                    &format!("Auto-discovered audio device: {}", device.display())
                )?;
            }
        }

        Ok(())
    }

    fn setup_pattern_watches(&mut self, watch_config: &WatchConfig) -> Result<()> {
        // Use glob to expand patterns
        match glob::glob(&watch_config.path) {
            Ok(paths) => {
                let mut found_any = false;
                for entry in paths {
                    match entry {
                        Ok(path) => {
                            found_any = true;
                            self.setup_single_watch(
                                &path.to_string_lossy(),
                                &format!("Pattern-matched: {} ({})", watch_config.description, path.display())
                            )?;
                        }
                        Err(e) => {
                            warn!("Error expanding pattern {}: {}", watch_config.path, e);
                        }
                    }
                }

                if !found_any {
                    debug!("No paths found for pattern: {}", watch_config.path);
                }
            }
            Err(e) => {
                warn!("Invalid glob pattern {}: {}", watch_config.path, e);
            }
        }

        Ok(())
    }

    fn setup_single_watch(&mut self, path_str: &str, description: &str) -> Result<()> {
        let path = Path::new(path_str);
        if !path.exists() {
            debug!("Watch path does not exist: {} ({})", path_str, description);
            return Ok(());
        }

        let mask = WatchMask::MODIFY
            | WatchMask::CREATE
            | WatchMask::DELETE
            | WatchMask::ACCESS
            | WatchMask::OPEN;

        let wd = self.inotify.watches().add(&path, mask)
            .with_context(|| format!("Failed to add watch for {}", path_str))?;

        self.watched_paths.insert(wd, path.to_path_buf());
        info!("Added watch for: {} ({})", path_str, description);

        Ok(())
    }

    async fn monitor_events(&mut self) -> Result<()> {
        let mut buffer = [0; 4096];

        loop {
            let events = self.inotify.read_events_blocking(&mut buffer)
                .context("Failed to read inotify events")?;

            for event in events {
                if let Some(watched_path) = self.watched_paths.get(&event.wd) {
                    let security_event = self.create_security_event(watched_path, &event);

                    debug!("Security event: {:?}", security_event);

                    // Process triggers for this event
                    self.process_event_triggers(&security_event).await;

                    if let Err(e) = self.event_sender.send(security_event) {
                        error!("Failed to send event: {}", e);
                    }
                }
            }
        }
    }

    fn create_security_event(&self, base_path: &Path, event: &inotify::Event<&std::ffi::OsStr>) -> SecurityEvent {
        let full_path = if let Some(name) = event.name {
            base_path.join(name)
        } else {
            base_path.to_path_buf()
        };

        let (event_type, severity, description) = self.classify_event(base_path, &full_path, event.mask);

        let mut metadata = HashMap::new();
        metadata.insert("mask".to_string(), format!("{:?}", event.mask));

        if let Some(name) = event.name {
            metadata.insert("filename".to_string(), name.to_string_lossy().to_string());
        }

        SecurityEvent {
            timestamp: Utc::now(),
            event_type,
            path: full_path,
            details: EventDetails {
                severity,
                description,
                metadata,
            },
        }
    }

    fn classify_event(&self, base_path: &Path, full_path: &Path, mask: inotify::EventMask) -> (EventType, Severity, String) {
        let base_str = base_path.to_string_lossy().to_lowercase();
        let path_str = full_path.to_string_lossy().to_lowercase();

        // Check for camera-related access
        if base_str.contains("video") || base_str.contains("camera") || path_str.contains("/dev/video") {
            return (
                EventType::CameraAccess,
                Severity::High,
                format!("Camera device access detected: {}", full_path.display())
            );
        }

        // Check for microphone-related access
        if base_str.contains("snd") || path_str.contains("/dev/snd/") ||
           path_str.contains("pcm") || path_str.contains("audio") ||
           base_str.contains("alsa") || path_str.contains("pulse") {
            return (
                EventType::MicrophoneAccess,
                Severity::High,
                format!("Microphone/audio device access detected: {}", full_path.display())
            );
        }

        // Check for SSH-related access
        if base_str.contains("ssh") || path_str.contains(".ssh") || path_str.contains("authorized_keys") {
            let severity = if path_str.contains("authorized_keys") || path_str.contains("id_rsa") {
                Severity::Critical
            } else {
                Severity::High
            };
            return (
                EventType::SshAccess,
                severity,
                format!("SSH-related file access: {}", full_path.display())
            );
        }

        // Classify based on inotify mask
        if mask.contains(inotify::EventMask::CREATE) {
            (EventType::FileCreate, Severity::Medium, format!("File created: {}", full_path.display()))
        } else if mask.contains(inotify::EventMask::DELETE) {
            (EventType::FileDelete, Severity::Medium, format!("File deleted: {}", full_path.display()))
        } else if mask.contains(inotify::EventMask::MODIFY) {
            (EventType::FileModify, Severity::Low, format!("File modified: {}", full_path.display()))
        } else if mask.contains(inotify::EventMask::ACCESS) || mask.contains(inotify::EventMask::OPEN) {
            (EventType::FileAccess, Severity::Low, format!("File accessed: {}", full_path.display()))
        } else {
            (EventType::FileAccess, Severity::Low, format!("File system event: {}", full_path.display()))
        }
    }

    async fn handle_socket_connections(listener: UnixListener, event_sender: broadcast::Sender<SecurityEvent>) {
        let mut incoming = UnixListenerStream::new(listener);

        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(stream) => {
                    let receiver = event_sender.subscribe();
                    tokio::spawn(Self::handle_client(stream, receiver));
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(mut stream: UnixStream, mut receiver: broadcast::Receiver<SecurityEvent>) {
        info!("New client connected");

        loop {
            match receiver.recv().await {
                Ok(event) => {
                    match serde_json::to_string(&event) {
                        Ok(json) => {
                            let message = format!("{}\n", json);
                            if let Err(e) = stream.write_all(message.as_bytes()).await {
                                debug!("Client disconnected: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Failed to serialize event: {}", e);
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    warn!("Client lagging, dropping events");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("Event channel closed");
                    break;
                }
            }
        }

        info!("Client disconnected");
    }

    async fn process_event_triggers(&self, event: &SecurityEvent) {
        let triggers = &self.config.triggers;

        for trigger in triggers {
            if !trigger.enabled {
                continue;
            }

            // Check if this event type matches the trigger
            let event_type_str = match &event.event_type {
                EventType::CameraAccess => "CameraAccess",
                EventType::SshAccess => "SshAccess",
                EventType::MicrophoneAccess => "MicrophoneAccess",
                EventType::NetworkConnection => "NetworkConnection",
                EventType::UsbDeviceInserted => "UsbDeviceInserted",
                EventType::FileAccess => "FileAccess",
                EventType::FileModify => "FileModify",
                EventType::FileCreate => "FileCreate",
                EventType::FileDelete => "FileDelete",
                EventType::DirectoryAccess => "DirectoryAccess",
            };

            if !trigger.event_types.contains(&event_type_str.to_string()) {
                continue;
            }

            // Check severity level
            if !self.severity_meets_minimum(&event.details.severity, &trigger.min_severity) {
                continue;
            }

            // Check cooldown
            if !self.check_trigger_cooldown(&trigger.name, trigger.cooldown_seconds).await {
                continue;
            }

            // Execute the trigger
            self.execute_trigger(trigger, event).await;
        }
    }

    async fn check_trigger_cooldown(&self, trigger_name: &str, cooldown_seconds: u64) -> bool {
        let mut cooldowns = self.trigger_cooldowns.lock().await;
        let now = std::time::Instant::now();

        if let Some(&last_run) = cooldowns.get(trigger_name) {
            if now.duration_since(last_run).as_secs() < cooldown_seconds {
                return false;
            }
        }

        cooldowns.insert(trigger_name.to_string(), now);
        true
    }

    fn severity_meets_minimum(&self, event_severity: &Severity, min_severity: &str) -> bool {
        let event_level = match event_severity {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        };

        let min_level = match min_severity {
            "Low" => 1,
            "Medium" => 2,
            "High" => 3,
            "Critical" => 4,
            _ => 2, // Default to Medium
        };

        event_level >= min_level
    }

    async fn execute_trigger(&self, trigger: &EventTrigger, event: &SecurityEvent) {
        debug!("Executing trigger: {}", trigger.name);

        // Substitute variables in command args
        let mut args = trigger.args.clone();
        for arg in &mut args {
            *arg = arg.replace("{path}", &event.path.to_string_lossy())
                     .replace("{severity}", &format!("{:?}", event.details.severity))
                     .replace("{description}", &event.details.description)
                     .replace("{timestamp}", &event.timestamp.to_rfc3339());
        }

        let command = trigger.command.clone();

        if trigger.run_async {
            tokio::spawn(async move {
                if let Err(e) = tokio::process::Command::new(&command)
                    .args(&args)
                    .output()
                    .await
                {
                    error!("Failed to execute trigger command '{}': {}", command, e);
                }
            });
        } else {
            if let Err(e) = tokio::process::Command::new(&command)
                .args(&args)
                .output()
                .await
            {
                error!("Failed to execute trigger command '{}': {}", command, e);
            }
        }
    }
}

impl Drop for SecurityMonitor {
    fn drop(&mut self) {
        // Clean up the socket file when the monitor is dropped
        if std::path::Path::new(&self.socket_path).exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                eprintln!("Warning: Failed to clean up socket file {}: {}", self.socket_path, e);
            } else {
                println!("Cleaned up socket file: {}", self.socket_path);
            }
        }
    }
}

fn daemonize(pid_file: &str, log_file: &str) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    // Check if daemon is already running
    if let Ok(existing_pid) = std::fs::read_to_string(pid_file) {
        if let Ok(pid) = existing_pid.trim().parse::<u32>() {
            // Check if the process is still running
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                eprintln!("Error: Daemon is already running (PID: {})", pid);
                std::process::exit(1);
            } else {
                // Stale PID file, remove it
                let _ = std::fs::remove_file(pid_file);
            }
        }
    }

    // Fork the process
    match unsafe { libc::fork() } {
        -1 => {
            return Err(anyhow::anyhow!("Failed to fork process"));
        }
        0 => {
            // Child process continues
        }
        _ => {
            // Parent process exits
            std::process::exit(0);
        }
    }

    // Create new session
    if unsafe { libc::setsid() } == -1 {
        return Err(anyhow::anyhow!("Failed to create new session"));
    }

    // Fork again to prevent acquiring a controlling terminal
    match unsafe { libc::fork() } {
        -1 => {
            return Err(anyhow::anyhow!("Failed to fork process (second)"));
        }
        0 => {
            // Child process continues
        }
        _ => {
            // Parent process exits
            std::process::exit(0);
        }
    }

    // Change working directory to root
    std::env::set_current_dir("/").context("Failed to change directory to /")?;

    // Close standard file descriptors
    unsafe {
        libc::close(0); // stdin
        libc::close(1); // stdout
        libc::close(2); // stderr
    }

    // Redirect stdout/stderr to log file
    let log_fd = File::create(log_file)
        .with_context(|| format!("Failed to create log file: {}", log_file))?
        .as_raw_fd();

    unsafe {
        libc::dup2(log_fd, 1); // stdout
        libc::dup2(log_fd, 2); // stderr
    }

    // Write PID to file
    let mut pid_file_handle = File::create(pid_file)
        .with_context(|| format!("Failed to create PID file: {}", pid_file))?;

    writeln!(pid_file_handle, "{}", std::process::id())
        .context("Failed to write PID to file")?;

    println!("Daemon started with PID: {}", std::process::id());

    Ok(())
}

fn cleanup_on_exit(socket_path: &str, pid_file: &str, daemon_mode: bool) {
    // Clean up socket file
    if std::path::Path::new(socket_path).exists() {
        if let Err(e) = std::fs::remove_file(socket_path) {
            eprintln!("Warning: Failed to clean up socket file {}: {}", socket_path, e);
        } else {
            info!("Cleaned up socket file: {}", socket_path);
        }
    }

    // Clean up PID file if in daemon mode
    if daemon_mode {
        if std::path::Path::new(pid_file).exists() {
            if let Err(e) = std::fs::remove_file(pid_file) {
                eprintln!("Warning: Failed to remove PID file {}: {}", pid_file, e);
            } else {
                info!("Cleaned up PID file: {}", pid_file);
            }
        }
    }
}

fn print_help() {
    println!("secmon-daemon - Security Monitor Daemon");
    println!();
    println!("USAGE:");
    println!("    secmon-daemon [OPTIONS] [CONFIG_FILE]");
    println!();
    println!("ARGS:");
    println!("    <CONFIG_FILE>    Configuration file path [default: /etc/secmon/config.toml]");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help                Print help information");
    println!("    -v, --version             Print version information");
    println!("    -l, --log-level <LEVEL>   Set log level [default: info]");
    println!("                              Values: error, warn, info, debug, trace");
    println!("    -d, --daemon              Run in background as daemon");
    println!("    --pid-file <FILE>         PID file path [default: /tmp/secmon.pid]");
    println!("    --log-file <FILE>         Log file path when running as daemon [default: /tmp/secmon.log]");
    println!();
    println!("DESCRIPTION:");
    println!("    A security monitoring daemon that watches for file system events,");
    println!("    network connections, USB device insertions, and other security-relevant");
    println!("    activities. Events are broadcast to connected clients via Unix socket.");
    println!();
    println!("EXAMPLES:");
    println!("    secmon-daemon                             # Run in foreground with default config");
    println!("    secmon-daemon --daemon                    # Run in background as daemon");
    println!("    secmon-daemon -d --log-level debug        # Background mode with debug logging");
    println!("    secmon-daemon --pid-file /var/run/secmon.pid  # Custom PID file location");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut log_level = "info".to_string();
    let mut config_path = "/etc/secmon/config.toml".to_string();
    let mut daemon_mode = false;
    let mut pid_file = "/tmp/secmon.pid".to_string();
    let mut log_file = "/tmp/secmon.log".to_string();

    // Parse command line arguments
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-v" => {
                println!("secmon-daemon {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--log-level" | "-l" => {
                if i + 1 < args.len() {
                    log_level = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --log-level requires a value");
                    std::process::exit(1);
                }
            }
            arg if arg.starts_with("--log-level=") => {
                log_level = arg.split('=').nth(1).unwrap_or("info").to_string();
                i += 1;
            }
            "--daemon" | "-d" => {
                daemon_mode = true;
                i += 1;
            }
            "--pid-file" => {
                if i + 1 < args.len() {
                    pid_file = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --pid-file requires a value");
                    std::process::exit(1);
                }
            }
            arg if arg.starts_with("--pid-file=") => {
                pid_file = arg.split('=').nth(1).unwrap_or("/tmp/secmon.pid").to_string();
                i += 1;
            }
            "--log-file" => {
                if i + 1 < args.len() {
                    log_file = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("Error: --log-file requires a value");
                    std::process::exit(1);
                }
            }
            arg if arg.starts_with("--log-file=") => {
                log_file = arg.split('=').nth(1).unwrap_or("/tmp/secmon.log").to_string();
                i += 1;
            }
            arg if !arg.starts_with('-') => {
                config_path = arg.to_string();
                i += 1;
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                eprintln!("Use --help for usage information");
                std::process::exit(1);
            }
        }
    }

    // Initialize logger with specified level
    env_logger::Builder::from_default_env()
        .filter_level(match log_level.to_lowercase().as_str() {
            "error" => log::LevelFilter::Error,
            "warn" => log::LevelFilter::Warn,
            "info" => log::LevelFilter::Info,
            "debug" => log::LevelFilter::Debug,
            "trace" => log::LevelFilter::Trace,
            _ => {
                eprintln!("Error: Invalid log level '{}'. Use: error, warn, info, debug, trace", log_level);
                std::process::exit(1);
            }
        })
        .init();

    // Handle daemon mode
    if daemon_mode {
        daemonize(&pid_file, &log_file)?;
    }

    let config = Config::load(&config_path)
        .context("Failed to load configuration")?;

    info!("Starting security monitor with config: {}", config_path);

    let mut monitor = SecurityMonitor::new(config)?;

    // Store paths for cleanup
    let socket_path = monitor.socket_path.clone();
    let pid_file_clone = pid_file.clone();
    let daemon_mode_clone = daemon_mode;

    // Setup signal handlers for graceful shutdown
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    // Also handle SIGINT directly for non-daemon mode (Ctrl+C)
    tokio::select! {
        result = monitor.start() => {
            if let Err(e) = result {
                error!("Monitor error: {}", e);
                cleanup_on_exit(&socket_path, &pid_file_clone, daemon_mode_clone);
                std::process::exit(1);
            }
        }
        _ = sigint.recv() => {
            info!("Received SIGINT signal, exiting gracefully");
            cleanup_on_exit(&socket_path, &pid_file_clone, daemon_mode_clone);
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM signal, exiting gracefully");
            cleanup_on_exit(&socket_path, &pid_file_clone, daemon_mode_clone);
        }
    }

    info!("Daemon shutdown complete");
    Ok(())
}