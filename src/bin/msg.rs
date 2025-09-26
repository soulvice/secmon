use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

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
    NetworkDiscovery,
    PingDetected,
    PortScanDetected,
    CustomMessage,
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
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help();
        return Ok(());
    }

    // Parse command line arguments
    let mut socket_path: Option<String> = None;
    let mut json_mode = false;
    let mut event_type = EventType::CustomMessage;
    let mut severity = Severity::Medium;
    let mut path: Option<PathBuf> = None;
    let mut description: Option<String> = None;
    let mut metadata = HashMap::new();
    let mut use_stdin = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" | "-s" => {
                if i + 1 < args.len() {
                    socket_path = Some(args[i + 1].clone());
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
            "--stdin" => {
                use_stdin = true;
                i += 1;
            }
            "--type" | "-t" => {
                if i + 1 < args.len() {
                    event_type = parse_event_type(&args[i + 1])?;
                    i += 2;
                } else {
                    eprintln!("Error: --type requires a value");
                    std::process::exit(1);
                }
            }
            "--severity" => {
                if i + 1 < args.len() {
                    severity = parse_severity(&args[i + 1])?;
                    i += 2;
                } else {
                    eprintln!("Error: --severity requires a value");
                    std::process::exit(1);
                }
            }
            "--path" | "-p" => {
                if i + 1 < args.len() {
                    path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    eprintln!("Error: --path requires a value");
                    std::process::exit(1);
                }
            }
            "--description" | "-d" => {
                if i + 1 < args.len() {
                    description = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --description requires a value");
                    std::process::exit(1);
                }
            }
            "--metadata" | "-m" => {
                if i + 1 < args.len() {
                    let meta_str = &args[i + 1];
                    if let Some((key, value)) = meta_str.split_once('=') {
                        metadata.insert(key.to_string(), value.to_string());
                    } else {
                        eprintln!("Error: --metadata format should be 'key=value'");
                        std::process::exit(1);
                    }
                    i += 2;
                } else {
                    eprintln!("Error: --metadata requires a value");
                    std::process::exit(1);
                }
            }
            arg if !arg.starts_with('-') => {
                // If no description was set yet, use this as description
                if description.is_none() {
                    description = Some(arg.to_string());
                }
                i += 1;
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_help();
                std::process::exit(1);
            }
        }
    }

    // Handle different input methods
    let event = if json_mode || use_stdin {
        if json_mode {
            // Read JSON from stdin or command line
            let json_input = if use_stdin || atty::isnt(atty::Stream::Stdin) {
                read_stdin()?
            } else {
                // Try to find JSON in remaining args
                args.get(args.len() - 1).cloned().unwrap_or_default()
            };

            parse_json_event(&json_input)?
        } else {
            // Read raw text from stdin
            let stdin_content = read_stdin()?;
            create_event_from_options(
                event_type,
                severity,
                path.unwrap_or_else(|| PathBuf::from("/custom/message")),
                Some(stdin_content),
                metadata,
            )
        }
    } else {
        // Create event from command line options
        if description.is_none() {
            eprintln!("Error: Description is required when not using --json or --stdin");
            std::process::exit(1);
        }

        create_event_from_options(
            event_type,
            severity,
            path.unwrap_or_else(|| PathBuf::from("/custom/message")),
            description,
            metadata,
        )
    };

    // Send the event
    let socket = resolve_socket_path(socket_path.as_ref());
    send_event(&socket, &event).await?;

    println!("Message sent successfully to daemon");
    Ok(())
}

fn print_help() {
    println!("secmon-msg - Send custom messages/events to Security Monitor Daemon");
    println!();
    println!("USAGE:");
    println!("    secmon-msg [OPTIONS] [DESCRIPTION]");
    println!("    echo 'data' | secmon-msg --stdin");
    println!("    echo '{{\"json\": \"data\"}}' | secmon-msg --json");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help              Show this help message");
    println!("    -s, --socket PATH       Socket path to connect to");
    println!("    -j, --json              Parse input as JSON event");
    println!("    --stdin                 Read message from stdin");
    println!("    -t, --type TYPE         Event type (default: CustomMessage)");
    println!("    --severity LEVEL        Severity level: Low, Medium, High, Critical");
    println!("    -p, --path PATH         File/resource path");
    println!("    -d, --description DESC  Event description");
    println!("    -m, --metadata KEY=VAL  Add metadata key-value pair (can be used multiple times)");
    println!();
    println!("EVENT TYPES:");
    println!("    CustomMessage, FileAccess, FileModify, FileCreate, FileDelete,");
    println!("    CameraAccess, SshAccess, MicrophoneAccess, NetworkConnection,");
    println!("    UsbDeviceInserted, NetworkDiscovery, PingDetected, PortScanDetected");
    println!();
    println!("EXAMPLES:");
    println!("    secmon-msg \"System backup completed\"");
    println!("    secmon-msg --type CameraAccess --severity High \"Unauthorized camera access\"");
    println!("    secmon-msg --path /etc/passwd --description \"File modified\" --metadata user=admin");
    println!("    echo \"Custom alert message\" | secmon-msg --stdin --severity Critical");
    println!("    echo '{{\"description\":\"JSON event\",\"severity\":\"High\"}}' | secmon-msg --json");
    println!();
    println!("JSON FORMAT (when using --json):");
    println!("    {{");
    println!("        \"event_type\": \"CustomMessage\",");
    println!("        \"severity\": \"Medium\",");
    println!("        \"path\": \"/path/to/resource\",");
    println!("        \"description\": \"Event description\",");
    println!("        \"metadata\": {{");
    println!("            \"key1\": \"value1\",");
    println!("            \"key2\": \"value2\"");
    println!("        }}");
    println!("    }}");
}

fn parse_event_type(type_str: &str) -> Result<EventType> {
    match type_str.to_lowercase().as_str() {
        "custommessage" | "custom" => Ok(EventType::CustomMessage),
        "fileaccess" => Ok(EventType::FileAccess),
        "filemodify" => Ok(EventType::FileModify),
        "filecreate" => Ok(EventType::FileCreate),
        "filedelete" => Ok(EventType::FileDelete),
        "directoryaccess" => Ok(EventType::DirectoryAccess),
        "cameraaccess" => Ok(EventType::CameraAccess),
        "sshaccess" => Ok(EventType::SshAccess),
        "microphoneaccess" => Ok(EventType::MicrophoneAccess),
        "networkconnection" => Ok(EventType::NetworkConnection),
        "usbdeviceinserted" => Ok(EventType::UsbDeviceInserted),
        "networkdiscovery" => Ok(EventType::NetworkDiscovery),
        "pingdetected" => Ok(EventType::PingDetected),
        "portscandetected" => Ok(EventType::PortScanDetected),
        _ => Err(anyhow::anyhow!("Invalid event type: {}", type_str)),
    }
}

fn parse_severity(severity_str: &str) -> Result<Severity> {
    match severity_str.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(anyhow::anyhow!("Invalid severity: {}", severity_str)),
    }
}

fn create_event_from_options(
    event_type: EventType,
    severity: Severity,
    path: PathBuf,
    description: Option<String>,
    metadata: HashMap<String, String>,
) -> SecurityEvent {
    SecurityEvent {
        timestamp: Utc::now(),
        event_type,
        path,
        details: EventDetails {
            severity,
            description: description.unwrap_or_else(|| "Custom message".to_string()),
            metadata,
        },
    }
}

fn parse_json_event(json_str: &str) -> Result<SecurityEvent> {
    // Try to parse as complete SecurityEvent first
    if let Ok(event) = serde_json::from_str::<SecurityEvent>(json_str) {
        return Ok(event);
    }

    // Try to parse as partial event and fill in defaults
    #[derive(Deserialize)]
    struct PartialEvent {
        event_type: Option<String>,
        severity: Option<String>,
        path: Option<PathBuf>,
        description: Option<String>,
        metadata: Option<HashMap<String, String>>,
    }

    let partial: PartialEvent = serde_json::from_str(json_str)
        .context("Invalid JSON format")?;

    let event_type = if let Some(type_str) = partial.event_type {
        parse_event_type(&type_str)?
    } else {
        EventType::CustomMessage
    };

    let severity = if let Some(sev_str) = partial.severity {
        parse_severity(&sev_str)?
    } else {
        Severity::Medium
    };

    Ok(SecurityEvent {
        timestamp: Utc::now(),
        event_type,
        path: partial.path.unwrap_or_else(|| PathBuf::from("/custom/json")),
        details: EventDetails {
            severity,
            description: partial.description.unwrap_or_else(|| "JSON message".to_string()),
            metadata: partial.metadata.unwrap_or_default(),
        },
    })
}

fn read_stdin() -> Result<String> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)
        .context("Failed to read from stdin")?;
    Ok(buffer.trim().to_string())
}

async fn send_event(socket_path: &str, event: &SecurityEvent) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("Failed to connect to daemon socket: {}", socket_path))?;

    let json = serde_json::to_string(event)
        .context("Failed to serialize event to JSON")?;

    let message = format!("{}\n", json);
    stream.write_all(message.as_bytes()).await
        .context("Failed to send event to daemon")?;

    Ok(())
}

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
    use toml::Value;

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