# Security Monitor Daemon (secmon-daemon)

A lightweight, efficient Rust daemon for monitoring filesystem changes on Linux, designed for security monitoring of camera devices, SSH access, and other sensitive file system events.

## Features

- **Event-driven monitoring**: Uses Linux `inotify` for efficient filesystem monitoring (no polling)
- **JSON event streaming**: Real-time events via Unix domain socket with structured JSON format
- **Camera intrusion detection**: Monitors `/dev/video*` devices for unauthorized access
- **SSH security monitoring**: Watches SSH keys, configs, and authentication logs
- **Configurable paths**: TOML-based configuration for custom monitoring locations
- **Lightweight daemon**: Minimal resource usage, runs as background service
- **Systemd integration**: Easy service management with provided unit file

## Architecture

```
secmon-daemon (main process)
├── inotify filesystem monitoring
├── Unix socket server (/tmp/secmon.sock)
├── JSON event broadcaster
└── Configuration management

secmon-client (example consumer)
├── Connects to Unix socket
├── Receives JSON events
├── Displays/processes security events
```

## Quick Start

1. **Build the project**:
   ```bash
   cargo build --release
   ```

2. **Install the daemon**:
   ```bash
   sudo cp target/release/secmon-daemon /usr/local/bin/
   sudo cp target/release/secmon-client /usr/local/bin/
   ```

3. **Setup configuration**:
   ```bash
   sudo mkdir -p /etc/secmon
   # Config will be auto-generated on first run
   ```

4. **Install systemd service**:
   ```bash
   sudo cp secmon.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable secmon
   sudo systemctl start secmon
   ```

5. **Monitor events**:
   ```bash
   secmon-client
   ```

## Configuration

Default config at `/etc/secmon/config.toml`:

```toml
socket_path = "/tmp/secmon.sock"
log_level = "info"

[[watches]]
path = "/dev/video0"
description = "Primary camera device"
enabled = true
recursive = false

[[watches]]
path = "/home"
description = "Home directories for SSH key monitoring"
enabled = true
recursive = true

[[watches]]
path = "/etc/ssh"
description = "SSH daemon configuration"
enabled = true
recursive = true
```

## Event Format

Events are streamed as JSON over the Unix socket:

```json
{
  "timestamp": "2025-09-25T14:30:45.123Z",
  "event_type": {"type": "CameraAccess"},
  "path": "/dev/video0",
  "details": {
    "severity": "High",
    "description": "Camera device access detected: /dev/video0",
    "metadata": {
      "mask": "OPEN | ACCESS",
      "filename": "video0"
    }
  }
}
```

## Event Types

- `FileAccess` - File/directory accessed
- `FileModify` - File content changed
- `FileCreate` - New file/directory created
- `FileDelete` - File/directory deleted
- `CameraAccess` - Camera device accessed (High/Critical severity)
- `SshAccess` - SSH-related file accessed (High/Critical severity)

## Severity Levels

- `Low` - Normal file operations
- `Medium` - File creation/deletion
- `High` - Camera/SSH access
- `Critical` - SSH key or authorized_keys access

## Usage Examples

**Run daemon manually**:
```bash
sudo secmon-daemon /path/to/config.toml
```

**Connect and monitor events**:
```bash
secmon-client /tmp/secmon.sock
```

**Custom event processing** (your own client):
```bash
socat UNIX-CONNECT:/tmp/secmon.sock - | jq .
```

## Development

```bash
# Build debug version
cargo build

# Run with logging
RUST_LOG=debug cargo run -- config.toml

# Test with example client
cargo run --bin secmon-client
```

## Security Considerations

- Runs as root to access device files and system directories
- Uses systemd security features (NoNewPrivileges, ProtectSystem, etc.)
- Socket permissions should be restricted in production
- Consider moving socket to `/var/run/` for production use

## Troubleshooting

**Permission denied errors**: Ensure daemon runs as root for device access
**Socket connection failed**: Check if daemon is running and socket path exists
**No events**: Verify paths exist and are accessible in configuration

## License

MIT License - see LICENSE file for details.