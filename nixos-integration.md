# NixOS Integration Guide

## Overview

The secmon-daemon provides a complete NixOS flake with integrated service configuration. You can enable security monitoring with simple declarative configuration.

## Quick Start

### 1. Add to your flake inputs

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    secmon.url = "github:your-username/secmon-daemon";
  };
}
```

### 2. Import the module and enable the service

```nix
{
  imports = [ secmon.nixosModules.default ];

  services.secmon.enable = true;
}
```

That's it! The daemon will start with sensible defaults monitoring cameras, microphones, SSH, and USB devices.

## Configuration Options

### Basic Configuration

```nix
services.secmon = {
  enable = true;                    # Enable the service

  # Choose which monitoring features to enable
  monitors = {
    filesystem = true;              # inotify filesystem events
    network = true;                 # TCP connection monitoring
    usb = true;                     # USB device insertion
    camera = true;                  # Camera access detection
    microphone = true;              # Microphone access detection
    ssh = true;                     # SSH security monitoring
  };

  socketPath = "/run/secmon/secmon.sock";  # IPC socket location
};
```

### Advanced Configuration

```nix
services.secmon = {
  enable = true;

  # Custom filesystem watches
  watches = [
    {
      path = "/etc/nixos";
      description = "NixOS configuration";
      enabled = true;
      recursive = true;
    }
    {
      path = "/root/.ssh";
      description = "Root SSH keys";
      enabled = true;
      recursive = false;
    }
  ];

  # Override all settings
  settings = {
    socket_path = "/run/secmon/secmon.sock";
    log_level = "debug";
    watches = [
      # Custom watch configuration
    ];
  };

  # Security settings
  user = "secmon";                  # Run as this user
  group = "secmon";                 # Run as this group
  extraGroups = [ "audio" "video" "input" ]; # Additional groups for device access
};
```

## Default Monitoring Paths

When monitors are enabled, these paths are automatically watched:

### Camera Monitoring (`monitors.camera = true`)
- `/dev/video0` - Primary camera
- `/dev/video1` - Secondary camera

### Microphone Monitoring (`monitors.microphone = true`)
- `/dev/snd/` - ALSA audio devices (recursive)
- `/tmp/.pulse` - PulseAudio temp files (recursive)

### SSH Monitoring (`monitors.ssh = true`)
- `/home` - All user SSH keys (recursive)
- `/etc/ssh` - SSH daemon config (recursive)
- `/var/log/auth.log` - Authentication logs

## Service Management

```bash
# Check service status
systemctl status secmon

# View logs
journalctl -u secmon -f

# Restart service
systemctl restart secmon

# Monitor events in real-time
secmon-client
```

## Event Monitoring

### Connect to event stream
```bash
# Using included client
secmon-client

# Using raw socket connection
socat UNIX-CONNECT:/run/secmon/secmon.sock - | jq .
```

### Example event JSON
```json
{
  "timestamp": "2025-09-25T14:30:45.123Z",
  "event_type": {"type": "CameraAccess"},
  "path": "/dev/video0",
  "details": {
    "severity": "High",
    "description": "Camera device access detected: /dev/video0",
    "metadata": {
      "mask": "OPEN | ACCESS"
    }
  }
}
```

## Custom Alert Handling

Create a systemd service to process events:

```nix
systemd.services.secmon-alerts = {
  description = "Secmon Alert Handler";
  after = [ "secmon.service" ];
  wants = [ "secmon.service" ];
  wantedBy = [ "multi-user.target" ];

  script = ''
    ${secmon.packages.x86_64-linux.default}/bin/secmon-client | while read -r event; do
      # Process event JSON
      echo "$event" | jq .

      # Send critical alerts
      if echo "$event" | jq -r '.details.severity' | grep -q "Critical"; then
        # Send webhook, email, SMS, etc.
        notify-send "Security Alert" "$(echo "$event" | jq -r '.details.description')"
      fi
    done
  '';

  serviceConfig = {
    Restart = "always";
    User = "nobody";
  };
};
```

## Security Considerations

The service runs with minimal privileges:
- Dedicated `secmon` user/group
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=read-only`
- Only necessary capabilities for device access

## Troubleshooting

### Permission Issues
If USB/device monitoring fails:
```nix
services.secmon.extraGroups = [ "audio" "video" "input" "plugdev" ];
```

### Socket Connection Issues
Check socket permissions and path:
```bash
ls -la /run/secmon/secmon.sock
systemctl status secmon
```

### Missing Events
Verify paths exist and monitoring is enabled:
```bash
# Check if camera devices exist
ls -la /dev/video*

# Verify configuration
nix eval .#nixosConfigurations.yourhost.config.services.secmon.settings
```

## Performance

- **Zero polling** - All monitoring is event-driven
- **Minimal CPU usage** - Idles at ~0% CPU
- **Low memory footprint** - ~5-10MB resident memory
- **Efficient IPC** - Unix domain sockets with JSON streaming

## Development

```bash
# Enter development environment
nix develop

# Build and test
cargo build --release
cargo test

# Run locally
sudo ./target/release/secmon-daemon example-config.toml
```