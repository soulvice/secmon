# Dynamic Device Discovery

The security monitor now automatically discovers and monitors **all** video and audio devices on your system, not just hardcoded ones like `/dev/video0`.

## 🎯 Auto-Discovery Features

### Camera/Video Devices
**Automatically discovers:**
- `/dev/video0`, `/dev/video1`, `/dev/video2`, ... (all video devices)
- `/dev/v4l/by-id/*` (descriptive V4L device names)
- Verifies devices are actual video capture devices via `/sys/class/video4linux/`

### Microphone/Audio Devices
**Automatically discovers:**
- `/dev/snd/pcm*` (ALSA PCM devices)
- `/dev/snd/control*` (ALSA control interfaces)
- `/tmp/.pulse*` (PulseAudio temporary files)
- `/run/user/*/pulse` (User-specific PulseAudio)
- `/var/lib/pulse` (System PulseAudio)
- JACK audio system paths

## 🔧 Configuration Options

### Automatic Discovery (Recommended)
```nix
services.secmon = {
  enable = true;

  monitors = {
    camera = true;      # Auto-discovers ALL video devices
    microphone = true;  # Auto-discovers ALL audio devices
  };
};
```

### Manual Pattern Matching
```nix
services.secmon = {
  enable = true;

  watches = [
    {
      path = "/dev/video*";           # Glob pattern
      description = "All cameras";
      pattern = true;                 # Enable pattern matching
      auto_discover = false;          # Use glob only
    }
    {
      path = "/dev/snd/pcm*";        # Specific audio pattern
      description = "ALSA PCM devices";
      pattern = true;
      recursive = false;
    }
  ];
};
```

### Advanced Auto-Discovery
```nix
services.secmon = {
  watches = [
    {
      path = "/dev/video*";
      description = "Cameras";
      auto_discover = true;           # Smart discovery + verification
      pattern = true;                 # Fallback to pattern matching
    }
  ];
};
```

## 🚀 How It Works

### Smart Discovery Process
1. **Device Enumeration**: Scans `/dev/` for device files matching patterns
2. **Device Verification**: Checks if devices are actual video/audio hardware
3. **Capability Detection**: Verifies device capabilities via sysfs
4. **Dynamic Monitoring**: Sets up inotify watches for all discovered devices

### Example Discovery Output
```
INFO: Discovered video device: /dev/video0
INFO: Discovered video device: /dev/video2
INFO: Discovered V4L device: /dev/v4l/by-id/usb-046d_HD_Pro_Webcam_C920-video-index0
INFO: Discovered ALSA device: /dev/snd/pcmC0D0c
INFO: Discovered ALSA device: /dev/snd/pcmC1D0c
INFO: Discovered PulseAudio path: /run/user/1000/pulse
```

## 📊 Comparison: Before vs After

### Before (Static Configuration)
```toml
[[watches]]
path = "/dev/video0"       # Only monitors video0
description = "Camera"

[[watches]]
path = "/dev/video1"       # Must manually add each device
description = "Second camera"
```
**Problem**: Misses `/dev/video2`, `/dev/video3`, USB cameras, etc.

### After (Dynamic Discovery)
```nix
services.secmon.monitors.camera = true;
```
**Result**: Automatically finds and monitors:
- `/dev/video0`, `/dev/video1`, `/dev/video2` (built-in cameras)
- `/dev/video3` (USB webcam)
- `/dev/v4l/by-id/usb-*` (descriptive names)
- Any new video devices plugged in

## 🔍 Device Types Detected

### Video Devices
- **Webcams**: USB cameras, built-in laptop cameras
- **Capture Cards**: HDMI/video input devices
- **Virtual Cameras**: OBS virtual cam, v4l2loopback
- **Security Cameras**: IP cameras with V4L drivers

### Audio Devices
- **Microphones**: USB mics, built-in mics, XLR interfaces
- **Audio Interfaces**: Professional audio equipment
- **Virtual Audio**: PulseAudio, JACK virtual devices
- **System Audio**: ALSA hardware devices

## ⚡ Performance Benefits

- **Zero Configuration**: Works out of the box
- **Complete Coverage**: Never miss a device
- **Future Proof**: Automatically handles new hardware
- **Efficient**: Only monitors devices that actually exist

## 🛠️ Manual Override

If you need specific control:

```nix
services.secmon = {
  enable = true;

  # Disable auto-discovery
  monitors.camera = false;
  monitors.microphone = false;

  # Manual device specification
  watches = [
    {
      path = "/dev/video0";
      description = "Only this specific camera";
      auto_discover = false;
      pattern = false;
    }
  ];
};
```

## 🔧 Troubleshooting

### No Devices Found
```bash
# Check if devices exist
ls -la /dev/video*
ls -la /dev/snd/

# Check secmon logs
journalctl -u secmon -f
```

### Partial Discovery
```bash
# Enable debug logging
services.secmon.settings.log_level = "debug";

# Check which devices were discovered
journalctl -u secmon | grep "Discovered"
```

### Permission Issues
```bash
# Ensure secmon user has device access
services.secmon.extraGroups = [ "audio" "video" "plugdev" ];
```

The dynamic discovery system ensures you never miss security events from new cameras, microphones, or audio devices - whether they're built-in, USB-connected, or virtual devices.