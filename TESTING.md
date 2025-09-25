# Testing Guide

Complete testing instructions for secmon-daemon before deployment.

## 🚀 Quick Test (2 minutes)

```bash
# Build and run comprehensive tests
./test-local.sh
```

This script tests:
- ✅ Build process
- ✅ Configuration loading
- ✅ Device discovery
- ✅ Daemon startup
- ✅ Socket communication
- ✅ Event generation
- ✅ Client connectivity

## 🔬 Detailed Testing

### 1. Build and Basic Functionality
```bash
# Build the project
cargo build --release

# Check binaries exist and run
./target/release/secmon-daemon --help
./target/release/secmon-client --help
```

### 2. Test Device Discovery
```bash
# Check what devices are actually available
ls -la /dev/video* 2>/dev/null || echo "No video devices"
ls -la /dev/snd/ 2>/dev/null || echo "No audio devices"

# Create simulated devices for testing
sudo ./simulate-devices.sh
```

### 3. Test Configuration
```bash
# Create test config
cat > test.toml << 'EOF'
socket_path = "/tmp/test-secmon.sock"
log_level = "debug"

[[watches]]
path = "/dev/video*"
description = "All cameras"
enabled = true
pattern = true
auto_discover = true

[[watches]]
path = "/tmp/test-monitoring"
description = "Test directory"
enabled = true
recursive = true
EOF

# Test config loading
mkdir -p /tmp/test-monitoring
./target/release/secmon-daemon test.toml
```

### 4. Test Real Device Monitoring
```bash
# Start daemon with your real devices
sudo ./target/release/secmon-daemon test.toml &

# In another terminal, monitor events
./target/release/secmon-client /tmp/test-secmon.sock

# Generate events by:
# - Accessing camera (open photo app)
# - Recording audio (open audio recorder)
# - Creating/modifying files in watched directories
# - Connecting USB devices
```

### 5. Test Network Monitoring
```bash
# With daemon running, make network connections
curl http://httpbin.org/get
ssh localhost  # (will fail but creates connection attempt)

# Check for network events in client output
```

### 6. Test USB Monitoring
```bash
# With daemon running (as root):
sudo ./target/release/secmon-daemon test.toml

# In another terminal:
./target/release/secmon-client /tmp/test-secmon.sock

# Plug/unplug USB devices to see events
# Or simulate with:
sudo ./simulate-devices.sh generate_events
```

## 🎯 NixOS Flake Testing

### Test Nix Build
```bash
# Test nix build (without installing)
nix build

# Check the built binary
./result/bin/secmon-daemon --help
```

### Test Development Shell
```bash
# Enter development environment
nix develop

# Should have all dependencies available
cargo build --release
```

### Test NixOS Module (VM)
```nix
# test-vm.nix
{
  imports = [ ./flake.nix ];

  services.secmon = {
    enable = true;
    monitors = {
      camera = true;
      microphone = true;
      network = true;
      usb = true;
    };
  };

  # VM configuration
  virtualisation.vmVariant = {
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
  };
}
```

```bash
# Build and test in VM
nixos-rebuild build-vm -I nixos-config=test-vm.nix
./result/bin/run-nixos-vm
```

## 🔍 Integration Tests

### Full System Test
```bash
# 1. Start comprehensive test
./test-local.sh 2>&1 | tee test-results.log

# 2. Check results
grep "PASSED\|FAILED" test-results.log

# 3. Review logs for issues
tail -50 secmon-test.log
```

### Performance Test
```bash
# Start daemon and monitor resource usage
sudo ./target/release/secmon-daemon test.toml &
DAEMON_PID=$!

# Monitor resources
watch -n 1 "ps -p $DAEMON_PID -o pid,ppid,cmd,%mem,%cpu,etime"

# Generate sustained load
for i in {1..100}; do
    echo "test $i" > /tmp/test-monitoring/file$i.txt
    sleep 0.1
done

# Check memory/CPU usage remains low
```

### Multi-Device Test
```bash
# Create multiple simulated cameras
sudo modprobe v4l2loopback devices=4 video_nr=10,11,12,13

# Verify discovery finds all devices
sudo ./target/release/secmon-daemon test.toml | grep -i "discovered"

# Should see:
# INFO: Discovered video device: /dev/video10
# INFO: Discovered video device: /dev/video11
# INFO: Discovered video device: /dev/video12
# INFO: Discovered video device: /dev/video13
```

## ✅ Pre-Deployment Checklist

Before pushing to GitHub and deploying:

- [ ] `./test-local.sh` passes all tests
- [ ] Device discovery finds your actual devices
- [ ] Camera/microphone access generates events
- [ ] Network connections are detected
- [ ] USB device insertion works
- [ ] No memory leaks or excessive CPU usage
- [ ] Socket communication works reliably
- [ ] Nix build succeeds: `nix build`
- [ ] NixOS module compiles without errors

### Expected Test Output
```
[OK] Build: PASSED
[OK] Configuration: PASSED
[OK] Daemon startup: PASSED
[OK] Socket creation: PASSED
[OK] Device discovery: PASSED
[OK] Event generation: PASSED
```

### Common Issues and Fixes

**"No devices found"**
- Check permissions: `sudo ./test-local.sh`
- Install v4l-utils: `nix-shell -p v4l-utils`
- Create test devices: `./simulate-devices.sh`

**"Permission denied" errors**
- Run as root: `sudo ./test-local.sh`
- Add user to groups: `usermod -a -G audio,video $USER`

**"Socket connection failed"**
- Check if daemon is running: `ps aux | grep secmon`
- Verify socket path: `ls -la /tmp/secmon*.sock`
- Check logs: `tail secmon-test.log`

**Build failures**
- Update Cargo.lock: `cargo update`
- Check dependencies: `nix develop`
- Clear build cache: `cargo clean && cargo build`

## 📊 Test Results Interpretation

The test suite will show:
- **Green [OK]**: Feature working correctly
- **Yellow [WARN]**: Feature working with limitations
- **Red [ERROR]**: Feature failed - needs fixing

You're ready to deploy when you see mostly green with only minor warnings!

## 🚢 Ready for Deployment

Once all tests pass:
1. Commit your changes
2. Push to GitHub
3. Deploy via NixOS flake
4. Monitor production logs

Your security monitoring daemon is ready for production! 🎉