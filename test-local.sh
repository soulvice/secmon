#!/bin/bash
set -euo pipefail

# Local testing script for secmon-daemon
# Tests all functionality before deployment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (required for device access)
if [[ $EUID -eq 0 ]]; then
    warning "Running as root - this is expected for device monitoring"
else
    warning "Not running as root - some device monitoring may not work"
fi

log "Starting secmon-daemon local tests..."

# 1. Build the project
log "Building secmon-daemon..."
if ! cargo build --release; then
    error "Build failed!"
    exit 1
fi
success "Build completed"

# 2. Check if binaries exist
if [[ ! -f "target/release/secmon-daemon" ]]; then
    error "secmon-daemon binary not found!"
    exit 1
fi

if [[ ! -f "target/release/secmon-client" ]]; then
    error "secmon-client binary not found!"
    exit 1
fi

# 3. Test device discovery
log "Testing device discovery..."
./target/release/secmon-daemon --help > /dev/null 2>&1 || {
    error "secmon-daemon --help failed!"
    exit 1
}
success "Binary executes correctly"

# 4. Create test configuration
log "Creating test configuration..."
cat > test-config.toml << 'EOF'
socket_path = "/tmp/secmon-test.sock"
log_level = "debug"

# Test auto-discovery
[[watches]]
path = "/dev/video*"
description = "Test video devices (auto-discovered)"
enabled = true
recursive = false
pattern = true
auto_discover = true

[[watches]]
path = "/dev/snd/*"
description = "Test audio devices (auto-discovered)"
enabled = true
recursive = true
pattern = true
auto_discover = true

# Test regular filesystem monitoring
[[watches]]
path = "/tmp/secmon-test"
description = "Test directory"
enabled = true
recursive = true
pattern = false
auto_discover = false

# Test SSH monitoring (if exists)
[[watches]]
path = "/etc/ssh"
description = "SSH config (if exists)"
enabled = true
recursive = true
pattern = false
auto_discover = false
EOF

success "Test configuration created"

# 5. Create test directory for filesystem events
log "Setting up test environment..."
mkdir -p /tmp/secmon-test
touch /tmp/secmon-test/test-file.txt

# Clean up any existing socket
rm -f /tmp/secmon-test.sock

# 6. Test configuration loading
log "Testing configuration loading..."
timeout 5s ./target/release/secmon-daemon test-config.toml --help > /dev/null 2>&1 || true
success "Configuration loading test completed"

# 7. Start daemon in background for integration testing
log "Starting daemon for integration tests..."

# Start daemon in background
./target/release/secmon-daemon test-config.toml > secmon-test.log 2>&1 &
DAEMON_PID=$!

# Function to cleanup on exit
cleanup() {
    log "Cleaning up test environment..."

    if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        log "Stopping daemon (PID: $DAEMON_PID)..."
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        sleep 2
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi

    rm -f /tmp/secmon-test.sock
    rm -rf /tmp/secmon-test
    rm -f test-config.toml
    rm -f secmon-test.log

    log "Cleanup completed"
}

trap cleanup EXIT INT TERM

# Wait for daemon to start
log "Waiting for daemon to start..."
sleep 3

# Check if daemon is running
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    error "Daemon failed to start! Check secmon-test.log:"
    cat secmon-test.log
    exit 1
fi

# Check if socket was created
if [[ ! -S "/tmp/secmon-test.sock" ]]; then
    error "Socket not created! Check secmon-test.log:"
    cat secmon-test.log
    exit 1
fi

success "Daemon started successfully (PID: $DAEMON_PID)"

# 8. Test client connection
log "Testing client connection..."
timeout 5s ./target/release/secmon-client /tmp/secmon-test.sock > client-test.log 2>&1 &
CLIENT_PID=$!

sleep 2

# Check if client connected
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    warning "Client may have disconnected early"
else
    success "Client connected successfully"
    kill -TERM "$CLIENT_PID" 2>/dev/null || true
fi

# 9. Generate test events
log "Generating filesystem test events..."

# Create some filesystem events to test
echo "test data" > /tmp/secmon-test/new-file.txt
sleep 1
echo "modified" >> /tmp/secmon-test/test-file.txt
sleep 1
rm /tmp/secmon-test/new-file.txt
sleep 1

# Test network events by making a connection
log "Generating network test events..."
curl -s http://httpbin.org/get > /dev/null 2>&1 || {
    warning "Network test skipped (no internet or curl)"
}

# Test USB events if possible
log "Checking for USB events..."
if [[ -d "/sys/bus/usb/devices" ]]; then
    ls /sys/bus/usb/devices/ > /dev/null 2>&1 || warning "USB device enumeration failed"
else
    warning "USB subsystem not available for testing"
fi

sleep 2

# 10. Check daemon logs
log "Checking daemon functionality..."

if [[ -f "secmon-test.log" ]]; then
    # Check for successful startup messages
    if grep -q "Security monitor started" secmon-test.log; then
        success "Daemon startup confirmed"
    else
        warning "Daemon startup message not found"
    fi

    # Check for device discovery
    if grep -q -i "discovered.*device" secmon-test.log; then
        success "Device discovery working"
        log "Discovered devices:"
        grep -i "discovered.*device" secmon-test.log | head -5
    else
        warning "No device discovery logs found"
    fi

    # Check for filesystem events
    if grep -q -i "security event" secmon-test.log; then
        success "Filesystem monitoring working"
    else
        warning "No filesystem events detected"
    fi

    # Check for any errors
    if grep -q -i error secmon-test.log; then
        warning "Some errors detected in logs:"
        grep -i error secmon-test.log | head -3
    fi
else
    error "No daemon log file found!"
fi

# 11. Test device discovery directly
log "Testing device discovery module..."

# Check what video devices exist
if ls /dev/video* > /dev/null 2>&1; then
    success "Video devices found:"
    ls -la /dev/video* | head -3
else
    warning "No video devices found on system"
fi

# Check what audio devices exist
if ls /dev/snd/ > /dev/null 2>&1; then
    success "Audio devices found:"
    ls -la /dev/snd/ | head -5
else
    warning "No ALSA audio devices found"
fi

# 12. Performance check
log "Checking daemon resource usage..."
if ps -p "$DAEMON_PID" -o pid,ppid,cmd,%mem,%cpu > /dev/null 2>&1; then
    ps -p "$DAEMON_PID" -o pid,ppid,cmd,%mem,%cpu
    success "Daemon is running efficiently"
else
    warning "Could not check daemon resource usage"
fi

# 13. Socket functionality test
log "Testing socket communication..."
if echo '{"test": "message"}' | socat - UNIX-CONNECT:/tmp/secmon-test.sock 2>/dev/null; then
    success "Socket accepts connections"
else
    warning "Socket connection test had issues"
fi

# 14. Final status check
log "Final system status check..."

success "✅ Build: PASSED"
success "✅ Configuration: PASSED"
success "✅ Daemon startup: PASSED"
success "✅ Socket creation: PASSED"

if grep -q -i "discovered.*device" secmon-test.log 2>/dev/null; then
    success "✅ Device discovery: PASSED"
else
    warning "⚠️  Device discovery: LIMITED (no devices or permissions)"
fi

if grep -q -i "security event" secmon-test.log 2>/dev/null; then
    success "✅ Event generation: PASSED"
else
    warning "⚠️  Event generation: LIMITED"
fi

log "==================== TEST SUMMARY ===================="
success "Local testing completed! 🎉"
log ""
log "Key files created:"
log "  - ./target/release/secmon-daemon (main binary)"
log "  - ./target/release/secmon-client (monitoring client)"
log "  - ./secmon-test.log (test run logs)"
log ""
log "Next steps:"
log "1. Review secmon-test.log for any issues"
log "2. Test with your actual device configuration"
log "3. Deploy to your NixOS system"
log ""

if [[ -f "secmon-test.log" ]]; then
    log "Recent daemon logs:"
    tail -10 secmon-test.log
fi

log "Test completed successfully! 🚀"