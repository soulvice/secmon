#!/bin/bash
set -euo pipefail

# Device simulation script for testing secmon-daemon
# Creates fake devices and events to test monitoring without real hardware

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[SIM]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check for root (needed for some device simulation)
if [[ $EUID -ne 0 ]]; then
    warning "Not running as root - some device simulation may not work"
    warning "Run with: sudo $0"
fi

SIMULATION_DIR="/tmp/secmon-device-simulation"
FAKE_DEV_DIR="$SIMULATION_DIR/dev"

cleanup() {
    log "Cleaning up device simulation..."
    rm -rf "$SIMULATION_DIR"

    # Stop any v4l2loopback devices
    if command -v modprobe >/dev/null 2>&1; then
        modprobe -r v4l2loopback 2>/dev/null || true
    fi

    log "Simulation cleanup completed"
}

trap cleanup EXIT INT TERM

log "Setting up device simulation environment..."

# Create simulation directories
mkdir -p "$FAKE_DEV_DIR"/{snd,v4l/by-id}
mkdir -p "$SIMULATION_DIR"/{pulse,jack}

# Function to create fake video devices
create_fake_video_devices() {
    log "Creating fake video devices..."

    # Create fake video device files
    for i in {0..3}; do
        touch "$FAKE_DEV_DIR/video$i"
        log "Created fake /dev/video$i"
    done

    # Create fake V4L by-id devices
    touch "$FAKE_DEV_DIR/v4l/by-id/usb-046d_HD_Pro_Webcam_C920-video-index0"
    touch "$FAKE_DEV_DIR/v4l/by-id/usb-Generic_USB_Camera-video-index0"

    success "Created 6 fake video devices"
}

# Function to create fake audio devices
create_fake_audio_devices() {
    log "Creating fake audio devices..."

    # ALSA PCM devices
    for card in {0..2}; do
        for device in {0..1}; do
            touch "$FAKE_DEV_DIR/snd/pcmC${card}D${device}c" # capture
            touch "$FAKE_DEV_DIR/snd/pcmC${card}D${device}p" # playback
        done
        touch "$FAKE_DEV_DIR/snd/controlC${card}"
    done

    # Other ALSA devices
    touch "$FAKE_DEV_DIR/snd/seq"
    touch "$FAKE_DEV_DIR/snd/timer"

    # PulseAudio paths
    mkdir -p "$SIMULATION_DIR/pulse"/{server,cli}
    touch "$SIMULATION_DIR/pulse/native"

    # Fake user PulseAudio directories
    for uid in 1000 1001; do
        mkdir -p "$SIMULATION_DIR/run/user/$uid/pulse"
        touch "$SIMULATION_DIR/run/user/$uid/pulse/native"
    done

    success "Created fake audio devices"
}

# Function to try creating real v4l2loopback devices
create_real_video_loopback() {
    if ! command -v modprobe >/dev/null 2>&1; then
        warning "modprobe not available - skipping real video device creation"
        return
    fi

    log "Attempting to create real v4l2loopback devices..."

    # Try to load v4l2loopback module (creates real /dev/video devices)
    if modprobe v4l2loopback devices=2 video_nr=10,11 card_label="SecMon Test Camera 1,SecMon Test Camera 2" 2>/dev/null; then
        success "Created real v4l2loopback devices at /dev/video10 and /dev/video11"

        # These will show up as real video devices that secmon can monitor
        if [[ -c /dev/video10 ]]; then
            success "Real test camera available at /dev/video10"
        fi

        if [[ -c /dev/video11 ]]; then
            success "Real test camera available at /dev/video11"
        fi
    else
        warning "Could not create v4l2loopback devices (module not available or no permissions)"
    fi
}

# Function to generate test events
generate_test_events() {
    log "Generating test events..."

    # Test directory for filesystem events
    TEST_DIR="/tmp/secmon-test-events"
    mkdir -p "$TEST_DIR"

    # Generate filesystem events
    log "Creating filesystem events..."
    echo "test file 1" > "$TEST_DIR/test1.txt"
    sleep 0.5
    echo "test file 2" > "$TEST_DIR/test2.txt"
    sleep 0.5
    echo "modified content" >> "$TEST_DIR/test1.txt"
    sleep 0.5
    rm "$TEST_DIR/test2.txt"
    sleep 0.5

    # Try to generate network events
    log "Generating network events..."
    if command -v curl >/dev/null 2>&1; then
        curl -s --connect-timeout 5 http://httpbin.org/get > /dev/null 2>&1 || {
            warning "Network event generation failed"
        }
    fi

    # Simulate audio device access
    if [[ -c /dev/snd/pcmC0D0c ]]; then
        log "Attempting to access real audio device..."
        # Just try to open the device (this will generate an access event)
        timeout 1s cat /dev/snd/pcmC0D0c > /dev/null 2>&1 || {
            log "Audio device access attempt completed (expected to fail)"
        }
    fi

    success "Test events generated"
}

# Function to create a custom test config that uses our simulated devices
create_test_config() {
    log "Creating test configuration..."

    cat > device-test-config.toml << EOF
socket_path = "/tmp/secmon-device-test.sock"
log_level = "debug"

# Test both real and simulated video devices
[[watches]]
path = "/dev/video*"
description = "All video devices (real + simulated)"
enabled = true
recursive = false
pattern = true
auto_discover = true

# Test real audio devices
[[watches]]
path = "/dev/snd/*"
description = "Real ALSA audio devices"
enabled = true
recursive = true
pattern = true
auto_discover = true

# Test filesystem monitoring
[[watches]]
path = "/tmp/secmon-test-events"
description = "Test events directory"
enabled = true
recursive = true
pattern = false
auto_discover = false

# Test SSH monitoring (if available)
[[watches]]
path = "/home/$USER/.ssh"
description = "User SSH directory"
enabled = true
recursive = true
pattern = false
auto_discover = false
EOF

    success "Test configuration created: device-test-config.toml"
}

# Main simulation setup
log "Starting device simulation setup..."

create_fake_video_devices
create_fake_audio_devices
create_real_video_loopback  # This creates actual /dev/video devices if possible
create_test_config

log "Device simulation setup complete!"

log ""
log "==================== SIMULATION STATUS ===================="
log "Real video devices available:"
ls -la /dev/video* 2>/dev/null || warning "No real video devices found"

log ""
log "Real audio devices available:"
ls -la /dev/snd/ 2>/dev/null || warning "No real audio devices found"

log ""
log "Fake devices created in: $FAKE_DEV_DIR"
ls -la "$FAKE_DEV_DIR"/ 2>/dev/null || true

log ""
log "==================== TESTING INSTRUCTIONS =================="
success "1. Build and test with simulated devices:"
log "   ./test-local.sh"

success "2. Test with custom device config:"
log "   cargo run -- device-test-config.toml"

success "3. Monitor events in another terminal:"
log "   ./target/release/secmon-client /tmp/secmon-device-test.sock"

success "4. Generate test events:"
log "   ./simulate-devices.sh generate_events"

log ""
if [[ "${1:-}" == "generate_events" ]]; then
    generate_test_events
    log "Test events generated! Check your secmon client for events."
else
    log "Device simulation complete. Use 'generate_events' argument to create test events."
fi

log "Run with --help to see available commands"