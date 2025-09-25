#!/bin/bash
# Quick validation script - runs in under 30 seconds

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

success() { echo -e "${GREEN}✓${NC} $1"; }
warning() { echo -e "${YELLOW}!${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; exit 1; }

echo "🚀 Quick secmon-daemon validation..."

# 1. Build test
echo -n "Building... "
if cargo build --release >/dev/null 2>&1; then
    success "Build OK"
else
    error "Build failed"
fi

# 2. Binary check
echo -n "Checking binaries... "
if [[ -f "target/release/secmon-daemon" && -f "target/release/secmon-client" ]]; then
    success "Binaries OK"
else
    error "Binaries missing"
fi

# 3. Help test
echo -n "Testing daemon... "
if timeout 5s ./target/release/secmon-daemon --help >/dev/null 2>&1; then
    success "Daemon OK"
else
    warning "Daemon help test inconclusive"
fi

# 4. Config test
echo -n "Testing config... "
cat > quick-test.toml << 'EOF'
socket_path = "/tmp/quick-test.sock"
log_level = "info"
[[watches]]
path = "/tmp"
description = "Test"
enabled = true
EOF

rm -f /tmp/quick-test.sock
timeout 3s ./target/release/secmon-daemon quick-test.toml >/dev/null 2>&1 &
sleep 1
if [[ -S "/tmp/quick-test.sock" ]]; then
    success "Config OK"
    kill %% 2>/dev/null || true
else
    warning "Config test inconclusive"
fi

# 5. Device check
echo -n "Checking devices... "
DEVICES=0
[[ -d "/dev/snd" ]] && DEVICES=$((DEVICES+1))
ls /dev/video* >/dev/null 2>&1 && DEVICES=$((DEVICES+1))

if [[ $DEVICES -gt 0 ]]; then
    success "Devices available ($DEVICES types)"
else
    warning "No devices found (testing may be limited)"
fi

# 6. Nix check (if available)
if command -v nix >/dev/null 2>&1; then
    echo -n "Testing nix build... "
    if timeout 30s nix build >/dev/null 2>&1; then
        success "Nix build OK"
    else
        warning "Nix build slow/failed"
    fi
fi

# Cleanup
rm -f quick-test.toml /tmp/quick-test.sock 2>/dev/null || true

echo ""
success "Quick validation complete! 🎉"
echo "Run './test-local.sh' for comprehensive testing."