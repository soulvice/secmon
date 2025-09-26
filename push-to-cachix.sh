#!/usr/bin/env bash
set -euo pipefail

# Configuration
CACHE_NAME="${1:-soulvice}"  # Default to soulvice, but allow override
SYSTEMS="x86_64-linux"  # Add more systems as needed: "x86_64-linux aarch64-linux"

echo "🚀 Building and pushing secmon-daemon to Cachix cache: $CACHE_NAME"

# Build for each system and push
for system in $SYSTEMS; do
    echo "📦 Building for $system..."

    # Build the main package
    echo "  Building secmon-daemon..."
    nix build ".#packages.$system.secmon-daemon" --print-out-paths | cachix push "$CACHE_NAME"

    # Build the development shell
    echo "  Building development shell..."
    nix build ".#devShells.$system.default" --print-out-paths | cachix push "$CACHE_NAME"

    echo "✅ Pushed $system packages to $CACHE_NAME"
done

echo "🎉 All packages pushed to https://app.cachix.org/cache/$CACHE_NAME"
echo ""
echo "📋 Users can now use your cache with:"
echo "  cachix use $CACHE_NAME"
echo ""
echo "Or add to their flake.nix:"
echo "  nixConfig = {"
echo "    extra-substituters = [ \"https://$CACHE_NAME.cachix.org\" ];"
echo "    extra-trusted-public-keys = [ \"$CACHE_NAME.cachix.org-1:...\" ];"
echo "  };"