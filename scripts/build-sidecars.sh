#!/bin/bash
# Build pubky-node and pkdns sidecar binaries for the current platform.
# Copies them to src-tauri/binaries/ with the required target triple suffix.
#
# Usage: ./scripts/build-sidecars.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARIES_DIR="$PROJECT_DIR/src-tauri/binaries"

# Detect target triple
TARGET=$(rustc --print host-tuple)
echo "Building for target: $TARGET"

# Determine build profile
PROFILE="release"
PROFILE_DIR="release"
CARGO_FLAGS="--release"
if [[ "${1:-}" != "--release" ]]; then
    PROFILE="debug"
    PROFILE_DIR="debug"
    CARGO_FLAGS=""
    echo "Building in debug mode (pass --release for release builds)"
fi

mkdir -p "$BINARIES_DIR"

# Extension for Windows
EXT=""
if [[ "$TARGET" == *"windows"* ]]; then
    EXT=".exe"
fi

# Build pubky-node
echo "Building pubky-node..."
cargo build $CARGO_FLAGS --manifest-path "$PROJECT_DIR/Cargo.toml"
cp "$PROJECT_DIR/target/$PROFILE_DIR/pubky-node${EXT}" \
   "$BINARIES_DIR/pubky-node-${TARGET}${EXT}"
echo "  → $BINARIES_DIR/pubky-node-${TARGET}${EXT}"

# Build pkdns (assumes pkdns repo is a sibling directory)
PKDNS_DIR="$(dirname "$PROJECT_DIR")/pkdns"
if [ -d "$PKDNS_DIR/server" ]; then
    echo "Building pkdns..."
    cargo build $CARGO_FLAGS --manifest-path "$PKDNS_DIR/server/Cargo.toml"
    cp "$PKDNS_DIR/target/$PROFILE_DIR/pkdns${EXT}" \
       "$BINARIES_DIR/pkdns-${TARGET}${EXT}"
    echo "  → $BINARIES_DIR/pkdns-${TARGET}${EXT}"
else
    echo "Warning: pkdns not found at $PKDNS_DIR/server"
    echo "  pkdns sidecar will not be included"
fi

echo ""
echo "Sidecar binaries ready in $BINARIES_DIR/"
ls -lh "$BINARIES_DIR/"
