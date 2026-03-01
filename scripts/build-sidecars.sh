#!/bin/bash
# Build sidecar binaries for the current platform and copy to src-tauri/binaries/.
# Builds: pubky-node, pkdns, pubky-homeserver
# Downloads: cloudflared (if not cached)
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

# ─── Build pubky-node ───────────────────────────────────────────
echo "Building pubky-node..."
cargo build $CARGO_FLAGS --manifest-path "$PROJECT_DIR/Cargo.toml"
cp "$PROJECT_DIR/target/$PROFILE_DIR/pubky-node${EXT}" \
   "$BINARIES_DIR/pubky-node-${TARGET}${EXT}"
echo "  → $BINARIES_DIR/pubky-node-${TARGET}${EXT}"

# ─── Build pkdns (sibling repo) ────────────────────────────────
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

# ─── Build pubky-homeserver (sibling repo pubky-core) ──────────
PUBKY_CORE_DIR="$(dirname "$PROJECT_DIR")/pubky-core"
if [ -d "$PUBKY_CORE_DIR" ]; then
    echo "Building pubky-homeserver..."
    cargo build $CARGO_FLAGS --manifest-path "$PUBKY_CORE_DIR/Cargo.toml" --bin pubky-homeserver 2>/dev/null || \
    cargo build $CARGO_FLAGS --manifest-path "$PUBKY_CORE_DIR/Cargo.toml"
    if [ -f "$PUBKY_CORE_DIR/target/$PROFILE_DIR/pubky-homeserver${EXT}" ]; then
        cp "$PUBKY_CORE_DIR/target/$PROFILE_DIR/pubky-homeserver${EXT}" \
           "$BINARIES_DIR/pubky-homeserver-${TARGET}${EXT}"
        echo "  → $BINARIES_DIR/pubky-homeserver-${TARGET}${EXT}"
    else
        echo "Warning: pubky-homeserver binary not found after build"
    fi
else
    echo "Warning: pubky-core not found at $PUBKY_CORE_DIR"
    echo "  pubky-homeserver sidecar will not be included"
fi

# ─── Download cloudflared (prebuilt) ───────────────────────────
CLOUDFLARED_BIN="$BINARIES_DIR/cloudflared-${TARGET}${EXT}"
if [ -f "$CLOUDFLARED_BIN" ]; then
    echo "cloudflared already cached at $CLOUDFLARED_BIN"
else
    echo "Downloading cloudflared..."
    CF_VERSION="2024.12.2"
    case "$TARGET" in
        *-apple-darwin)
            # Universal macOS binary
            CF_URL="https://github.com/cloudflare/cloudflared/releases/download/${CF_VERSION}/cloudflared-darwin-amd64.tgz"
            if [[ "$TARGET" == "aarch64"* ]]; then
                CF_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz"
            fi
            curl -sL "$CF_URL" | tar xz -C /tmp/ 2>/dev/null || true
            if [ -f /tmp/cloudflared ]; then
                mv /tmp/cloudflared "$CLOUDFLARED_BIN"
            else
                # Try direct binary download
                curl -sL -o "$CLOUDFLARED_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64"
            fi
            ;;
        x86_64-unknown-linux*)
            curl -sL -o "$CLOUDFLARED_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
            ;;
        aarch64-unknown-linux*)
            curl -sL -o "$CLOUDFLARED_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
            ;;
        *windows*)
            curl -sL -o "$CLOUDFLARED_BIN" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
            ;;
        *)
            echo "Warning: No cloudflared binary available for target $TARGET"
            ;;
    esac
    if [ -f "$CLOUDFLARED_BIN" ]; then
        chmod +x "$CLOUDFLARED_BIN"
        echo "  → $CLOUDFLARED_BIN"
    fi
fi

echo ""
echo "Sidecar binaries ready in $BINARIES_DIR/"
ls -lh "$BINARIES_DIR/"
