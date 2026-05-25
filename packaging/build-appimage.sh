#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$PROJECT_ROOT/packaging/out"
APP_DIR="$OUT_DIR/icb-installer.AppDir"
VERSION=$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')
ARCH="x86_64"

echo "=== Building icb-sandbox $VERSION (musl static) ==="

# Build in Alpine container
docker build --network=host -f "$SCRIPT_DIR/Dockerfile.musl" -t icb-sandbox-builder "$PROJECT_ROOT"

# Extract binaries
rm -rf "$OUT_DIR"
mkdir -p "$APP_DIR/usr/bin" "$APP_DIR/usr/sbin" "$APP_DIR/etc"

CONTAINER=$(docker create icb-sandbox-builder)
docker cp "$CONTAINER:/build/target/x86_64-unknown-linux-musl/release/icb-sandboxd" "$APP_DIR/usr/sbin/"
docker cp "$CONTAINER:/build/target/x86_64-unknown-linux-musl/release/icb-sandbox-ctl" "$APP_DIR/usr/bin/"
docker cp "$CONTAINER:/build/target/x86_64-unknown-linux-musl/release/icb-sandbox-bootstrap" "$APP_DIR/usr/bin/"
docker rm "$CONTAINER"

# Copy service files and default policy
cp "$PROJECT_ROOT/config/icb-sandboxd.service" "$APP_DIR/etc/"
cp "$PROJECT_ROOT/config/icb-sandbox-bootstrap.service" "$APP_DIR/etc/"
cp "$PROJECT_ROOT/config/policy.toml" "$APP_DIR/etc/default-policy.toml"

# Find and bundle icb-agent binary
ICB_AGENT=$(find "$PROJECT_ROOT/.." -maxdepth 3 -name "icb-agent" -type f -executable -print -quit 2>/dev/null)
if [ -z "$ICB_AGENT" ]; then
  ICB_AGENT=$(find "$(pwd)" -maxdepth 3 -name "icb-agent" -type f -executable -print -quit 2>/dev/null)
fi
if [ -z "$ICB_AGENT" ]; then
  echo "WARNING: icb-agent binary not found nearby. AppImage will not include icb-agent."
  echo "  Place icb-agent binary in the project root or a sibling directory and re-run."
else
  echo "Bundling icb-agent from: $ICB_AGENT"
  cp "$ICB_AGENT" "$APP_DIR/usr/bin/icb-agent"
fi

# Copy BPF object file
mkdir -p "$APP_DIR/usr/lib/icb-sandbox"
BPF_OBJ=$(find "$PROJECT_ROOT" -path "*/bpfel-unknown-none/release/bpfjailer.bpf.o" -print -quit)
if [ -z "$BPF_OBJ" ]; then
  BPF_OBJ=$(find "$PROJECT_ROOT" -path "*/bpfel-unknown-none/debug/bpfjailer.bpf.o" -print -quit)
fi
if [ -z "$BPF_OBJ" ]; then
  echo "ERROR: bpfjailer.bpf.o not found. Build the BPF crate first."
  exit 1
fi
cp "$BPF_OBJ" "$APP_DIR/usr/lib/icb-sandbox/bpfjailer.bpf.o"

# Copy AppRun entry point
cp "$SCRIPT_DIR/AppRun" "$APP_DIR/AppRun"
chmod +x "$APP_DIR/AppRun"

# .desktop file (required by AppImage spec)
cat >"$APP_DIR/icb-installer.desktop" <<'DESKTOP'
[Desktop Entry]
Name=icb-installer
Exec=AppRun
Icon=icb-installer
Type=Application
Categories=System;Security;
DESKTOP

# Minimal icon (1x1 PNG placeholder)
printf '\x89PNG\r\n\x1a\n' >"$APP_DIR/icb-installer.png"

# Download appimagetool if not present
APPIMAGETOOL="$OUT_DIR/appimagetool"
if [ ! -x "$APPIMAGETOOL" ]; then
  echo "Downloading appimagetool..."
  curl -fsSL "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
    -o "$APPIMAGETOOL"
  chmod +x "$APPIMAGETOOL"
fi

# Build AppImage
export ARCH
"$APPIMAGETOOL" "$APP_DIR" "$OUT_DIR/icb-installer-${VERSION}-${ARCH}.AppImage"

echo "=== Done: $OUT_DIR/icb-installer-${VERSION}-${ARCH}.AppImage ==="
