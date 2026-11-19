#!/usr/bin/env bash
set -euo pipefail

# Builds a fully static x86_64-unknown-linux-musl binary that runs on
# Ubuntu 20.04, 22.04, 24.04 (and any Linux x86_64 kernel >= 4.15)
# with ZERO glibc/OpenSSL runtime dependencies.

TARGET="x86_64-unknown-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Install Rust from https://rustup.rs" >&2
  exit 1
fi

rustup target add "$TARGET" >/dev/null 2>&1 || true

if command -v musl-gcc >/dev/null 2>&1; then
  export CC_x86_64_unknown_linux_musl=musl-gcc
fi
export RUSTFLAGS="-C target-feature=+crt-static"

echo "[*] Building static release binary for $TARGET ..."
cargo build --release --target "$TARGET"

BIN="target/$TARGET/release/astrika"
cp -f "$BIN" ./astrika
chmod 755 ./astrika

echo "[+] Built: $SCRIPT_DIR/astrika"
file ./astrika || true
ls -lh ./astrika
