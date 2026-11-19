#!/usr/bin/env bash
set -euo pipefail

# Astrika installer / updater for Ubuntu 20.04, 22.04, 24.04 (x86_64)
# Usage:
#   sudo ./install.sh [port] [service_name]
#   sudo ASTRIKA_REPO="owner/astrika" bash -c "$(curl -fsSL https://raw.githubusercontent.com/owner/astrika/main/install.sh)"

PORT="${1:-8000}"
SVC_NAME="${2:-astrika}"
REPO="${ASTRIKA_REPO:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Error: please run as root (sudo)." >&2
  exit 1
fi

ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" ]]; then
  echo "Warning: detected $ARCH; static prebuilt binary targets x86_64. Will build from source if Cargo is available."
fi

install_bin=""

if [[ -x "$SCRIPT_DIR/astrika" && "$ARCH" == "x86_64" ]]; then
  install_bin="$SCRIPT_DIR/astrika"
elif [[ -n "$REPO" && "$ARCH" == "x86_64" ]]; then
  tmp_bin="$(mktemp /tmp/astrika.XXXXXX)"
  echo "[*] Downloading prebuilt static binary from GitHub ($REPO)..."
  if curl -fsSL "https://github.com/${REPO}/releases/latest/download/astrika-linux-x86_64-musl" -o "$tmp_bin"; then
    chmod 755 "$tmp_bin"
    install_bin="$tmp_bin"
  elif curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/astrika" -o "$tmp_bin"; then
    chmod 755 "$tmp_bin"
    install_bin="$tmp_bin"
  else
    rm -f "$tmp_bin"
  fi
fi

if [[ -z "$install_bin" ]]; then
  if [[ -f "$SCRIPT_DIR/Cargo.toml" ]]; then
    echo "[*] Building Astrika from source..."
    if ! command -v cargo >/dev/null 2>&1; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
      # shellcheck disable=SC1091
      source "$HOME/.cargo/env"
    fi
    if [[ "$ARCH" == "x86_64" ]]; then
      "$SCRIPT_DIR/build-static.sh"
      install_bin="$SCRIPT_DIR/astrika"
    else
      (cd "$SCRIPT_DIR" && cargo build --release)
      install_bin="$SCRIPT_DIR/target/release/astrika"
    fi
  else
    echo "Error: no binary or Cargo.toml found. Set ASTRIKA_REPO=owner/astrika or clone the repository first." >&2
    exit 1
  fi
fi

echo "[*] Installing binary to /usr/bin/astrika ..."
install -m 0755 "$install_bin" /usr/bin/astrika

if [[ "$install_bin" == /tmp/astrika.* ]]; then
  rm -f "$install_bin"
fi

echo "[*] Initializing systemd service ($SVC_NAME on port $PORT)..."
if [[ "$SVC_NAME" == "astrika" && "$PORT" == "8000" ]]; then
  /usr/bin/astrika init 8000 --start
else
  /usr/bin/astrika init "$PORT" "$SVC_NAME" --start
fi

echo ""
echo "[+] Astrika is installed and running!"
echo "    Web UI:  http://$(hostname -I | awk '{print $1}'):${PORT}/"
echo "    Status:  systemctl status ${SVC_NAME}"
echo "    Logs:    journalctl -u ${SVC_NAME} -f"
