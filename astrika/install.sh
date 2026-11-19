#!/usr/bin/env bash
# Ubuntu 20.04 / 22.04 / 24.04 & Debian one-command installer, updater, and uninstaller for Astrika (Static Rust Single Binary).
# Zero runtime dependencies (static-pie musl ELF) — identical in simplicity to astrag / Cesbo Astra.

set -euo pipefail

START=true
UNINSTALL=false
PURGE=false
FORCE_BUILD=false
REMOVE_ASTRAG=false
CUSTOM_PORT="${ASTRIKA_PORT:-8000}"
SVC_NAME="${ASTRIKA_SVC:-astrika}"
REPO_URL="${ASTRIKA_REPO_URL:-https://github.com/udemika/astrika.git}"
RAW_URL="${ASTRIKA_RAW_URL:-https://raw.githubusercontent.com/udemika/astrika/main/astrika/astrika}"
RAW_URL_ALT="https://raw.githubusercontent.com/udemika/astrika/main/astrika"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --start|--restart|--update) START=true; shift ;;
        --no-start) START=false; shift ;;
        --uninstall|--remove) UNINSTALL=true; shift ;;
        --purge) UNINSTALL=true; PURGE=true; shift ;;
        --build|--source|--compile) FORCE_BUILD=true; shift ;;
        --remove-astrag|--migrate-astrag) REMOVE_ASTRAG=true; shift ;;
        --port)
            if [ "$#" -lt 2 ]; then echo "Missing port number after --port" >&2; exit 2; fi
            CUSTOM_PORT="$2"; shift 2 ;;
        --name)
            if [ "$#" -lt 2 ]; then echo "Missing service name after --name" >&2; exit 2; fi
            SVC_NAME="$2"; shift 2 ;;
        --repo)
            if [ "$#" -lt 2 ]; then echo "Missing repository URL after --repo" >&2; exit 2; fi
            REPO_URL="$2"; shift 2 ;;
        --raw-url)
            if [ "$#" -lt 2 ]; then echo "Missing binary URL after --raw-url" >&2; exit 2; fi
            RAW_URL="$2"; shift 2 ;;
        [0-9]*)
            CUSTOM_PORT="$1"; shift ;;
        *)
            echo "Usage: sudo bash install.sh [--start|--no-start|--uninstall|--purge] [--build] [--remove-astrag] [--port PORT] [--name SVC] [--repo GIT_URL]" >&2
            exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: please run as root (sudo)." >&2
    exit 1
fi

if "$UNINSTALL"; then
    if [ -x /usr/bin/astrika ]; then
        if "$PURGE"; then
            /usr/bin/astrika purge || true
        else
            /usr/bin/astrika remove "$SVC_NAME" || true
        fi
    elif "$PURGE"; then
        rm -f /usr/bin/astrika
        rm -rf /etc/astrika /var/lib/astrika
    fi
    exit 0
fi

if "$REMOVE_ASTRAG"; then
    echo "==> Migrating config and removing legacy astrag..."
    mkdir -p /etc/astrika
    if [ -f /etc/astrag/astrag.conf ] && [ ! -f /etc/astrika/astrika.conf ]; then
        cp -a /etc/astrag/astrag.conf /etc/astrika/astrika.conf
        echo "    Copied /etc/astrag/astrag.conf -> /etc/astrika/astrika.conf"
    fi
    for u in /etc/systemd/system/astrag*.service; do
        [ -e "$u" ] || continue
        s="$(basename "$u" .service)"
        systemctl stop "$s" 2>/dev/null || true
        systemctl disable "$s" 2>/dev/null || true
        rm -f "$u"
    done
    systemctl daemon-reload || true
    rm -rf /etc/astrag /var/lib/astrag /usr/bin/astrag /usr/local/bin/astrag
fi

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

TMP_DIR=""
STAGING_BIN="/usr/bin/.astrika.new.$$"
cleanup_tmp() {
    rm -f "$STAGING_BIN" 2>/dev/null || true
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup_tmp EXIT

install_atomic() {
    local src="$1"
    cp -f "$src" "$STAGING_BIN"
    chown root:root "$STAGING_BIN" 2>/dev/null || true
    chmod 0755 "$STAGING_BIN"
    mv -f "$STAGING_BIN" /usr/bin/astrika
}

build_from_source() {
    local src_dir="$1"
    echo "==> Building static Rust binary Astrika from $src_dir..."
    if ! command -v cargo >/dev/null 2>&1; then
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
    if [ "$(uname -m)" = "x86_64" ]; then
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq musl-tools ca-certificates || true
        "$src_dir/build-static.sh"
        install_atomic "$src_dir/astrika"
    else
        (cd "$src_dir" && cargo build --release)
        install_atomic "$src_dir/target/release/astrika"
    fi
}

ARCH="$(uname -m)"
INSTALLED_BIN=false

if ! "$FORCE_BUILD" && [ "$ARCH" = "x86_64" ]; then
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/astrika" ] && "$SCRIPT_DIR/astrika" --version >/dev/null 2>&1; then
        echo "==> Installing local static Rust binary (/usr/bin/astrika)..."
        install_atomic "$SCRIPT_DIR/astrika"
        INSTALLED_BIN=true
    fi

    if ! "$INSTALLED_BIN"; then
        if ! command -v curl >/dev/null 2>&1; then
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates
        fi
        echo "==> Downloading static Rust binary astrika from GitHub..."
        if curl -fsSL "$RAW_URL" -o "$STAGING_BIN" && chmod 0755 "$STAGING_BIN" && "$STAGING_BIN" --version >/dev/null 2>&1; then
            chown root:root "$STAGING_BIN" 2>/dev/null || true
            mv -f "$STAGING_BIN" /usr/bin/astrika
            INSTALLED_BIN=true
        elif rm -f "$STAGING_BIN" && curl -fsSL "$RAW_URL_ALT" -o "$STAGING_BIN" && chmod 0755 "$STAGING_BIN" && "$STAGING_BIN" --version >/dev/null 2>&1; then
            chown root:root "$STAGING_BIN" 2>/dev/null || true
            mv -f "$STAGING_BIN" /usr/bin/astrika
            INSTALLED_BIN=true
        else
            rm -f "$STAGING_BIN"
        fi
    fi
fi

if ! "$INSTALLED_BIN"; then
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
        build_from_source "$SCRIPT_DIR"
    else
        TMP_DIR="${TMP_DIR:-$(mktemp -d /tmp/astrika-src.XXXXXX)}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git curl ca-certificates
        git clone --depth 1 "$REPO_URL" "$TMP_DIR/repo"
        if [ -f "$TMP_DIR/repo/astrika/Cargo.toml" ]; then
            build_from_source "$TMP_DIR/repo/astrika"
        else
            build_from_source "$TMP_DIR/repo"
        fi
    fi
fi

if "$START"; then
    if [ "$SVC_NAME" = "astrika" ] && [ "$CUSTOM_PORT" = "8000" ]; then
        /usr/bin/astrika init 8000 --start
    else
        /usr/bin/astrika init "$CUSTOM_PORT" "$SVC_NAME" --start
    fi
else
    if [ "$SVC_NAME" = "astrika" ] && [ "$CUSTOM_PORT" = "8000" ]; then
        /usr/bin/astrika init 8000 --no-start
    else
        /usr/bin/astrika init "$CUSTOM_PORT" "$SVC_NAME" --no-start
    fi
fi

echo ""
echo "[+] Astrika is installed!"
echo "    Web UI:  http://$(hostname -I 2>/dev/null | awk '{print $1}'):${CUSTOM_PORT}/"
echo "    Status:  systemctl status ${SVC_NAME}"
echo "    Logs:    journalctl -u ${SVC_NAME} -f"
