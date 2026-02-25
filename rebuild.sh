#!/usr/bin/env bash
# rebuild.sh - Build, install, and restart Netatalk on throwback
#
# meson install overwrites /etc/netatalk/{afp,atalkd}.conf with defaults.
# Custom configs are backed up before the install and restored after.
# Canonical copies are kept in config/throwback/ for version control.
#
# Services are always restarted at the end, even if the build fails.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$REPO_DIR/build"
CUSTOM_CFG_DIR="$REPO_DIR/config/throwback"
BUILD_FAILED=0

# ── service stop ─────────────────────────────────────────────────────────────
stop_services() {
    echo "Stopping services..."
    sudo systemctl stop netatalk atalkd 2>/dev/null || true
}

# ── service start ─────────────────────────────────────────────────────────────
start_services() {
    # Reload unit files in case they were updated by meson install
    sudo systemctl daemon-reload

    echo "Starting atalkd..."
    sudo systemctl start atalkd
    echo "Waiting for atalkd to be ready (up to 40s)..."
    for i in $(seq 1 40); do
        timeout 2 /usr/local/bin/getzones 2>/dev/null | grep -q . && break
        sleep 1
    done

    echo "Starting netatalk..."
    sudo systemctl start netatalk

    echo ""
    echo "=== Service Status ==="
    systemctl is-active atalkd   && echo "atalkd:   active" || echo "atalkd:   FAILED"
    systemctl is-active netatalk && echo "netatalk: active" || echo "netatalk: FAILED"
}

# Always restart services on exit, whether the build succeeded or not
cleanup() {
    if [[ $BUILD_FAILED -ne 0 ]]; then
        echo ""
        echo "Build/install failed — restoring configs from backup and restarting services..."
        sudo cp /tmp/afp.conf.bak    /etc/netatalk/afp.conf    2>/dev/null || true
        sudo cp /tmp/atalkd.conf.bak /etc/netatalk/atalkd.conf 2>/dev/null || true
    fi
    start_services
}
trap cleanup EXIT

stop_services

# ── back up live configs ──────────────────────────────────────────────────────
echo "Backing up /etc/netatalk configs..."
sudo cp -p /etc/netatalk/afp.conf    /tmp/afp.conf.bak
sudo cp -p /etc/netatalk/atalkd.conf /tmp/atalkd.conf.bak

# ── build & install ───────────────────────────────────────────────────────────
echo "Building..."
meson compile -C "$BUILD_DIR" || { BUILD_FAILED=1; exit 1; }
echo "Installing..."
sudo meson install -C "$BUILD_DIR" || { BUILD_FAILED=1; exit 1; }

# ── restore custom configs ────────────────────────────────────────────────────
echo "Restoring custom configs..."
sudo cp /tmp/afp.conf.bak    /etc/netatalk/afp.conf
sudo cp /tmp/atalkd.conf.bak /etc/netatalk/atalkd.conf
# Keep repo copies in sync
cp /tmp/afp.conf.bak    "$CUSTOM_CFG_DIR/afp.conf"
cp /tmp/atalkd.conf.bak "$CUSTOM_CFG_DIR/atalkd.conf"
