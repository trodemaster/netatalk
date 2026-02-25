#!/bin/bash
# refresh_router_list.sh
#
# Fetches the latest AURP peer list from the upstream source and updates
# the local aurp_peers.txt file used by atalkd. If the list changes,
# atalkd is restarted so the new peers take effect immediately.
#
# Peer list URL is recorded in /etc/netatalk/atalkd.conf.
# Target file: /usr/local/etc/aurp_peers.txt

set -euo pipefail

PEER_URL="http://kalleboo.com/GT2024.txt"
PEER_FILE="/usr/local/etc/aurp_peers.txt"
TMP_FILE="$(mktemp /tmp/aurp_peers_new.XXXXXX)"
ATALKD_PID_FILE="/var/lock/atalkd"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*" >&2; }

cleanup() { rm -f "$TMP_FILE"; }
trap cleanup EXIT

# ── root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (needs to write $PEER_FILE and restart atalkd)."
    exit 1
fi

echo
echo "===  AURP Peer List Refresh  ==="
echo

# ── fetch ─────────────────────────────────────────────────────────────────────
info "Fetching peer list from $PEER_URL ..."
if ! curl -fsSL --max-time 30 "$PEER_URL" -o "$TMP_FILE"; then
    err "Download failed. Check network connectivity."
    exit 1
fi

# ── validate ──────────────────────────────────────────────────────────────────
new_count=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$TMP_FILE" || true)
if [[ "$new_count" -eq 0 ]]; then
    err "Downloaded file contains no valid IP addresses — aborting to protect existing config."
    exit 1
fi

# Strip duplicate IPs (the upstream list can have duplicates)
sort -u "$TMP_FILE" -o "$TMP_FILE"
new_count=$(wc -l < "$TMP_FILE")
info "Downloaded $new_count unique peer IPs."

# ── compare ───────────────────────────────────────────────────────────────────
if [[ -f "$PEER_FILE" ]]; then
    old_count=$(wc -l < "$PEER_FILE")
    info "Existing peer file has $old_count IPs."

    # Sort both for a stable diff
    old_sorted=$(sort "$PEER_FILE")
    new_sorted=$(sort "$TMP_FILE")

    added=$(comm -13 <(echo "$old_sorted") <(echo "$new_sorted") | wc -l)
    removed=$(comm -23 <(echo "$old_sorted") <(echo "$new_sorted") | wc -l)

    if [[ "$added" -eq 0 && "$removed" -eq 0 ]]; then
        ok "Peer list is already up to date — no changes needed."
        echo
        exit 0
    fi

    echo
    info "Changes detected:"
    [[ "$added"   -gt 0 ]] && ok "  + $added peer(s) added"
    [[ "$removed" -gt 0 ]] && warn "  - $removed peer(s) removed"

    if [[ "$added" -gt 0 ]]; then
        echo
        info "New peers:"
        comm -13 <(echo "$old_sorted") <(echo "$new_sorted") | sed 's/^/    /'
    fi
    if [[ "$removed" -gt 0 ]]; then
        echo
        info "Removed peers:"
        comm -23 <(echo "$old_sorted") <(echo "$new_sorted") | sed 's/^/    /'
    fi
else
    warn "No existing peer file found at $PEER_FILE — creating it fresh."
    added=$new_count
    removed=0
fi

# ── update file ───────────────────────────────────────────────────────────────
echo
info "Writing updated peer list to $PEER_FILE ..."
cp "$TMP_FILE" "$PEER_FILE"
chmod 644 "$PEER_FILE"
ok "Peer file updated ($new_count peers)."

# ── restart atalkd ────────────────────────────────────────────────────────────
echo
info "Restarting atalkd to apply new peer list ..."
if systemctl restart atalkd; then
    sleep 2
    if systemctl is-active --quiet atalkd; then
        ok "atalkd restarted successfully."
    else
        err "atalkd failed to restart — check: journalctl -u atalkd -n 30"
        exit 1
    fi
else
    err "systemctl restart atalkd failed."
    exit 1
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Done ==="
echo -e "  Peer file : $PEER_FILE"
echo -e "  Total peers: $new_count"
echo -e "  Added      : $added"
echo -e "  Removed    : $removed"
echo
info "Verify AURP connectivity with:  getzones"
echo
