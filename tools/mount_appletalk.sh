#!/bin/bash

# Script to mount an AFP file share via AppleTalk on Linux using afpfs-ng
# Usage: ./mount_appletalk.sh <zone> <server> <share> <mount_point> [username]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo "Usage: $0 <zone> <server> <share> <mount_point> [username]"
    echo ""
    echo "Arguments:"
    echo "  zone        AppleTalk zone name"
    echo "  server      AppleTalk server name"
    echo "  share       Share/volume name to mount"
    echo "  mount_point Local directory to mount the share"
    echo "  username    (Optional) Username for authentication (default: guest)"
    echo ""
    echo "Examples:"
    echo "  $0 \"My Zone\" \"MyServer\" \"Public\" \"/mnt/appletalk\""
    echo "    # Mounts as guest (default)"
    echo "  $0 \"My Zone\" \"MyServer\" \"Public\" \"/mnt/appletalk\" \"guest\""
    echo "    # Explicitly mount as guest"
    echo "  $0 \"My Zone\" \"MyServer\" \"Public\" \"/mnt/appletalk\" \"username\""
    echo "    # Mount with specific username"
    exit 1
}

# Check arguments
if [ $# -lt 4 ]; then
    echo -e "${RED}Error: Missing required arguments${NC}"
    usage
fi

ZONE="$1"
SERVER="$2"
SHARE="$3"
MOUNT_POINT="$4"
USERNAME="${5:-guest}"

# Check if mount point exists, create if it doesn't
if [ ! -d "$MOUNT_POINT" ]; then
    echo "Creating mount point: $MOUNT_POINT"
    mkdir -p "$MOUNT_POINT"
fi

# Check if mount point is already mounted
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo -e "${YELLOW}Warning: $MOUNT_POINT is already mounted${NC}"
    read -p "Unmount first? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        umount "$MOUNT_POINT" || {
            echo -e "${RED}Error: Failed to unmount $MOUNT_POINT${NC}"
            exit 1
        }
    else
        echo "Aborting."
        exit 1
    fi
fi

# Check for afpfs-ng mount_afpfs tool
if ! command -v mount_afpfs &> /dev/null; then
    echo -e "${RED}Error: mount_afpfs not found${NC}"
    echo "Please install afpfs-ng: https://github.com/Netatalk/afpfs-ng"
    exit 1
fi

# Construct AFP URL for AppleTalk
# Format: afp://guest@at/Zone:Server/Share or afp://username@at/Zone:Server/Share
if [ "$USERNAME" = "guest" ]; then
    # Use explicit guest access
    AFP_URL="afp://guest@at/${ZONE}:${SERVER}/${SHARE}"
else
    # Include username in URL for authenticated access
    AFP_URL="afp://${USERNAME}@at/${ZONE}:${SERVER}/${SHARE}"
fi

echo "Mounting AppleTalk share..."
echo "  Zone: $ZONE"
echo "  Server: $SERVER"
echo "  Share: $SHARE"
echo "  Mount Point: $MOUNT_POINT"
echo "  Username: $USERNAME"
echo "  URL: $AFP_URL"
echo ""

# Mount using afpfs-ng mount_afpfs
# Format: mount_afpfs [-o options] afp://url mountpoint
echo "Executing: mount_afpfs \"$AFP_URL\" \"$MOUNT_POINT\""
echo ""

# Capture both stdout and stderr for error reporting
MOUNT_OUTPUT=$(mktemp)
MOUNT_ERROR=$(mktemp)
trap "rm -f '$MOUNT_OUTPUT' '$MOUNT_ERROR'" EXIT

if [ "$USERNAME" = "guest" ]; then
    # Mount as guest with explicit guest access
    # Capture all output (both stdout and stderr) for verbose error reporting
    if mount_afpfs "$AFP_URL" "$MOUNT_POINT" > "$MOUNT_OUTPUT" 2> "$MOUNT_ERROR"; then
        echo -e "${GREEN}Successfully mounted $SHARE to $MOUNT_POINT as guest${NC}"
        # Show any informational output
        if [ -s "$MOUNT_OUTPUT" ]; then
            cat "$MOUNT_OUTPUT"
        fi
    else
        MOUNT_EXIT_CODE=$?
        echo -e "${RED}Error: Failed to mount the share as guest (exit code: $MOUNT_EXIT_CODE)${NC}"
        echo ""
        echo "=== mount_afpfs stdout ==="
        if [ -s "$MOUNT_OUTPUT" ]; then
            cat "$MOUNT_OUTPUT"
        else
            echo "(no output)"
        fi
        echo ""
        echo "=== mount_afpfs stderr ==="
        if [ -s "$MOUNT_ERROR" ]; then
            cat "$MOUNT_ERROR"
        else
            echo "(no output)"
        fi
        echo ""
        echo "=== Recent afpfsd logs (syslog) ==="
        if command -v journalctl &> /dev/null; then
            journalctl -u afpfsd -n 20 --no-pager 2>/dev/null || \
            journalctl -t afpfsd -n 20 --no-pager 2>/dev/null || \
            echo "Could not access journalctl"
        elif [ -f /var/log/syslog ]; then
            grep -i afpfsd /var/log/syslog | tail -20 || echo "No afpfsd entries in syslog"
        elif [ -f /var/log/messages ]; then
            grep -i afpfsd /var/log/messages | tail -20 || echo "No afpfsd entries in messages"
        else
            echo "Could not access system logs"
        fi
        echo ""
        echo "=== Debugging suggestions ==="
        echo "1. Check if afpfsd is running: ps aux | grep afpfsd"
        echo "2. Run afpfsd in debug mode manually:"
        echo "   afp_client exit  # Stop existing daemon"
        echo "   afpfsd -d > /tmp/afpfsd_debug.log 2>&1 &"
        echo "   # Then retry the mount command"
        echo "3. Check AppleTalk connectivity: ping -c 1 $SERVER"
        echo "4. Verify share exists: afpgetstatus \"$ZONE:$SERVER\" 2>/dev/null || afpcmd \"afp://at/${ZONE}:${SERVER}\""
        exit 1
    fi
else
    # For authenticated access, user will be prompted for password
    # Note: password prompts may appear on stderr, so we don't fully suppress it
    if mount_afpfs "$AFP_URL" "$MOUNT_POINT" > "$MOUNT_OUTPUT" 2> "$MOUNT_ERROR"; then
        echo -e "${GREEN}Successfully mounted $SHARE to $MOUNT_POINT as $USERNAME${NC}"
        # Show any informational output
        if [ -s "$MOUNT_OUTPUT" ]; then
            cat "$MOUNT_OUTPUT"
        fi
    else
        MOUNT_EXIT_CODE=$?
        echo -e "${RED}Error: Failed to mount the share (exit code: $MOUNT_EXIT_CODE)${NC}"
        echo ""
        echo "=== mount_afpfs stdout ==="
        if [ -s "$MOUNT_OUTPUT" ]; then
            cat "$MOUNT_OUTPUT"
        else
            echo "(no output)"
        fi
        echo ""
        echo "=== mount_afpfs stderr ==="
        if [ -s "$MOUNT_ERROR" ]; then
            cat "$MOUNT_ERROR"
        else
            echo "(no output)"
        fi
        echo ""
        echo "=== Recent afpfsd logs (syslog) ==="
        if command -v journalctl &> /dev/null; then
            journalctl -u afpfsd -n 20 --no-pager 2>/dev/null || \
            journalctl -t afpfsd -n 20 --no-pager 2>/dev/null || \
            echo "Could not access journalctl"
        elif [ -f /var/log/syslog ]; then
            grep -i afpfsd /var/log/syslog | tail -20 || echo "No afpfsd entries in syslog"
        elif [ -f /var/log/messages ]; then
            grep -i afpfsd /var/log/messages | tail -20 || echo "No afpfsd entries in messages"
        else
            echo "Could not access system logs"
        fi
        echo ""
        echo "=== Debugging suggestions ==="
        echo "1. Verify username and password are correct"
        echo "2. Check if afpfsd is running: ps aux | grep afpfsd"
        echo "3. Run afpfsd in debug mode manually:"
        echo "   afp_client exit  # Stop existing daemon"
        echo "   afpfsd -d > /tmp/afpfsd_debug.log 2>&1 &"
        echo "   # Then retry the mount command"
        echo "4. Check AppleTalk connectivity: ping -c 1 $SERVER"
        echo "5. Verify share exists: afpgetstatus \"$ZONE:$SERVER\" 2>/dev/null || afpcmd \"afp://at/${ZONE}:${SERVER}\""
        exit 1
    fi
fi

echo ""
echo "To unmount later, use:"
echo "  umount $MOUNT_POINT"
echo ""
echo "Troubleshooting tips:"
echo "  1. Ensure atalkd is running: systemctl status atalkd"
echo "  2. Verify AppleTalk connectivity: ping -c 1 $SERVER"
if command -v afpgetstatus &> /dev/null; then
    echo "  3. Check server status: afpgetstatus \"$ZONE:$SERVER\""
elif command -v afpcmd &> /dev/null; then
    echo "  3. Check available shares: afpcmd \"afp://at/${ZONE}:${SERVER}\""
fi
echo "  4. For verbose debugging, run afpfsd manually:"
echo "     afp_client exit && afpfsd -d > /tmp/afpfsd_debug.log 2>&1 &"