#!/bin/bash

# Diagnostic script for AFP mount failures
# Captures packets and logs during AFP mount attempts to identify the failure point

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if atalkd is running
if ! pgrep -x atalkd > /dev/null; then
    echo -e "${RED}Error: atalkd is not running${NC}"
    echo "Start it with: sudo systemctl start atalkd"
    exit 1
fi

# Determine output directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")/tmp_packetcaptures"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$OUTPUT_DIR/afp_mount_debug_${TIMESTAMP}.pcap"

echo -e "${BLUE}AFP Mount Diagnostic Tool${NC}"
echo "=========================="
echo ""
echo "This tool will:"
echo "  1. Start packet capture on UDP port 387 (AppleTalk)"
echo "  2. Wait for you to attempt an AFP mount from your Mac"
echo "  3. Analyze the traffic to identify why the mount fails"
echo ""
echo -e "${YELLOW}Instructions:${NC}"
echo "  1. Press ENTER to start the capture"
echo "  2. On your Mac, open Chooser and try to mount an AFP server"
echo "  3. Wait for the mount to fail (or succeed if it works!)"
echo "  4. Press ENTER again to stop the capture and analyze"
echo ""
read -p "Press ENTER to start capture..."

# Start packet capture
echo ""
echo "Starting packet capture..."
sudo tcpdump -i any -w "$CAPTURE_FILE" 'udp port 387' > /dev/null 2>&1 &
TCPDUMP_PID=$!

echo -e "${GREEN}Capture running (PID: $TCPDUMP_PID)${NC}"
echo ""
echo -e "${YELLOW}Now try to mount an AFP server from your Mac${NC}"
echo ""
read -p "Press ENTER when mount attempt is complete..."

# Stop capture
echo ""
echo "Stopping capture..."
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

# Get file size
FILESIZE=$(stat -f%z "$CAPTURE_FILE" 2>/dev/null || stat -c%s "$CAPTURE_FILE" 2>/dev/null || echo "0")
echo "Captured ${FILESIZE} bytes to: $CAPTURE_FILE"
echo ""

# Analyze the capture
echo -e "${BLUE}Analyzing capture...${NC}"
echo "===================="
echo ""

# Count packet types (ensure we get clean integers)
NBP_COUNT=$(sudo tcpdump -r "$CAPTURE_FILE" -n 2>/dev/null | grep -c "DDP.*type 2" 2>/dev/null || echo "0")
NBP_COUNT=$(echo "$NBP_COUNT" | tr -d '\n' | tr -d ' ')
ATP_COUNT=$(sudo tcpdump -r "$CAPTURE_FILE" -n 2>/dev/null | grep -c "DDP.*type 3" 2>/dev/null || echo "0")
ATP_COUNT=$(echo "$ATP_COUNT" | tr -d '\n' | tr -d ' ')
RTMP_COUNT=$(sudo tcpdump -r "$CAPTURE_FILE" -n 2>/dev/null | grep -c "DDP.*type 1" 2>/dev/null || echo "0")
RTMP_COUNT=$(echo "$RTMP_COUNT" | tr -d '\n' | tr -d ' ')

# Count UDP packets (AURP tunnel traffic)
UDP_COUNT=$(sudo tcpdump -r "$CAPTURE_FILE" -n 2>/dev/null | grep -c "UDP" 2>/dev/null || echo "0")
UDP_COUNT=$(echo "$UDP_COUNT" | tr -d '\n' | tr -d ' ')

# Count local AppleTalk packets (non-UDP, DDP on local network)
LOCAL_COUNT=$(sudo tcpdump -r "$CAPTURE_FILE" -n 2>/dev/null | grep "DDP" | grep -cv "UDP" 2>/dev/null || echo "0")
LOCAL_COUNT=$(echo "$LOCAL_COUNT" | tr -d '\n' | tr -d ' ')

echo "Packet Summary:"
echo "  UDP packets (AURP tunnels): $UDP_COUNT"
echo "  Local DDP packets (from Mac): $LOCAL_COUNT"
echo "  RTMP packets (routing - type 1): $RTMP_COUNT"
echo "  NBP packets (name lookup - type 2): $NBP_COUNT"
echo "  ATP packets (file transfers - type 3): $ATP_COUNT"
echo ""

# Check if we captured any local traffic
if [ "$LOCAL_COUNT" -eq 0 ] && [ "$UDP_COUNT" -gt 0 ]; then
    echo -e "${RED}⨯ No local AppleTalk traffic from Mac detected!${NC}"
    echo ""
    echo "  Problem: Only AURP tunnel traffic was captured."
    echo "  This means your Mac either:"
    echo "    1. Didn't actually try to mount anything (check Chooser was used)"
    echo "    2. Is on a different network interface"
    echo "    3. Has AppleTalk disabled or misconfigured"
    echo ""
    echo "  Verify Mac setup:"
    echo "    - Check AppleTalk is enabled in Network control panel"
    echo "    - Verify Mac is on network 650 (should see 650.x.x address)"
    echo "    - Try: getzones (should show zone list on Mac)"
    echo "    - Ensure you clicked on a server name in Chooser"
    echo ""
elif [ "$LOCAL_COUNT" -eq 0 ]; then
    echo -e "${RED}⨯ No AppleTalk traffic captured at all!${NC}"
    echo ""
    echo "  Problem: The capture didn't see any AppleTalk packets."
    echo "  Suggestions:"
    echo "    - Verify atalkd is running: systemctl status atalkd"
    echo "    - Check network interface is correct"
    echo "    - Make sure you tried to mount during capture"
    echo ""
fi

# Diagnosis
if [ "$LOCAL_COUNT" -gt 0 ] && [ "$NBP_COUNT" -eq 0 ]; then
    echo -e "${RED}⨯ No NBP packets detected${NC}"
    echo "  Problem: Mac did not perform name lookup"
    echo "  Suggestion: Make sure you clicked on the server in Chooser"
elif [ "$LOCAL_COUNT" -gt 0 ] && [ "$NBP_COUNT" -gt 0 ] && [ "$ATP_COUNT" -eq 0 ]; then
    echo -e "${GREEN}✓ NBP packets detected ($NBP_COUNT)${NC}"
    echo -e "${RED}⨯ No ATP packets detected${NC}"
    echo ""
    echo "  Problem: Mac found the server but didn't initiate file transfer connection"
    echo "  This indicates one of:"
    echo "    1. Mac doesn't have route to the server's network"
    echo "    2. ATP packets are being blocked or not forwarded"
    echo "    3. Server didn't respond to connection request"
    echo ""
    echo "Checking recent logs for clues..."
    echo ""
    
    # Check logs for routing issues
    sudo journalctl -u atalkd --since "2 minutes ago" -n 100 | \
        grep -E "650|ATP|route.*2940|RTMP BROADCAST" | tail -30
    
    echo ""
    echo -e "${YELLOW}Recommendations:${NC}"
    echo "  1. Verify RTMP is broadcasting routes to Mac's network"
    echo "  2. Check Mac's routing table (use AppleTalk control panel or atalkvars)"
    echo "  3. Try pinging the AFP server from Mac to test routing"
elif [ "$LOCAL_COUNT" -gt 0 ] && [ "$ATP_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ NBP packets detected ($NBP_COUNT)${NC}"
    echo -e "${GREEN}✓ ATP packets detected ($ATP_COUNT)${NC}"
    echo ""
    echo "  Good news: Both NBP and ATP traffic is working!"
    echo "  If mount still failed, the issue is at the AFP protocol level"
    echo ""
    echo "Checking for AFP errors in logs..."
    sudo journalctl -u atalkd --since "2 minutes ago" | \
        grep -iE "afp|auth|login|error" | tail -20
fi

echo ""
echo -e "${BLUE}Full packet capture details:${NC}"
echo "============================"
sudo tcpdump -r "$CAPTURE_FILE" -n 2>/dev/null | head -50

echo ""
echo -e "${BLUE}Mac AppleTalk Configuration Check:${NC}"
echo "===================================="
echo "On your Mac, verify AppleTalk is working:"
echo "  1. Open Network control panel → AppleTalk tab"
echo "  2. Ensure AppleTalk is 'Active' or 'Enabled'"
echo "  3. Check your AppleTalk address (should be 650.x.x)"
echo "  4. Run 'getzones' to see if you can see zone list"
echo "  5. Try 'nbplkup =:AFPServer@*' to see nearby servers"
echo ""
echo "If AppleTalk shows as active but no traffic captured:"
echo "  - Mac might be on a different subnet/VLAN"
echo "  - Network cable/WiFi might not be bridged to AppleTalk network"
echo "  - Try restarting AppleTalk on the Mac"

echo ""
echo "Capture saved to: $CAPTURE_FILE"
echo ""
echo "For detailed analysis, use:"
echo "  sudo tcpdump -r $CAPTURE_FILE -vv -n"
echo "  python3 tools/aurp_pcap_analyze.py $CAPTURE_FILE"
