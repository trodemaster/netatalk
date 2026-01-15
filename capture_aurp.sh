#!/bin/bash
#
# AURP Packet Capture Script
# Captures AURP traffic and logs for protocol analysis
#

set -e

# Configuration
INTERFACE="${1:-enp12s0}"
DURATION="${2:-120}"  # seconds
OUTPUT_DIR="${3:-/tmp/aurp_captures}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== AURP Packet Capture Script ===${NC}"
echo "Interface: $INTERFACE"
echo "Duration: ${DURATION}s"
echo "Output: $OUTPUT_DIR"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Output files
PCAP_FILE="$OUTPUT_DIR/aurp_${TIMESTAMP}.pcap"
PCAP_TEXT="$OUTPUT_DIR/aurp_${TIMESTAMP}.txt"
JROUTER_LOG="$OUTPUT_DIR/jrouter_${TIMESTAMP}.log"
ATALKD_LOG="$OUTPUT_DIR/atalkd_${TIMESTAMP}.log"
SUMMARY_FILE="$OUTPUT_DIR/capture_${TIMESTAMP}_summary.txt"

# Check if running as root (needed for tcpdump)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root for packet capture${NC}"
    echo "Usage: sudo $0 [interface] [duration_seconds] [output_dir]"
    exit 1
fi

# Check if interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    echo -e "${RED}Error: Interface $INTERFACE does not exist${NC}"
    echo "Available interfaces:"
    ip -br link show
    exit 1
fi

# Detect which service is running
USING_JROUTER=false
USING_ATALKD=false

if pgrep -x "jrouter" > /dev/null; then
    USING_JROUTER=true
    JROUTER_PID=$(pgrep -x "jrouter")
    echo -e "${GREEN}✓${NC} jrouter is running (PID: $JROUTER_PID)"
elif systemctl is-active --quiet atalkd; then
    USING_ATALKD=true
    echo -e "${GREEN}✓${NC} atalkd is running"
else
    echo -e "${YELLOW}⚠${NC}  No AURP service detected (neither jrouter nor atalkd)"
    echo "Continue anyway? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo

# Start capture summary
cat > "$SUMMARY_FILE" <<EOF
AURP Packet Capture Summary
===========================
Date: $(date)
Interface: $INTERFACE
Duration: ${DURATION}s
Service: $(if $USING_JROUTER; then echo "jrouter"; elif $USING_ATALKD; then echo "atalkd"; else echo "none"; fi)

Files:
- Packet capture: $(basename "$PCAP_FILE")
- Text dump: $(basename "$PCAP_TEXT")
- jrouter log: $(basename "$JROUTER_LOG")
- atalkd log: $(basename "$ATALKD_LOG")

EOF

echo -e "${GREEN}Starting packet capture...${NC}"
echo "This will capture for ${DURATION} seconds. Press Ctrl+C to stop early."
echo

# Start tcpdump in background
tcpdump -i "$INTERFACE" -n -s 0 -w "$PCAP_FILE" \
    'udp port 387' 2>&1 | tee -a "$SUMMARY_FILE" &
TCPDUMP_PID=$!

# Give tcpdump a moment to start
sleep 2

# Record start time
START_TIME=$(date +%s)

# Monitor capture
echo -e "${YELLOW}Capturing packets...${NC}"
if $USING_JROUTER; then
    echo "Monitoring jrouter log..."
    tail -f /tmp/jrouter.log 2>/dev/null >> "$JROUTER_LOG" &
    TAIL_PID=$!
elif $USING_ATALKD; then
    echo "Monitoring atalkd log..."
    journalctl -u atalkd -f --since "1 minute ago" >> "$ATALKD_LOG" &
    TAIL_PID=$!
fi

# Wait for duration
sleep "$DURATION"

# Stop capture
echo
echo -e "${GREEN}Stopping capture...${NC}"
kill -INT $TCPDUMP_PID 2>/dev/null || true
if [ -n "${TAIL_PID:-}" ]; then
    kill $TAIL_PID 2>/dev/null || true
fi

# Wait for tcpdump to finish writing
sleep 2

# Generate text dump of packets
echo -e "${GREEN}Generating packet analysis...${NC}"
tcpdump -r "$PCAP_FILE" -n -v -X > "$PCAP_TEXT" 2>&1

# Analyze capture
PACKET_COUNT=$(tcpdump -r "$PCAP_FILE" 2>&1 | grep -oP '\d+(?= packets captured)' || echo "0")
FILE_SIZE=$(ls -lh "$PCAP_FILE" | awk '{print $5}')

# Identify packet types
echo >> "$SUMMARY_FILE"
echo "Analysis:" >> "$SUMMARY_FILE"
echo "---------" >> "$SUMMARY_FILE"
echo "Total packets captured: $PACKET_COUNT" >> "$SUMMARY_FILE"
echo "Capture file size: $FILE_SIZE" >> "$SUMMARY_FILE"
echo >> "$SUMMARY_FILE"

# Count AURP packet types by looking at command codes
echo "AURP Packet Type Distribution:" >> "$SUMMARY_FILE"
if [ "$PACKET_COUNT" -gt 0 ]; then
    # Extract and count packet types from hex dump
    echo "  (Detailed analysis in $(basename "$PCAP_TEXT"))" >> "$SUMMARY_FILE"

    # Count unique source/dest IPs
    echo >> "$SUMMARY_FILE"
    echo "Peer IP addresses:" >> "$SUMMARY_FILE"
    tcpdump -r "$PCAP_FILE" -n 2>/dev/null | \
        grep -oP '\d+\.\d+\.\d+\.\d+\.387 > \d+\.\d+\.\d+\.\d+\.387' | \
        sort -u >> "$SUMMARY_FILE" || echo "  (none detected)" >> "$SUMMARY_FILE"
fi

# Add log summary
echo >> "$SUMMARY_FILE"
if $USING_JROUTER && [ -s "$JROUTER_LOG" ]; then
    echo "jrouter log summary:" >> "$SUMMARY_FILE"
    grep -c "connected\|Open-Rsp\|RI-Rsp\|ZI-Rsp" "$JROUTER_LOG" >> "$SUMMARY_FILE" 2>/dev/null || echo "  (no matches)" >> "$SUMMARY_FILE"
elif $USING_ATALKD && [ -s "$ATALKD_LOG" ]; then
    echo "atalkd log summary:" >> "$SUMMARY_FILE"
    grep -c "aurp_handle.*Rsp\|zone.*added\|route.*learned" "$ATALKD_LOG" >> "$SUMMARY_FILE" 2>/dev/null || echo "  (no matches)" >> "$SUMMARY_FILE"
fi

# Final summary
echo
echo -e "${GREEN}=== Capture Complete ===${NC}"
echo
echo "Files saved to: $OUTPUT_DIR"
echo "  - Packet capture (pcap): $(basename "$PCAP_FILE") ($FILE_SIZE)"
echo "  - Packet dump (text):    $(basename "$PCAP_TEXT")"
if $USING_JROUTER && [ -s "$JROUTER_LOG" ]; then
    echo "  - jrouter log:           $(basename "$JROUTER_LOG") ($(wc -l < "$JROUTER_LOG") lines)"
elif $USING_ATALKD && [ -s "$ATALKD_LOG" ]; then
    echo "  - atalkd log:            $(basename "$ATALKD_LOG") ($(wc -l < "$ATALKD_LOG") lines)"
fi
echo "  - Summary:               $(basename "$SUMMARY_FILE")"
echo
echo "Captured $PACKET_COUNT packets in ${DURATION}s"
echo

# Show summary
cat "$SUMMARY_FILE"
echo
echo -e "${GREEN}To analyze the capture:${NC}"
echo "  View packets:     tcpdump -r $PCAP_FILE -n -v"
echo "  View hex dump:    less $PCAP_TEXT"
echo "  Open in Wireshark: wireshark $PCAP_FILE"
echo
echo -e "${YELLOW}Note: AURP packets are UDP port 387${NC}"
