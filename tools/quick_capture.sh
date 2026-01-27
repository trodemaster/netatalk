#!/bin/bash
# Quick packet capture for Mac AppleTalk testing
# Captures for 60 seconds, then analyzes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")/tmp_packetcaptures"
mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$OUTPUT_DIR/mac_test_${TIMESTAMP}.pcap"

echo "Starting 60-second packet capture..."
echo "File: $CAPTURE_FILE"
echo ""
echo "Now on your Mac:"
echo "  1. Open Chooser"
echo "  2. Click AppleShare"
echo "  3. Switch between zones (BaroNet, PurrTopia, etc.)"
echo "  4. Try to mount a server when you see one"
echo ""
echo "Capture will run for 60 seconds..."

# Start capture
sudo tcpdump -i any -w "$CAPTURE_FILE" 'udp port 387' > /dev/null 2>&1 &
TCPDUMP_PID=$!

# Wait 60 seconds
sleep 60

# Stop capture
sudo kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo ""
echo "Capture complete!"
echo ""
echo "Analyzing..."
python3 "$SCRIPT_DIR/aurp_pcap_analyze.py" "$CAPTURE_FILE"

echo ""
echo "Capture saved to: $CAPTURE_FILE"
