#!/bin/bash
# Script to compare AFP mount traffic between netatalk and jrouter
# This captures full AURP traffic to analyze AFP/ASP session establishment

set -e

CAPTURE_DIR="/home/blake/code/netatalk/tmp_packetcaptures"
mkdir -p "$CAPTURE_DIR"

echo "===== AFP Mount Traffic Comparison ====="
echo "This script will capture AURP traffic during AFP mount attempts"
echo "You'll be prompted to attempt mounting twice: once with netatalk, once with jrouter"
echo ""

echo "===== Testing netatalk ====="
echo "1. Checking atalkd status..."
if ! sudo systemctl is-active --quiet atalkd; then
    echo "   atalkd not running, starting..."
    sudo systemctl start atalkd
    sleep 10
else
    echo "   atalkd already running"
fi

echo "2. Waiting for AURP connections to establish (60 seconds)..."
sleep 60

echo "3. Starting AURP packet capture..."
sudo tcpdump -i any port 387 -w "$CAPTURE_DIR/netatalk_afp_mount.pcap" &
TCPDUMP_PID=$!
sleep 2

echo ""
echo "============================================"
echo "READY: Now attempt to mount an AFP share from your Mac"
echo "  1. Open Chooser"
echo "  2. Click AppleShare"
echo "  3. Select a server (e.g., in zone 'Airaga')"
echo "  4. Click OK and attempt to mount"
echo "  5. Wait for success OR failure"
echo "  6. Press Enter here when done"
echo "============================================"
read -p "Press Enter when you've finished the mount attempt..."

echo ""
echo "4. Stopping capture..."
sudo kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null || true
sleep 2

echo "5. Analyzing netatalk AURP packets..."
python3 "$CAPTURE_DIR/../tools/aurp_pcap_analyze.py" "$CAPTURE_DIR/netatalk_afp_mount.pcap" > "$CAPTURE_DIR/netatalk_afp_analysis.txt"

echo ""
echo "===== Testing jrouter ====="
echo "1. Stopping atalkd..."
sudo systemctl stop atalkd
echo "   Waiting for Mac to detect network change (30 seconds)..."
sleep 30

echo "2. Starting jrouter..."
cd ~/code/jrouter_orig
sudo ./jrouter -config ~/code/machine-cfg/macpro2013/jrouter.yaml > "$CAPTURE_DIR/jrouter_afp.log" 2>&1 &
JROUTER_PID=$!
echo "   Waiting for jrouter connections to establish (60 seconds)..."
sleep 60

echo "3. Starting AURP packet capture..."
sudo tcpdump -i any port 387 -w "$CAPTURE_DIR/jrouter_afp_mount.pcap" &
TCPDUMP_PID=$!
sleep 2

echo ""
echo "============================================"
echo "READY: Now attempt to mount the SAME AFP share from your Mac"
echo "  1. Open Chooser (may already be open)"
echo "  2. Click AppleShare"
echo "  3. Select the SAME server as before"
echo "  4. Click OK and attempt to mount"
echo "  5. Wait for success (should work with jrouter)"
echo "  6. Press Enter here when done"
echo "============================================"
read -p "Press Enter when you've finished the mount attempt..."

echo ""
echo "4. Stopping capture..."
sudo kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null || true
sleep 2

echo "5. Analyzing jrouter AURP packets..."
python3 "$CAPTURE_DIR/../tools/aurp_pcap_analyze.py" "$CAPTURE_DIR/jrouter_afp_mount.pcap" > "$CAPTURE_DIR/jrouter_afp_analysis.txt"

echo "6. Stopping jrouter..."
sudo pkill -f jrouter 2>/dev/null || true
wait $JROUTER_PID 2>/dev/null || true

echo ""
echo "7. Restarting atalkd for normal operation..."
sudo systemctl start atalkd

echo ""
echo "===== Comparison ====="
echo ""
echo "Netatalk results:"
cat "$CAPTURE_DIR/netatalk_afp_analysis.txt"
echo ""
echo "jrouter results:"
cat "$CAPTURE_DIR/jrouter_afp_analysis.txt"

echo ""
echo "===== Files Created ====="
echo "  - $CAPTURE_DIR/netatalk_afp_mount.pcap"
echo "  - $CAPTURE_DIR/netatalk_afp_analysis.txt"
echo "  - $CAPTURE_DIR/jrouter_afp_mount.pcap"
echo "  - $CAPTURE_DIR/jrouter_afp_analysis.txt"
echo ""
echo "Next steps:"
echo "  1. Use Wireshark to compare the .pcap files"
echo "  2. Look for differences in DDP/ATP/ASP packet patterns"
echo "  3. Check if netatalk's packets are missing replies"
echo "  4. Look at tools/aurp_packet_compare.py for byte-by-byte comparison"
echo ""
echo "Done!"
