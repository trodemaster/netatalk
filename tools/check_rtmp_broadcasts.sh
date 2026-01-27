#!/bin/bash
# Check for RTMP broadcasts on the AppleTalk network

echo "=== RTMP Broadcast Checker ==="
echo
echo "This script captures AppleTalk packets for 30 seconds"
echo "and checks if RTMP broadcasts (DDP type 0x01) are being sent."
echo
echo "RTMP broadcasts are needed for Mac clients to discover routers."
echo "Without RTMP, Macs cannot forward packets to remote networks."
echo
echo "Starting capture..."
echo

# Capture for 30 seconds
sudo timeout 30 tcpdump -i any -vvv -X 'udp port 387' 2>&1 | tee /tmp/rtmp_capture.txt &
CAPTURE_PID=$!

sleep 30

echo
echo "=== Analysis ==="
echo

# Check for DDP type 0x01 (RTMP)
RTMP_COUNT=$(grep -c "DDP.*type 0x01" /tmp/rtmp_capture.txt || echo "0")

if [ "$RTMP_COUNT" -gt 0 ]; then
    echo "✅ FOUND $RTMP_COUNT RTMP packets"
    echo
    echo "Sample RTMP packets:"
    grep -A 10 "DDP.*type 0x01" /tmp/rtmp_capture.txt | head -50
else
    echo "❌ NO RTMP packets found!"
    echo
    echo "This means:"
    echo "  1. atalkd is not sending RTMP broadcasts, OR"
    echo "  2. RTMP broadcasts are not reaching the network interface"
    echo
    echo "Expected behavior:"
    echo "  - RTMP broadcasts should occur every 10-20 seconds"
    echo "  - They should come from netatalk's address (650.37)"
    echo "  - They should go to broadcast address (650.255)"
    echo
    echo "Check atalkd configuration:"
    echo "  - Verify enp12s0 has -router flag"
    echo "  - Verify IFACE_ISROUTER flag is set"
    echo "  - Check atalkd logs for RTMP broadcast messages"
fi

echo
echo "Full capture saved to /tmp/rtmp_capture.txt"
