#!/bin/bash
# Quick RTMP packet checker

echo "Checking for RTMP broadcasts on enp12s0..."
echo "RTMP = DDP type 0x01 (Routing Table Maintenance Protocol)"
echo
echo "Capturing for 30 seconds. Look for packets with first byte = 0x01..."
echo

timeout 30 sudo tcpdump -i enp12s0 -X 'udp port 387' 2>&1 | while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*0x00.*:.*01.*02 ]]; then
        echo ">>> POTENTIAL RTMP PACKET: $line"
    else
        echo "$line"
    fi
done

echo
echo "Done. If you saw '>>> POTENTIAL RTMP PACKET' above, RTMP is being sent."
echo "If not, RTMP broadcasts are not reaching the network."
