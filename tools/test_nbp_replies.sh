#!/bin/bash
# Test if netatalk AURP is receiving NBP replies by combining packet capture with zone scanning

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$(dirname "$SCRIPT_DIR")/tmp_packetcaptures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAPTURE_FILE="$DATA_DIR/nbp_test_${TIMESTAMP}.pcap"
ANALYSIS_FILE="$DATA_DIR/nbp_test_${TIMESTAMP}_analysis.txt"
SCAN_FILE="$DATA_DIR/nbp_test_${TIMESTAMP}_scan.txt"

# Parse arguments
CAPTURE_TIME=90
ZONES=""
NBP_OBJ="="
NBP_TYPE="="

while [[ $# -gt 0 ]]; do
    case $1 in
        --capture-time)
            CAPTURE_TIME="$2"
            shift 2
            ;;
        --zone)
            ZONES="$ZONES --zone $2"
            shift 2
            ;;
        --obj)
            NBP_OBJ="$2"
            shift 2
            ;;
        --type)
            NBP_TYPE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Test if AURP is receiving NBP replies by capturing packets during zone scan."
            echo ""
            echo "Options:"
            echo "  --capture-time <sec>   Capture duration in seconds (default: 90)"
            echo "  --zone <name>          Scan specific zone (can repeat)"
            echo "  --obj <name>           NBP object to search for (default: '=')"
            echo "  --type <type>          NBP type to search for (default: '=')"
            echo "  --help                 Show this help"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 --capture-time 120"
            echo "  $0 --type AFPServer"
            echo "  $0 --zone netjibbing --zone Airaga"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "============================================"
echo "NBP Reply Test - $(date)"
echo "============================================"
echo ""
echo "Configuration:"
echo "  Capture file: $CAPTURE_FILE"
echo "  Capture time: ${CAPTURE_TIME}s"
echo "  NBP query: ${NBP_OBJ}:${NBP_TYPE}"
[[ -n "$ZONES" ]] && echo "  Zones: $ZONES" || echo "  Zones: (auto-discover via getzones)"
echo ""

# Check if atalkd is running
if ! pgrep -x atalkd > /dev/null; then
    echo "ERROR: atalkd is not running"
    echo "Start it with: sudo systemctl start atalkd"
    exit 1
fi

# Start packet capture in background
echo "[1/4] Starting packet capture (${CAPTURE_TIME}s)..."
sudo tcpdump -i any port 387 -w "$CAPTURE_FILE" -G "$CAPTURE_TIME" -W 1 2>/dev/null &
TCPDUMP_PID=$!
sleep 2

# Wait a bit for AURP connections to stabilize
echo "[2/4] Waiting 5 seconds for AURP to stabilize..."
sleep 5

# Run NBP zone scan
echo "[3/4] Running NBP zone scan..."
python3 "$SCRIPT_DIR/nbp_zone_scan.py" --obj "$NBP_OBJ" --type "$NBP_TYPE" $ZONES > "$SCAN_FILE" 2>&1

# Show scan results
echo ""
echo "===== NBP Scan Results ====="
cat "$SCAN_FILE"
echo ""

# Wait for capture to complete
echo "[4/4] Waiting for packet capture to complete..."
wait $TCPDUMP_PID 2>/dev/null || true

# Analyze the capture
echo ""
echo "===== Analyzing Packet Capture ====="
python3 "$SCRIPT_DIR/aurp_pcap_analyze.py" "$CAPTURE_FILE" > "$ANALYSIS_FILE"

# Extract key metrics
OUTBOUND_FWDREQ=$(grep "Outbound NBP ops.*FwdReq" "$ANALYSIS_FILE" | head -1 | awk '{print $NF}' || echo "0")
INBOUND_DATA=$(grep "^in_type0002" "$ANALYSIS_FILE" | awk '{print $2}' || echo "0")
INBOUND_LKUPREPLY=$(grep "Inbound NBP ops.*LkUpReply" "$ANALYSIS_FILE" | head -1 | awk '{print $NF}' || echo "0")

echo ""
echo "===== Test Results ====="
echo "Outbound NBP FwdReq queries sent: $OUTBOUND_FWDREQ"
echo "Inbound AURP data packets:        $INBOUND_DATA"
echo "Inbound NBP LkUpReply received:   $INBOUND_LKUPREPLY"
echo ""

# Determine test result
if [[ "$OUTBOUND_FWDREQ" -gt 0 ]]; then
    echo "✓ NBP queries are being sent"
else
    echo "✗ NO NBP queries sent (problem with NBP forwarding)"
fi

if [[ "$INBOUND_DATA" -gt 0 ]]; then
    echo "✓ Receiving AURP data packets from peers"
    
    if [[ "$INBOUND_LKUPREPLY" -gt 0 ]]; then
        echo "✓ SUCCESS: Receiving NBP replies! ($INBOUND_LKUPREPLY replies)"
        SUCCESS=true
    else
        echo "⚠ Receiving data packets but they are NOT NBP replies"
        echo "  (Likely incoming queries FROM remote peers, not replies TO us)"
        SUCCESS=false
    fi
else
    echo "✗ NOT receiving any AURP data packets"
    echo "  Remote peers cannot route to us or are not sending replies"
    SUCCESS=false
fi

echo ""
echo "===== Diagnostic Information ====="

# Show top peers by packet type
echo ""
echo "Top inbound data packet sources:"
grep -A 10 "Inbound DDP types" "$ANALYSIS_FILE" | tail -n +2 | head -5 || echo "  (none)"

echo ""
echo "Top outbound destinations:"
grep -A 10 "Outbound NBP ops by peer:" "$ANALYSIS_FILE" | tail -n +2 | head -5 || echo "  (none)"

# Check for common issues
echo ""
echo "Checking for common issues:"

# Check if we're advertising routes as extended
RECENT_LOGS=$(sudo journalctl -u atalkd --since "5 minutes ago" --no-pager 2>/dev/null || echo "")
if echo "$RECENT_LOGS" | grep -q "adding network.*extended=1"; then
    echo "✓ Advertising network as extended (correct for Phase 2)"
elif echo "$RECENT_LOGS" | grep -q "adding network.*extended=0"; then
    echo "✗ WARNING: Advertising network as non-extended (wrong for Phase 2 networks!)"
else
    echo "⚠ Could not verify extended flag in recent logs"
fi

# Check for zone info being sent
if echo "$RECENT_LOGS" | grep -q "aurp_send_zi_rsp"; then
    ZONE_COUNT=$(echo "$RECENT_LOGS" | grep -c "aurp_send_zi_rsp: sent" || echo "0")
    echo "✓ Sent zone information to $ZONE_COUNT peer(s)"
else
    echo "⚠ No zone information sent recently (may be normal if connections are old)"
fi

# Check for incoming data handling
if echo "$RECENT_LOGS" | grep -q "aurp_handle_data: ENTRY"; then
    DATA_COUNT=$(echo "$RECENT_LOGS" | grep -c "aurp_handle_data: ENTRY" || echo "0")
    echo "✓ Received $DATA_COUNT AURP data packet(s) (processed by aurp_handle_data)"
else
    echo "✗ No AURP data packets processed by aurp_handle_data"
fi

echo ""
echo "===== Files Created ====="
echo "  Capture: $CAPTURE_FILE"
echo "  Analysis: $ANALYSIS_FILE"
echo "  Scan results: $SCAN_FILE"
echo ""

if [[ "$SUCCESS" == "true" ]]; then
    echo "✓✓✓ TEST PASSED: NBP replies are working! ✓✓✓"
    exit 0
else
    echo "✗✗✗ TEST FAILED: Not receiving NBP replies ✗✗✗"
    echo ""
    echo "Next steps:"
    echo "1. Check logs: sudo journalctl -u atalkd -n 200"
    echo "2. Verify peers connected: sudo journalctl -u atalkd | grep 'recv=CONNECTED send=CONNECTED'"
    echo "3. Review full analysis: cat $ANALYSIS_FILE"
    echo "4. Compare with jrouter: cd tools/ && ./compare_nbp.sh"
    exit 1
fi
