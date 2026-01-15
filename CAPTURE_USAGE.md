# AURP Packet Capture Script Usage

## Overview

`capture_aurp.sh` is a comprehensive packet capture script for analyzing AURP protocol traffic. It captures both packets and logs for cross-reference analysis.

## Requirements

- Root privileges (for tcpdump)
- tcpdump installed
- Either jrouter or atalkd running (or can capture without either)

## Basic Usage

```bash
# Capture on default interface (enp12s0) for 120 seconds
sudo ./capture_aurp.sh

# Capture on specific interface for 300 seconds
sudo ./capture_aurp.sh eth0 300

# Capture with custom output directory
sudo ./capture_aurp.sh enp12s0 120 /home/blake/aurp_analysis
```

## Parameters

1. **Interface** (default: enp12s0) - Network interface to capture on
2. **Duration** (default: 120) - Capture duration in seconds
3. **Output directory** (default: /tmp/aurp_captures) - Where to save captures

## Output Files

The script creates timestamped files in the output directory:

- `aurp_YYYYMMDD_HHMMSS.pcap` - Binary packet capture (for Wireshark)
- `aurp_YYYYMMDD_HHMMSS.txt` - Human-readable packet dump with hex
- `jrouter_YYYYMMDD_HHMMSS.log` - jrouter log during capture (if running)
- `atalkd_YYYYMMDD_HHMMSS.log` - atalkd log during capture (if running)
- `capture_YYYYMMDD_HHMMSS_summary.txt` - Capture summary and statistics

## Features

- ✓ Automatically detects running service (jrouter or atalkd)
- ✓ Validates interface exists before starting
- ✓ Captures only AURP traffic (UDP port 387)
- ✓ Generates both binary (pcap) and text packet dumps
- ✓ Records service logs during capture for cross-reference
- ✓ Provides packet count and peer IP statistics
- ✓ Timestamped output for multiple captures
- ✓ Color-coded status messages
- ✓ Summary report with analysis hints

## Example Workflows

### Capture jrouter Connection Establishment

```bash
# Start jrouter
./jrouter -config jrouter.yaml > /tmp/jrouter.log 2>&1 &

# Wait a moment for startup
sleep 5

# Run 5-minute capture to catch full connection cycle
sudo ./capture_aurp.sh enp12s0 300

# Analyze the pcap
cd /tmp/aurp_captures
tcpdump -r aurp_*.pcap -n -v | grep -E "Open-Req|Open-Rsp|RI-Req|RI-Rsp|ZI-Req|ZI-Rsp"
```

### Compare netatalk vs jrouter

```bash
# Capture with atalkd
sudo systemctl start atalkd
sleep 10
sudo ./capture_aurp.sh enp12s0 120 /tmp/atalkd_capture

# Stop atalkd, start jrouter
sudo systemctl stop atalkd
./jrouter -config jrouter.yaml > /tmp/jrouter.log 2>&1 &
sleep 10
sudo ./capture_aurp.sh enp12s0 120 /tmp/jrouter_capture

# Compare packet counts
echo "atalkd packets:"
tcpdump -r /tmp/atalkd_capture/aurp_*.pcap 2>&1 | grep captured
echo "jrouter packets:"
tcpdump -r /tmp/jrouter_capture/aurp_*.pcap 2>&1 | grep captured
```

### Debug Zone Exchange Issues

```bash
# Run extended capture to catch zone information exchange
sudo ./capture_aurp.sh enp12s0 600

# Filter for Zone Information packets
cd /tmp/aurp_captures
grep -A 10 "ZI-Req\|ZI-Rsp" aurp_*.txt
```

## Analyzing Captured Data

### View Packets in Terminal

```bash
# View all packets
tcpdump -r /tmp/aurp_captures/aurp_*.pcap -n -v

# View with full hex dump
tcpdump -r /tmp/aurp_captures/aurp_*.pcap -n -v -X

# Filter specific peer
tcpdump -r /tmp/aurp_captures/aurp_*.pcap -n host 63.228.98.61
```

### Open in Wireshark

```bash
wireshark /tmp/aurp_captures/aurp_*.pcap &
```

Wireshark display filters:
- `udp.port == 387` - All AURP traffic
- `ip.addr == 63.228.98.61` - Specific peer
- `frame.len > 100` - Larger packets (likely Open-Req/Rsp with data)

### Cross-Reference with Logs

```bash
cd /tmp/aurp_captures

# View packets and logs side-by-side
less -N aurp_*.txt
less -N jrouter_*.log

# Search for connection events
grep -n "Open-Rsp\|RI-Rsp\|ZI-Rsp" jrouter_*.log
grep -n "Open-Rsp\|RI-Rsp\|ZI-Rsp" aurp_*.txt
```

## AURP Packet Identification

Look for these patterns in hex dumps:

### Open-Req (cmd 0x08)
- UDP payload ~33 bytes
- Command bytes: `00 08` at offset 22

### Open-Rsp (cmd 0x09)
- UDP payload ~36 bytes
- Command bytes: `00 09` at offset 22

### RI-Req (cmd 0x00)
- Command bytes: `00 00` at offset 22

### RI-Rsp (cmd 0x01)
- Command bytes: `00 01` at offset 22
- Contains route tuples (network ranges)

### ZI-Req (cmd 0x06)
- Command bytes: `00 06` at offset 22

### ZI-Rsp (cmd 0x07)
- Command bytes: `00 07` at offset 22
- Contains zone names (Pascal strings)

### Tickle (cmd 0x0E)
- UDP payload 24-30 bytes
- Command bytes: `00 0e` at offset 22
- Most common packet type (keepalive every 10s)

## Tips

1. **Start capture BEFORE starting jrouter** to catch Open-Req packets
2. **Use longer durations (300s+)** for zone exchange (can be slow)
3. **Check summary file first** for quick overview
4. **Compare successful (atalkd) vs failed (jrouter) captures** side-by-side
5. **Look at sequence numbers** to identify packet order

## Troubleshooting

**No packets captured:**
- Verify service is running and trying to connect to peers
- Check interface name is correct: `ip link show`
- Ensure peers are configured and reachable

**Empty log files:**
- jrouter: Make sure it's logging to /tmp/jrouter.log
- atalkd: Check journalctl has data: `journalctl -u atalkd -n 20`

**Permission denied:**
- Script must be run with sudo for tcpdump
- Output directory must be writable

## Integration with AURP Implementation Plan

Captures can be used to:
- Validate packet format matches RFC 1504
- Compare with jrouter reference implementation
- Debug connection establishment issues
- Document zone registration flow
- Verify SZI flag behavior in RI-Ack

Add capture analysis to AURP_IMPLEMENTATION_PLAN.md under:
- "Testing Strategy" section
- "jrouter Reference Testing Findings" section
