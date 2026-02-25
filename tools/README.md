# Netatalk AURP Testing and Analysis Tools

This directory contains various tools for testing, debugging, and analyzing the AURP (AppleTalk Update-based Routing Protocol) implementation in netatalk.

## Data Storage

All captured packet files, logs, and analysis results are stored in **`../tmp_packetcaptures/`** directory. This keeps the tools directory clean and separates executable scripts from data files.

## Tools Overview

### aurp_pcap_analyze.py

**Purpose**: Analyzes AURP packet captures to summarize traffic patterns and protocol behavior.

**Usage**:
```bash
python3 aurp_pcap_analyze.py <capture.pcap>
```

**Features**:
- Identifies AURP packet types (RI-Req, RI-Rsp, Open-Req, Open-Rsp, Tickle, etc.)
- Counts inbound/outbound type 0x0002 (data) and type 0x0003 (routing) packets
- Extracts DDP protocol types and NBP operations (BrRq, LkUp, FwdReq, LkUpReply)
- Lists top peers by packet count
- Breaks down NBP operations by peer
- Useful for diagnosing routing and NBP forwarding issues

**Output**: Plain text summary with packet counts and peer statistics

---

### aurp_probe.py

**Purpose**: Low-level AURP protocol testing tool that sends raw AURP packets to test peer connectivity.

**Usage**:
```bash
python3 aurp_probe.py <mode> <target_ip> [options]
```

**Modes**:
- `tickle`: Send AURP Tickle keepalive packet
- `open`: Send AURP Open-Req connection initiation packet
- `ri-req`: Send AURP Routing Information Request packet

**Features**:
- Crafts raw AURP packets with proper domain headers and transport headers
- Tests basic AURP connectivity without full atalkd running
- Useful for debugging connection establishment issues
- Can specify source IP or auto-detect

**Example**:
```bash
# Test if peer responds to Tickle
python3 aurp_probe.py tickle 192.168.0.1

# Initiate connection with Open-Req
python3 aurp_probe.py open 192.168.0.1
```

---

### nbp_zone_scan.py

**Purpose**: Scans AppleTalk zones for NBP services (like AFP servers) across the AURP network.

**Usage**:
```bash
python3 nbp_zone_scan.py [options]
```

**Options**:
- `--obj <name>`: NBP object to search for (default: `=` for all)
- `--type <type>`: NBP type to search for (default: `=` for all)
- `--zone <zone>`: Specific zone to scan (can repeat for multiple zones)
- `--zones-from-getzones`: Auto-discover zones using `getzones` command (default: enabled)
- `--op <brrq|fwd|lkup>`: NBP operation type (default: `brrq` for broadcast)
- `--max-responses <n>`: Maximum responses per zone (default: 1000)

**Features**:
- Automatically discovers all zones via `getzones` if not specified
- Searches each zone for NBP services using `nbplkup`
- Groups results by zone for easy viewing
- Useful for verifying AURP NBP forwarding works end-to-end
- Shows total result count across all zones

**Example**:
```bash
# Scan all zones for all AFP servers
python3 nbp_zone_scan.py --type AFPServer

# Scan specific zones
python3 nbp_zone_scan.py --zone "netjibbing" --zone "Airaga"

# Find all workstations in all zones
python3 nbp_zone_scan.py --type Workstation
```

**Dependencies**: Requires `getzones` and `nbplkup` from netatalk to be installed and in PATH.

---

### aurp_nbp_flow.py

**Purpose**: Real-time AURP/NBP end-to-end flow analyzer. Parses `atalkd` and `netatalk` journal logs and reconstructs inbound NBP lookup events from remote AURP peers, showing every step of the reply path. The primary tool for debugging why remote users can or cannot see our AFP server in their Chooser.

**Usage**:
```bash
python3 aurp_nbp_flow.py                    # last 2 hours (default)
python3 aurp_nbp_flow.py -H 6              # last 6 hours
python3 aurp_nbp_flow.py --since "1 hour ago"
python3 aurp_nbp_flow.py --summary         # counts only, no per-event detail
python3 aurp_nbp_flow.py --tail            # follow live (like tail -f)
python3 aurp_nbp_flow.py --all             # show all NBP types, not just AFPServer
python3 aurp_nbp_flow.py --verbose         # include peer connect/disconnect events
```

**Options**:
- `-H, --hours <n>`: Look back N hours (default: 2)
- `--since <time>`: journalctl-style time spec, e.g. `"30 minutes ago"` (overrides `--hours`)
- `--tail`: Stream journal live, printing events as they complete (Ctrl-C to stop)
- `--summary`: Print summary counts only without the per-event detail block
- `--verbose`: Include AURP peer connect/disconnect events in the event log
- `--all`: Show all inbound NBP lookup types, not only `AFPServer`

**Flow steps tracked for each inbound FwdReq**:
1. FwdReq received from remote AURP peer (peer IP, NBP id, original reply-to tuple)
2. Tuple reply-to address rewritten to local router address
3. LkUp broadcast on local Ethernet segment
4. LkUpReply received from `afpd`
5. Reply forwarded back through AURP tunnel to original requester

**Outcome codes**:
- `✓ FORWARDED` — complete round trip succeeded; remote user should see the server
- `✗ DROPPED (no tracked request)` — reply arrived but tracking entry was missing
- `? LKUP BROADCAST, no reply` — `afpd` didn't respond (likely NBP registration gap after atalkd restart)
- `? INCOMPLETE` — log window ended before the lookup resolved

**Summary section reports**:
- Inbound FwdReq count and AFPServer-specific count
- Reply forwarded / dropped counts
- Outbound BrRq count (local Mac scanning remote zones)
- AURP peer connection and route counts
- SEGV crashes, atalkd/netatalk restarts, AFPServer re-registrations

**Exit codes** (useful for scripting/monitoring):
- `0` — healthy
- `1` — one or more SEGV crashes detected
- `2` — AFPServer lookups received but zero replies forwarded (broken reply path)

**Example output**:
```
════════════════════════════════════════════════════════════
  AURP/NBP Flow Summary  —  last 2.0h
════════════════════════════════════════════════════════════

  Inbound NBP lookups from remote peers:
    Total FwdReq received:        17
    For AFPServer:                 9
    Replies forwarded via AURP:    9  ✓
    Replies dropped:               0

  Health:
    SEGV crashes:                  0
    atalkd restarts:               0
    netatalk restarts:             0
    AFPServer re-registrations:    1
════════════════════════════════════════════════════════════

  Event log:
  Feb 25 21:28:15  ℹ NBP: AFPServer registered at 650.41:128 zone=netjibbing
  Feb 25 21:30:02  =:AFPServer@netjibbing (+4 retries)
    peer=71.74.97.148  orig_tuple=9315.50.254
    → tuple rewritten to 650.41.2
    → LkUp broadcast on local net
    → LkUpReply received from afpd
    ✓ FORWARDED
```

**When to use**:
- After a code change, run `python3 aurp_nbp_flow.py --since "5 minutes ago"` immediately after TalkScanner's next sweep to see if the reply path worked
- Run `--tail` during live debugging sessions to see events in real time
- Run `--summary` as a quick health check (scriptable, exit code signals problems)
- Run `-H 24` the morning after an overnight soak test to see the full picture

---

### nbp_scan_monitor.py

**Purpose**: Shows detailed information about recent NBP lookups and scans seen on the local AppleTalk network. Filters to highlight external (non-local) scans. See `NBP_SCAN_MONITOR.md` for full documentation.

**Usage**:
```bash
python3 nbp_scan_monitor.py [options]
```

**Quick reference**: external scans by zone, object, and source address; complements `aurp_nbp_flow.py` (which focuses on the inbound AURP→local reply path).

---

### aurp_packet_compare.py

**Purpose**: Compares AURP packets between two pcap captures byte-by-byte to identify protocol differences. Essential for debugging when comparing netatalk behavior against a reference implementation like jrouter.

**Usage**:
```bash
python3 aurp_packet_compare.py <pcap1> <pcap2> [packet_type]
```

**Arguments**:
- `pcap1`: First pcap file (e.g., jrouter capture)
- `pcap2`: Second pcap file (e.g., netatalk capture)
- `packet_type`: Type of packet to compare (default: `open-req`)

**Supported Packet Types**:
- `open-req`: Connection initiation request
- `open-rsp`: Connection initiation response
- `ri-req`: Routing Information request
- `ri-rsp`: Routing Information response
- `ri-ack`: Routing Information acknowledgment
- `ri-upd`: Routing Information update
- `zi-req`: Zone Information request
- `zi-rsp`: Zone Information response
- `tickle`: Keepalive packet
- `tickle-ack`: Keepalive acknowledgment

**Features**:
- Finds first matching packet of specified type in each capture
- Shows raw hex dump of each packet
- Performs byte-by-byte comparison with visual diff markers
- Lists all byte offsets where differences occur
- Helpful for identifying subtle protocol bugs

**Example**:
```bash
# Compare Open-Req packets between jrouter and netatalk
python3 aurp_packet_compare.py jrouter.pcap netatalk.pcap open-req

# Compare Tickle packets
python3 aurp_packet_compare.py capture1.pcap capture2.pcap tickle
```

**Dependencies**: Requires `scapy` (`pip install scapy`)

---

### mount_appletalk.sh

**Purpose**: Interactive tool for mounting AFP file shares via AppleTalk from a Linux client. Attempts to use available AFP mounting utilities to establish connections to remote AFP servers discovered via AppleTalk.

**Usage**:
```bash
./mount_appletalk.sh <zone> <server> <share> <mount_point> [username]
```

**Arguments**:
- `zone`: AppleTalk zone name (e.g., "BaroNet")
- `server`: AppleTalk server name (e.g., "Blackbird")
- `share`: Share/volume name to mount (e.g., "Public")
- `mount_point`: Local directory path for mount point (e.g., "/mnt/afp")
- `username`: (Optional) Username for authentication (default: "guest")

**Features**:
- Auto-detects available AFP client tools (`mount_afp`, `afp_client`, or kernel AFP support)
- Creates mount point directory if it doesn't exist
- Detects and prompts to unmount if mount point is already in use
- Constructs proper AFP URLs for AppleTalk connections (`afp://at/Zone:Server/Share`)
- Supports both guest and authenticated mounts
- Color-coded output for success/error messages
- Provides troubleshooting tips on failure

**AFP URL Format**:
- Guest: `afp://at/Zone:Server/Share`
- Authenticated: `afp://username@at/Zone:Server/Share`

**Example**:
```bash
# Mount as guest (default)
./mount_appletalk.sh "BaroNet" "Blackbird" "Public" "/mnt/blackbird"

# Mount with authentication
./mount_appletalk.sh "BaroNet" "landisk" "Data" "/mnt/landisk" "admin"

# Unmount when done
umount /mnt/blackbird
```

**Requirements**:
- One of: `afpfs-ng` package, macOS `mount_afp`, or kernel AFP support
- atalkd service running and connected to AppleTalk network
- AppleTalk routing to the target zone/network

**Troubleshooting**:
- **"No AFP mounting tool found"**: Install `afpfs-ng` on Linux (`apt install afpfs-ng`)
- **"Failed to mount"**: Verify AppleTalk connectivity with `ping` or `nbplkup`
- **Connection hangs**: Check that AURP routes exist to target network (check routing table)
- **Authentication fails**: Verify username/password, try guest mount first

**Note**: This tool requires AFP client libraries which are not commonly available on Linux systems. Most modern Linux distributions do not include AFP mounting support. The script will detect available tools and attempt to use them, but may fail if no AFP client is installed.

---

### diagnose_afp_mount.sh

**Purpose**: Interactive diagnostic tool to capture and analyze network traffic during AFP mount attempts from Mac clients. Helps identify the exact point of failure when AFP mounts don't work over AURP.

**Usage**:
```bash
./diagnose_afp_mount.sh
```

**Interactive Procedure**:
1. Starts packet capture on UDP port 387 (AppleTalk/AURP)
2. Waits for user to attempt AFP mount from Mac Chooser
3. Stops capture when mount attempt completes
4. Analyzes captured packets to diagnose failure point

**Analysis Output**:
- **Packet counts** by DDP protocol type:
  - RTMP (type 1): Routing updates
  - NBP (type 2): Name lookups
  - ATP (type 3): File transfer connections
- **Diagnostic results**:
  - ✓ NBP working: Mac found the server
  - ⨯ ATP missing: Mac can't connect to server (most common)
  - ⨯ NBP missing: Mac didn't look up server name
- **Recent atalkd logs**: Shows routing, connection, and error messages
- **Recommendations**: Specific troubleshooting steps based on symptoms

**Common Findings**:
- **NBP packets but no ATP**: Mac lacks route to server's network
  - Check RTMP broadcasts reach Mac
  - Verify Mac's routing table includes remote networks
  - Ensure AURP routes have zone information before broadcast
- **No NBP packets**: Mac didn't browse or click server
  - User didn't interact with Chooser properly
  - Capture started too late
- **Both NBP and ATP**: Connection established, failure is AFP-level
  - Check authentication, permissions, protocol version

**Output Files**:
- Capture saved to: `../tmp_packetcaptures/afp_mount_debug_YYYYMMDD_HHMMSS.pcap`

**Example Session**:
```bash
./diagnose_afp_mount.sh
# Press ENTER to start
# [Open Chooser on Mac, click on server]
# [Wait for mount to fail or succeed]
# Press ENTER to analyze
# View results and recommendations
```

**Dependencies**: Requires `tcpdump` and `journalctl`. Mac client must be on local network segment.

---

### test_nbp_replies.sh

**Purpose**: Automated test to verify if netatalk is receiving NBP replies from remote AURP peers. Combines packet capture with zone scanning to diagnose reply issues without requiring a Mac.

**Usage**:
```bash
./test_nbp_replies.sh [options]
```

**Options**:
- `--capture-time <sec>`: Capture duration in seconds (default: 90)
- `--zone <name>`: Scan specific zone (can repeat for multiple zones)
- `--obj <name>`: NBP object to search for (default: `=` for all)
- `--type <type>`: NBP type to search for (default: `=` for all)
- `--help`: Show help message

**Test Procedure**:
1. Verifies atalkd is running
2. Starts background packet capture (90 seconds by default)
3. Waits 5 seconds for AURP to stabilize
4. Runs `nbp_zone_scan.py` with specified parameters
5. Waits for packet capture to complete
6. Analyzes capture with `aurp_pcap_analyze.py`
7. Reports results with clear pass/fail status

**Success Criteria**:
- ✓ NBP FwdReq queries are sent to remote peers
- ✓ AURP data packets are received from peers
- ✓ Received packets include NBP LkUpReply messages

**Output**:
- Shows NBP scan results (what services were found)
- Displays packet statistics (queries sent, replies received)
- Checks for common configuration issues:
  - Extended network flag set correctly
  - Zone information being advertised
  - AURP data packets being processed
- Exit code 0 on success, 1 on failure

**Example**:
```bash
# Basic test - scan all zones for all services
./test_nbp_replies.sh

# Test for AFP servers only
./test_nbp_replies.sh --type AFPServer

# Test specific zones with longer capture
./test_nbp_replies.sh --zone netjibbing --zone Airaga --capture-time 120

# Quick test for workstations
./test_nbp_replies.sh --type Workstation --capture-time 60
```

**Output Files** (in `../tmp_packetcaptures/`):
- `nbp_test_YYYYMMDD_HHMMSS.pcap`: Packet capture during test
- `nbp_test_YYYYMMDD_HHMMSS_analysis.txt`: Packet analysis results
- `nbp_test_YYYYMMDD_HHMMSS_scan.txt`: NBP zone scan output

**When to Use**:
- After making changes to AURP code to verify NBP still works
- Diagnosing why remote services don't appear in Chooser
- Comparing before/after behavior when fixing bugs
- Automated testing in CI/CD pipelines (scriptable, no GUI needed)

**Advantages over Manual Testing**:
- No Mac required - runs entirely on Linux server
- Automated pass/fail determination
- Captures diagnostic data automatically
- Consistent test procedure
- Can be scripted/scheduled

---

### compare_nbp.sh

**Purpose**: Automated comparison test script that captures NBP packet behavior for both netatalk and jrouter implementations.

**Usage**:
```bash
./compare_nbp.sh
```

**Test Procedure**:
1. Starts netatalk's atalkd
2. Waits for AURP connections to establish (60 seconds)
3. Captures AURP packets during Mac Chooser browsing session
4. Analyzes netatalk packet capture
5. Stops netatalk and waits for Mac to detect network change (30 seconds)
6. Starts jrouter
7. Waits for jrouter connections to establish (60 seconds)  
8. Prompts for screenshot of jrouter status page at http://192.168.0.214:9459/status
9. Captures AURP packets during second Mac Chooser browsing session
10. Analyzes jrouter packet capture
11. Displays side-by-side comparison of results

**Output Files** (in `../tmp_packetcaptures/`):
- `netatalk_aurp.pcap`: Packet capture from netatalk test
- `netatalk_analysis.txt`: Analysis summary for netatalk
- `jrouter_aurp.pcap`: Packet capture from jrouter test
- `jrouter_analysis.txt`: Analysis summary for jrouter
- `jrouter.log`: jrouter console output

**Interactive Steps**:
- User must browse with Mac Chooser during indicated periods
- User must press Enter after each browsing session
- User should capture screenshot of jrouter status page when prompted

**Purpose**: 
- Identifies behavioral differences between netatalk and jrouter
- Helps diagnose why jrouter receives NBP replies but netatalk doesn't
- Validates fixes by comparing before/after behavior

---

### compare_nbp_packets.py

**Purpose**: Deep packet-level comparison of NBP FwdReq packets between netatalk and jrouter captures.

**Usage**:
```bash
python3 compare_nbp_packets.py <netatalk.pcap> <jrouter.pcap>
```

**Features**:
- Parses AURP type 0x0002 (data) packets to extract DDP headers
- Focuses specifically on NBP FwdReq (op=4) packets
- Compares DDP source/destination addresses between implementations
- Identifies mismatches in packet structure that could prevent NBP replies
- Shows first few packets from each capture for detailed inspection

**Output**:
- Displays first 3 NBP FwdReq packets from each capture
- Shows total count of FwdReq packets sent
- Highlights any differences in DDP addressing (network, node, socket)
- Alerts on critical mismatches that could break routing

**Example**:
```bash
python3 compare_nbp_packets.py \
    ../tmp_packetcaptures/netatalk_aurp.pcap \
    ../tmp_packetcaptures/jrouter_aurp.pcap
```

**Use Case**: Debugging subtle packet format issues that cause remote peers to drop or misroute NBP replies.

---

## Common Workflows

### Quick NBP Reply Verification (No Mac Required)

**Fastest way to test if AURP NBP is working:**

```bash
./test_nbp_replies.sh
```

This single command:
- Captures packets during NBP zone scan
- Checks if we're receiving replies
- Reports clear pass/fail status
- Saves diagnostic data for further analysis

**Example output when working:**
```
✓ NBP queries are being sent
✓ Receiving AURP data packets from peers
✓ SUCCESS: Receiving NBP replies! (16 replies)
✓ Advertising network as extended (correct for Phase 2)
✓ Sent zone information to 12 peer(s)
✓✓✓ TEST PASSED: NBP replies are working! ✓✓✓
```

**Example output when broken:**
```
✓ NBP queries are being sent
✗ NOT receiving any AURP data packets
✗✗✗ TEST FAILED: Not receiving NBP replies ✗✗✗
```

### Testing Basic AURP Connectivity

1. Use `aurp_probe.py` to verify peer responds:
   ```bash
   python3 aurp_probe.py tickle <peer_ip>
   ```

2. Check if connection can be established:
   ```bash
   python3 aurp_probe.py open <peer_ip>
   ```

### Diagnosing NBP Forwarding Issues

1. Scan all zones to see what's visible:
   ```bash
   python3 nbp_zone_scan.py
   ```

2. If results are missing, capture packets during browsing:
   ```bash
   sudo tcpdump -i any port 387 -w ../tmp_packetcaptures/test.pcap &
   # Browse with Mac Chooser
   sudo pkill tcpdump
   ```

3. Analyze the capture:
   ```bash
   python3 aurp_pcap_analyze.py ../tmp_packetcaptures/test.pcap
   ```

4. Check for:
   - Are FwdReq packets being sent? (outbound type0002 NBP FwdReq)
   - Are LkUpReply packets being received? (inbound type0002 NBP LkUpReply)
   - Are Tickles being exchanged? (bidirectional Tickle/Tickle-Ack)

### Comparing netatalk vs jrouter Behavior

1. Run the automated comparison:
   ```bash
   cd tools/
   ./compare_nbp.sh
   ```

2. After completion, review the analysis files:
   ```bash
   cat ../tmp_packetcaptures/netatalk_analysis.txt
   cat ../tmp_packetcaptures/jrouter_analysis.txt
   ```

3. Compare key metrics:
   - Inbound type0002 packets (should have NBP LkUpReply)
   - Outbound type0002 packets (FwdReq queries)
   - Peer connection counts
   - Routing update exchanges (RI-Req/RI-Rsp/RI-Ack)

4. For deep packet analysis:
   ```bash
   python3 compare_nbp_packets.py \
       ../tmp_packetcaptures/netatalk_aurp.pcap \
       ../tmp_packetcaptures/jrouter_aurp.pcap
   ```

### Monitoring AURP Activity

**Log-based (no capture required — preferred for ongoing monitoring)**:

```bash
# Quick health snapshot — last 2 hours
python3 aurp_nbp_flow.py

# Summary only, suitable for scripting
python3 aurp_nbp_flow.py --summary
echo "Exit: $?"   # 0=healthy, 1=crash, 2=broken reply path

# Live follow — see events as they happen (TalkScanner sweeps arrive hourly)
python3 aurp_nbp_flow.py --tail

# Morning-after soak test review
python3 aurp_nbp_flow.py -H 12 --summary
```

**Packet-capture based (when you need raw byte-level detail)**:

1. Start a capture in background:
   ```bash
   sudo tcpdump -i any port 387 -w ../tmp_packetcaptures/monitor.pcap -G 300 -W 1 &
   ```

2. Let it run for 5 minutes (or adjust `-G` seconds)

3. Analyze periodic activity:
   ```bash
   python3 aurp_pcap_analyze.py ../tmp_packetcaptures/monitor.pcap
   ```

4. Look for anomalies:
   - Missing Tickle exchanges (connections may be stale)
   - Unexpected RI-Upd packets (route changes)
   - Router Down (RD) packets (peers disconnecting)

---

## Dependencies

### System Requirements
- Python 3.6+
- tcpdump (packet capture)
- Netatalk binaries: `getzones`, `nbplkup` (for nbp_zone_scan.py)

### Python Standard Library Only
All Python tools use only standard library modules:
- `socket`, `struct` - Network/binary operations
- `argparse` - Command-line parsing
- `subprocess` - Running external commands
- `collections` - Data structures
- `ipaddress` - IP address handling

No external Python packages (like scapy) are required.

---

## Troubleshooting Tips

### No Results from nbp_zone_scan.py
- Check `getzones` returns zones: `getzones`
- Verify atalkd is running: `systemctl status atalkd`
- Check local zone is configured: `cat /tmp/netatalk-*/atalkd.*.debug`
- Test direct NBP lookup: `nbplkup =:=@*`

### AURP Probe Gets No Response
- Verify peer IP is correct and reachable: `ping <peer_ip>`
- Check firewall allows UDP port 387: `sudo iptables -L | grep 387`
- Confirm peer is running AURP router
- Try different modes: `tickle` for existing connections, `open` for new

### compare_nbp.sh Shows Differences
- **netatalk sends FwdReq but receives 0 replies**: Remote peers can't route back to us
  - Check RI-Rsp advertises network as extended (for Phase 2 networks)
  - Verify Zone Information is sent (ZI-Rsp with zone names)
  - Ensure peers have learned our routes (check logs for "learned route")
- **Different peer counts**: Timing issue, connections not fully established
  - Increase sleep timers in script
  - Restart both implementations before testing
- **jrouter receives replies but netatalk doesn't**: Implementation bug
  - Compare packet structures with `compare_nbp_packets.py`
  - Check atalkd logs for incoming packet processing
  - Verify `aurp_handle_data()` is called for type 0x0002 packets

### Packet Analysis Shows Zero type0002
- No NBP queries sent: Check if Mac Chooser was actually browsing
- Capture too short: Increase tcpdump `-G` timer
- Wrong interface: Use `-i any` to capture all interfaces
- Port filter wrong: Verify `port 387` matches AURP packets

---

## Development Notes

### Adding New Tools

When adding new analysis or testing tools:

1. Place executable scripts in this `tools/` directory
2. Store output/data files in `../tmp_packetcaptures/`
3. Update this README with:
   - Tool purpose and usage
   - Command-line options
   - Example invocations
   - Output format description
4. Make scripts executable: `chmod +x <script>`
5. Use shebang: `#!/usr/bin/env python3` or `#!/bin/bash`
6. Add brief docstring/comment at top of file

### Test Data Organization

The `../tmp_packetcaptures/` directory contains:
- `.pcap` files: Raw packet captures from tcpdump
- `.txt` files: Analysis outputs, logs, zone lists
- `.log` files: Console output from atalkd, jrouter, etc.
- `.json` files: Structured data exports (routes, status)
- `.sh` and `.py` files: (Legacy - moved to tools/)

Naming convention: `<tool>_<date>_<description>.<ext>`
Example: `aurp_scan_20260125_vintage.pcap`

### Known Issues

- `compare_nbp_packets.py`: Currently finds 0 packets due to hardcoded offset assumptions
  - Needs update for actual packet structure in captures
  - IPv6 packets may have different offsets
- `compare_nbp.sh`: Requires manual Mac Chooser interaction
  - Could be automated with AppleScript if Mac scripting is available
- `aurp_probe.py`: Only sends packets, doesn't listen for responses
  - Future: Add response capture and validation

---

## See Also

- [AURP_IMPLEMENTATION_PLAN.md](../AURP_IMPLEMENTATION_PLAN.md) - Implementation design and progress tracking
- [AURP_PACKET_DETAILS.md](../AURP_PACKET_DETAILS.md) - Detailed packet format documentation
- [CAPTURE_USAGE.md](../CAPTURE_USAGE.md) - Guide for capturing and analyzing AppleTalk traffic
- Netatalk documentation: https://netatalk.sourceforge.io/
- AppleTalk Protocol Specification (Inside AppleTalk)
