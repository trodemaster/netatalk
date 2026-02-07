# NBP Scan Monitor

Monitor NBP (Name Binding Protocol) scan activity on your AppleTalk network.

## Overview

This tool analyzes `journalctl` logs from `atalkd` to show what remote systems are querying on your network. It helps you:

- See who's scanning your AppleTalk zones
- Identify what services they're looking for
- Detect network discovery/enumeration activity
- Monitor AFP server lookups and other service queries

## Requirements

- atalkd running with normal logging enabled (log_info level, default)
- Python 3
- Access to journalctl logs (may require sudo)

## Usage

### Basic Usage

Show the last 10 minutes of NBP activity:
```bash
python3 nbp_scan_monitor.py
```

### Common Options

```bash
# Show last 30 minutes
python3 nbp_scan_monitor.py -m 30

# Show detailed packet-by-packet activity
python3 nbp_scan_monitor.py -d

# Try to resolve addresses to NBP names (slower)
python3 nbp_scan_monitor.py -r

# Detailed view of last 5 minutes
python3 nbp_scan_monitor.py -m 5 -d
```

## Example Output

```
=== NBP Scan Activity (last 10 minutes) ===

Summary by Source:
----------------------------------------------------------------------------------------------------
Source               Name                      Packets    Top Services                  
----------------------------------------------------------------------------------------------------
650.197.252          Blake                     156        AFPServer(45), Workstation(32)
650.39.128           macpro2013                22         netatalk(8), AppleRouter(6)

Zones Queried:
----------------------------------------------------------------------------------------------------
  netjibbing                     (2 sources)
  PurrTopia                      (1 sources)
  *                              (1 sources)

Total: 178 NBP operations from 2 unique sources
```

## What Gets Logged

With normal logging (log_info level), atalkd logs:

1. **NBP Lookups** - When someone searches for a specific service
   - Format: `nbp lkup: 'object:type@zone' from net.node.socket`
   - Example: `nbp lkup: '=:AFPServer@netjibbing' from 650.197.252`

2. **Broadcast Requests** - When someone scans an entire zone
   - Format: `nbp brrq: received BrRq for zone 'zonename' from net.node.socket`
   - Example: `nbp brrq: received BrRq for zone 'netjibbing' from 650.197.252`

3. **General NBP Packets** - Any other NBP activity
   - Format: `nbp_packet: received N bytes from net.node.socket`

## Understanding the Output

### Lookup Types

- **`=:AFPServer@zone`** - Looking for ANY AFP file server in zone
- **`macpro2013:AFPServer@zone`** - Looking for specific server
- **`=:LaserWriter@zone`** - Looking for printers
- **`=:AppleRouter@zone`** - Looking for routers
- **`*:*@*`** - Wildcard lookup (everything)

### Activity Patterns

**Zone Scanner:**
```
650.197.252: Zone scan: netjibbing
650.197.252: Looking for =:AFPServer@netjibbing
650.197.252: Looking for =:LaserWriter@netjibbing
```
This indicates someone is enumerating all services in a zone.

**AFP Client:**
```
650.39.128: Looking for =:AFPServer@netjibbing
```
Someone's "Chooser" or Finder is looking for file servers to mount.

**Network Discovery:**
```
Multiple sources querying =:AppleRouter@*
```
Someone's mapping the network topology.

## Use Cases

### Security Monitoring
Detect unauthorized network enumeration:
```bash
# Monitor continuously
watch -n 30 'python3 nbp_scan_monitor.py -m 5'
```

### Troubleshooting
Debug why clients aren't finding your services:
```bash
# Check if clients are even querying
python3 nbp_scan_monitor.py -d | grep AFPServer
```

### Network Analysis
Understand how your network is being used:
```bash
# Weekly summary
python3 nbp_scan_monitor.py -m 10080 > weekly_activity.txt
```

## Privacy Note

This tool only shows information already logged by atalkd. It doesn't capture packet contents beyond what's in the logs, and all NBP queries are inherently broadcast protocols - anyone on the network can see them.

## Related Tools

- `nbplkup` - Perform NBP lookups yourself
- `nbp_zone_scan.py` - Comprehensive zone enumeration
- `getzones` - List all available zones
