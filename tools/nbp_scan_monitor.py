#!/usr/bin/env python3
"""
NBP Scan Monitor - Show detailed information about recent NBP lookups/scans

This tool parses journalctl logs to show who has been scanning your AppleTalk
network and what services they've been looking for.

By default, filters out local zone activity to show only external scans.
"""

import subprocess
import sys
import re
from collections import defaultdict
from datetime import datetime, timedelta

def parse_atalk_addr(addr_str):
    """Parse AppleTalk address like '650.197.252' into net.node"""
    parts = addr_str.split('.')
    if len(parts) == 3:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return addr_str

def get_local_zones():
    """Detect local zones by checking NBP registrations and interface config"""
    local_zones = set()
    local_networks = set()
    
    # Method 1: Check our own NBP registrations
    try:
        result = subprocess.run(['nbplkup', '@*'], capture_output=True, text=True, timeout=2)
        hostname = subprocess.run(['hostname'], capture_output=True, text=True, timeout=1).stdout.strip().split('.')[0]
        
        for line in result.stdout.split('\n'):
            # Look for our hostname in registrations
            if hostname.lower() in line.lower():
                # Extract the address (format: "name:type net.node:socket")
                # Example: "macpro2013:AppleRouter     650.39:4"
                match = re.search(r'\s+(\d+)\.(\d+):(\d+)\s*$', line)
                if match:
                    network = match.group(1)
                    local_networks.add(network)
    except Exception:
        pass  # Silent fail, will try other methods
    
    # Method 2: Check systemctl status for network info
    try:
        result = subprocess.run(
            ['systemctl', 'status', 'atalkd', '--no-pager'],
            capture_output=True, text=True, timeout=2
        )
        
        # Look for our process info which might show the network
        for line in result.stdout.split('\n'):
            if 'atalkd' in line:
                # Extract network numbers
                matches = re.findall(r'\b(\d{1,5})\.(\d{1,3})\b', line)
                for net, node in matches:
                    if int(net) < 65535 and int(node) < 255:
                        local_networks.add(net)
    except Exception:
        pass  # Silent fail
    
    # Method 3: Parse atalkd startup logs to find our zone
    try:
        result = subprocess.run(
            ['journalctl', '-u', 'atalkd', '--since', '24 hours ago', '--no-pager'],
            capture_output=True, text=True, timeout=2
        )
        
        # Look for zone information in startup/config messages
        for line in result.stdout.split('\n'):
            # Match patterns like "zone 'zonename'" in our config
            if 'restart' in line or 'Started' in line:
                match = re.search(r"zone[: ]*['\"]([^'\"]+)['\"]" , line, re.IGNORECASE)
                if match:
                    zone = match.group(1)
                    if zone != '*' and zone != '=' and len(zone) > 0:
                        local_zones.add(zone)
    except Exception:
        pass  # Silent fail
    
    return local_zones, local_networks

def is_local_source(source, local_networks):
    """Check if a source address is from our local network(s)"""
    if not local_networks:
        return False
    
    parts = source.split('.')
    if len(parts) >= 1:
        network = parts[0]
        return network in local_networks
    return False

def get_nbp_activity(minutes=10):
    """Get NBP activity from journalctl logs"""
    try:
        since = f"{minutes} minutes ago"
        cmd = ["journalctl", "-u", "atalkd", "--since", since, "--no-pager"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error reading logs: {e}", file=sys.stderr)
        return ""

def parse_nbp_logs(logs):
    """Parse NBP activity from logs"""
    
    # Pattern for NBP packet receipts
    packet_pattern = re.compile(
        r'(\w+ \d+ \d+:\d+:\d+).*nbp_packet: received (\d+) bytes from (\d+\.\d+\.\d+)'
    )
    
    # Pattern for BrRq (broadcast requests)
    brrq_pattern = re.compile(
        r"(\w+ \d+ \d+:\d+:\d+).*nbp brrq: received BrRq for zone '([^']+)' from (\d+\.\d+\.\d+)"
    )
    
    # Pattern for lookups (detailed)
    lkup_pattern = re.compile(
        r"(\w+ \d+ \d+:\d+:\d+).*nbp lkup: '([^']+)' from (\d+\.\d+\.\d+)"
    )
    
    scans = []
    
    for line in logs.split('\n'):
        # Check for lookups (most specific)
        lkup_match = lkup_pattern.search(line)
        if lkup_match:
            timestamp = lkup_match.group(1)
            nbp_name = lkup_match.group(2)
            source = parse_atalk_addr(lkup_match.group(3))
            
            # Parse NBP name (object:type@zone)
            parts = nbp_name.split('@')
            zone = parts[1] if len(parts) > 1 else '*'
            service_parts = parts[0].split(':')
            obj = service_parts[0] if len(service_parts) > 0 else '='
            svc_type = service_parts[1] if len(service_parts) > 1 else '='
            
            scans.append({
                'timestamp': timestamp,
                'type': 'Lookup',
                'source': source,
                'zone': zone,
                'object': obj,
                'service': svc_type,
                'detail': f"Looking for {nbp_name}"
            })
            continue
        
        # Check for broadcast requests
        brrq_match = brrq_pattern.search(line)
        if brrq_match:
            timestamp = brrq_match.group(1)
            zone = brrq_match.group(2)
            source = parse_atalk_addr(brrq_match.group(3))
            
            scans.append({
                'timestamp': timestamp,
                'type': 'BrRq',
                'source': source,
                'zone': zone,
                'object': '',
                'service': '',
                'detail': f"Zone scan: {zone}"
            })
            continue
        
        # Check for general NBP packets
        packet_match = packet_pattern.search(line)
        if packet_match:
            timestamp = packet_match.group(1)
            size = packet_match.group(2)
            source = parse_atalk_addr(packet_match.group(3))
            
            # Only log if it's not already part of a BrRq/Lookup we caught
            if not any(s['source'] == source and s['timestamp'] == timestamp 
                      for s in scans[-5:] if scans):
                scans.append({
                    'timestamp': timestamp,
                    'type': 'NBP',
                    'source': source,
                    'zone': '?',
                    'object': '',
                    'service': '',
                    'detail': f"NBP packet ({size} bytes)"
                })
    
    return scans

def summarize_activity(scans):
    """Summarize scan activity by source"""
    by_source = defaultdict(lambda: {
        'count': 0,
        'zones': set(),
        'services': defaultdict(int),
        'first_seen': None,
        'last_seen': None,
        'types': defaultdict(int)
    })
    
    for scan in scans:
        source = scan['source']
        info = by_source[source]
        info['count'] += 1
        info['types'][scan['type']] += 1
        
        if scan['zone'] != '?':
            info['zones'].add(scan['zone'])
        
        if scan.get('service') and scan['service'] != '=':
            info['services'][scan['service']] += 1
        
        if info['first_seen'] is None:
            info['first_seen'] = scan['timestamp']
        info['last_seen'] = scan['timestamp']
    
    return by_source

def resolve_nbp_name(address):
    """Try to resolve AppleTalk address to NBP name"""
    try:
        parts = address.split('.')
        if len(parts) != 3:
            return None
        
        # Use nbplkup to find what's registered at this address
        cmd = ["nbplkup", f"@*"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        
        # Parse nbplkup output to find matching address
        for line in result.stdout.split('\n'):
            if address in line:
                # Extract the name (format: "name:type net.node:socket")
                match = re.match(r'\s*([^:]+):', line)
                if match:
                    return match.group(1).strip()
        return None
    except:
        return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Monitor NBP scan activity on your AppleTalk network',
        epilog='By default, filters out local zone activity. Use --include-local to see everything.'
    )
    parser.add_argument(
        '-m', '--minutes',
        type=int,
        default=10,
        help='Minutes of history to show (default: 10)'
    )
    parser.add_argument(
        '-d', '--detailed',
        action='store_true',
        help='Show detailed packet-by-packet activity'
    )
    parser.add_argument(
        '-r', '--resolve',
        action='store_true',
        help='Try to resolve addresses to NBP names (slower)'
    )
    parser.add_argument(
        '--include-local',
        action='store_true',
        help='Include activity from local zone (default: filter out local activity)'
    )
    parser.add_argument(
        '--show-local-info',
        action='store_true',
        help='Show detected local zones/networks and exit'
    )
    
    args = parser.parse_args()
    
    # Detect local zones and networks
    local_zones, local_networks = get_local_zones()
    
    if args.show_local_info:
        print("=== Detected Local Configuration ===\n")
        print(f"Local Zones: {', '.join(sorted(local_zones)) if local_zones else '(none detected)'}")
        print(f"Local Networks: {', '.join(sorted(local_networks)) if local_networks else '(none detected)'}")
        print("\nNote: Detection is based on:")
        print("  - NBP registrations matching hostname")
        print("  - Zone information from atalkd logs")
        print("  - Network numbers from interface configuration")
        return 0
    
    filter_msg = "external sources only" if not args.include_local and local_networks else "all sources"
    print(f"=== NBP Scan Activity (last {args.minutes} minutes, {filter_msg}) ===")
    if local_networks and not args.include_local:
        print(f"    (Filtering out local networks: {', '.join(sorted(local_networks))})")
    print()
    
    logs = get_nbp_activity(args.minutes)
    if not logs:
        print("No logs available or unable to read logs.")
        return 1
    
    scans = parse_nbp_logs(logs)
    
    # Filter out local sources unless requested
    if not args.include_local and local_networks:
        original_count = len(scans)
        scans = [s for s in scans if not is_local_source(s['source'], local_networks)]
        filtered_count = original_count - len(scans)
        if filtered_count > 0:
            print(f"(Filtered {filtered_count} local operations)\n")
    
    if not scans:
        print("No NBP activity detected from external sources.")
        print("Use --include-local to see local zone activity.")
        return 0
    
    if args.detailed:
        print("Detailed Activity:")
        print("-" * 80)
        for scan in scans:
            print(f"{scan['timestamp']:16} {scan['source']:15} {scan['type']:6} {scan['detail']}")
        print()
    
    # Show summary
    print("Summary by Source:")
    print("-" * 100)
    print(f"{'Source':<20} {'Name':<25} {'Packets':<10} {'Top Services':<30}")
    print("-" * 100)
    
    summary = summarize_activity(scans)
    for source in sorted(summary.keys()):
        info = summary[source]
        
        name = "?"
        if args.resolve:
            resolved = resolve_nbp_name(source)
            if resolved:
                name = resolved
        
        # Show top 3 services queried
        top_services = sorted(info['services'].items(), key=lambda x: x[1], reverse=True)[:3]
        services_str = ", ".join([f"{s}({c})" for s, c in top_services]) if top_services else "(zone scans)"
        if len(services_str) > 28:
            services_str = services_str[:25] + "..."
        
        print(f"{source:<20} {name:<25} {info['count']:<10} {services_str:<30}")
    
    # Show zones scanned
    print(f"\nZones Queried:")
    print("-" * 100)
    all_zones = set()
    for info in summary.values():
        all_zones.update(info['zones'])
    for zone in sorted(all_zones):
        sources_for_zone = [s for s, i in summary.items() if zone in i['zones']]
        print(f"  {zone:<30} ({len(sources_for_zone)} sources)")
    
    print(f"\nTotal: {len(scans)} NBP operations from {len(summary)} unique sources")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
