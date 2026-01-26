#!/usr/bin/env python3
"""
aurp_packet_compare.py - Compare AURP packets between two pcap captures

This tool finds specific AURP packet types (like Open-Req) in two pcap files
and performs byte-by-byte comparison to identify protocol differences.

Useful for comparing jrouter (reference) vs netatalk implementations.

Usage:
    python3 aurp_packet_compare.py <pcap1> <pcap2> [packet_type]
    
    packet_type: open-req (default), tickle, ri-req, ri-rsp, etc.

Example:
    python3 aurp_packet_compare.py jrouter.pcap netatalk.pcap open-req
"""
import sys
import struct
from scapy.all import rdpcap, UDP

# AURP command codes
AURP_COMMANDS = {
    1: 'RI-Req',
    2: 'RI-Rsp',
    3: 'RI-Ack',
    4: 'RI-Upd',
    5: 'RD',
    6: 'ZI-Req',
    7: 'ZI-Rsp',
    8: 'Open-Req',
    9: 'Open-Rsp',
    14: 'Tickle',
    15: 'Tickle-Ack',
}

def find_aurp_packet(pkts, label, target_cmd):
    """Find AURP packets of specified command type in a pcap."""
    cmd_name = AURP_COMMANDS.get(target_cmd, f'cmd-{target_cmd}')
    print(f'\n=== {label} {cmd_name} packets ===')
    found = []
    for i, pkt in enumerate(pkts):
        if UDP in pkt:
            data = bytes(pkt[UDP].payload)
            if len(data) >= 14:
                pkt_type = struct.unpack('>H', data[20:22])[0]
                if pkt_type == 3:  # type 0003 = routing/control
                    cmd = struct.unpack('>H', data[22:24])[0]
                    if cmd == target_cmd:
                        print(f'Packet {i}: len={len(data)}')
                        print(f'  Hex: {data.hex()}')
                        found.append(data)
                        if len(found) >= 3:
                            break
    return found[0] if found else None

def compare_packets(pkt1, pkt2, label1, label2):
    """Perform byte-by-byte comparison of two packets."""
    print(f'\n=== BYTE-BY-BYTE COMPARISON ===')
    print(f'{label1} len: {len(pkt1)}, {label2} len: {len(pkt2)}')
    
    max_len = max(len(pkt1), len(pkt2))
    diffs = []
    for i in range(max_len):
        b1 = pkt1[i] if i < len(pkt1) else None
        b2 = pkt2[i] if i < len(pkt2) else None
        match = '  ' if b1 == b2 else '!!'
        if b1 != b2:
            diffs.append(i)
        hex1 = f'{b1:02x}' if b1 is not None else '--'
        hex2 = f'{b2:02x}' if b2 is not None else '--'
        print(f'  [{i:3d}] {match} {label1}={hex1} {label2}={hex2}')
    
    print(f'\nDifferences at byte offsets: {diffs}')
    return diffs

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("Available packet types:")
        for code, name in sorted(AURP_COMMANDS.items()):
            print(f"  {name.lower()}: {name} (cmd {code})")
        sys.exit(1)
    
    pcap1_path = sys.argv[1]
    pcap2_path = sys.argv[2]
    packet_type = sys.argv[3] if len(sys.argv) > 3 else 'open-req'
    
    # Map packet type name to command code
    cmd_map = {name.lower(): code for code, name in AURP_COMMANDS.items()}
    target_cmd = cmd_map.get(packet_type.lower())
    if target_cmd is None:
        print(f"Unknown packet type: {packet_type}")
        print("Available types:", list(cmd_map.keys()))
        sys.exit(1)
    
    print(f"Reading {pcap1_path}...")
    pkts1 = rdpcap(pcap1_path)
    print(f"  Found {len(pkts1)} packets")
    
    print(f"Reading {pcap2_path}...")
    pkts2 = rdpcap(pcap2_path)
    print(f"  Found {len(pkts2)} packets")
    
    label1 = pcap1_path.split('/')[-1].replace('.pcap', '')
    label2 = pcap2_path.split('/')[-1].replace('.pcap', '')
    
    pkt1 = find_aurp_packet(pkts1, label1, target_cmd)
    pkt2 = find_aurp_packet(pkts2, label2, target_cmd)
    
    if pkt1 and pkt2:
        compare_packets(pkt1, pkt2, label1, label2)
    else:
        print(f"\nCould not find {AURP_COMMANDS[target_cmd]} in one or both captures")

if __name__ == '__main__':
    main()
