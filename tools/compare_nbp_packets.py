#!/usr/bin/env python3
"""Compare NBP packet structures between netatalk and jrouter captures."""

import sys
import struct
from collections import namedtuple

PCAPFileHeader = namedtuple('PCAPFileHeader', 
    'magic_number version_major version_minor thiszone sigfigs snaplen network')
PCAPPacketHeader = namedtuple('PCAPPacketHeader',
    'ts_sec ts_usec incl_len orig_len')

def read_pcap_packets(filename):
    """Read packets from pcap file."""
    packets = []
    with open(filename, 'rb') as f:
        # Read file header (24 bytes)
        file_header_data = f.read(24)
        if len(file_header_data) < 24:
            return packets
        
        file_header = PCAPFileHeader._make(struct.unpack('IHHiIII', file_header_data))
        
        # Read packets
        while True:
            # Read packet header (16 bytes)
            pkt_header_data = f.read(16)
            if len(pkt_header_data) < 16:
                break
            
            pkt_header = PCAPPacketHeader._make(struct.unpack('IIII', pkt_header_data))
            
            # Read packet data
            pkt_data = f.read(pkt_header.incl_len)
            if len(pkt_data) < pkt_header.incl_len:
                break
            
            packets.append(pkt_data)
    
    return packets

def parse_aurp_data_packet(pkt_data):
    """Parse AURP type 0x0002 data packet to extract DDP header."""
    # Skip Ethernet (14) + IP (20) + UDP (8) headers = 42 bytes
    if len(pkt_data) < 90:
        return None
    
    # Find UDP port 387
    ip_start = 14
    udp_start = ip_start + 20
    src_port = (pkt_data[udp_start] << 8) | pkt_data[udp_start + 1]
    dst_port = (pkt_data[udp_start + 2] << 8) | pkt_data[udp_start + 3]
    
    if src_port != 387 and dst_port != 387:
        return None
    
    # UDP payload starts at udp_start + 8
    payload_start = udp_start + 8
    payload = pkt_data[payload_start:]
    
    if len(payload) < 40:
        return None
    
    # AURP domain header (22 bytes) + transport header (8 bytes) = 30 bytes
    # Command code at offset 30-31
    if len(payload) < 32:
        return None
    
    cmd_code = (payload[30] << 8) | payload[31]
    if cmd_code != 0x0002:  # Not a data packet
        return None
    
    # DDP extended header starts at offset 34
    if len(payload) < 48:
        return None
    
    ddp_start = 34
    ddp_len = (payload[ddp_start] << 8) | payload[ddp_start + 1]
    ddp_cksum = (payload[ddp_start + 2] << 8) | payload[ddp_start + 3]
    ddp_dst_net = (payload[ddp_start + 4] << 8) | payload[ddp_start + 5]
    ddp_src_net = (payload[ddp_start + 6] << 8) | payload[ddp_start + 7]
    ddp_dst_node = payload[ddp_start + 8]
    ddp_src_node = payload[ddp_start + 9]
    ddp_dst_sock = payload[ddp_start + 10]
    ddp_src_sock = payload[ddp_start + 11]
    ddp_proto = payload[ddp_start + 12]
    
    # NBP packet starts after DDP header (13 bytes)
    nbp_start = ddp_start + 13
    if len(payload) < nbp_start + 2:
        return None
    
    nbp_ctrl = payload[nbp_start]
    nbp_op = (nbp_ctrl >> 4) & 0x0F
    nbp_count = nbp_ctrl & 0x0F
    nbp_id = payload[nbp_start + 1]
    
    return {
        'ddp_len': ddp_len,
        'ddp_cksum': ddp_cksum,
        'ddp_dst_net': ddp_dst_net,
        'ddp_src_net': ddp_src_net,
        'ddp_dst_node': ddp_dst_node,
        'ddp_src_node': ddp_src_node,
        'ddp_dst_sock': ddp_dst_sock,
        'ddp_src_sock': ddp_src_sock,
        'ddp_proto': ddp_proto,
        'nbp_op': nbp_op,
        'nbp_count': nbp_count,
        'nbp_id': nbp_id,
        'full_payload': payload.hex()
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: compare_nbp_packets.py <netatalk.pcap> <jrouter.pcap>")
        sys.exit(1)
    
    netatalk_file = sys.argv[1]
    jrouter_file = sys.argv[2]
    
    print("=== Analyzing netatalk NBP queries ===")
    netatalk_pkts = read_pcap_packets(netatalk_file)
    netatalk_nbp = []
    for pkt in netatalk_pkts:
        parsed = parse_aurp_data_packet(pkt)
        if parsed and parsed['nbp_op'] == 4:  # FwdReq
            netatalk_nbp.append(parsed)
            if len(netatalk_nbp) <= 3:
                print(f"\nPacket {len(netatalk_nbp)}:")
                print(f"  DDP: {parsed['ddp_src_net']}.{parsed['ddp_src_node']}:{parsed['ddp_src_sock']} -> {parsed['ddp_dst_net']}.{parsed['ddp_dst_node']}:{parsed['ddp_dst_sock']}")
                print(f"  NBP: op={parsed['nbp_op']} (FwdReq) id={parsed['nbp_id']} count={parsed['nbp_count']}")
                print(f"  Proto: {parsed['ddp_proto']}")
    
    print(f"\nTotal netatalk FwdReq packets: {len(netatalk_nbp)}")
    
    print("\n=== Analyzing jrouter NBP queries ===")
    jrouter_pkts = read_pcap_packets(jrouter_file)
    jrouter_nbp = []
    for pkt in jrouter_pkts:
        parsed = parse_aurp_data_packet(pkt)
        if parsed and parsed['nbp_op'] == 4:  # FwdReq
            jrouter_nbp.append(parsed)
            if len(jrouter_nbp) <= 3:
                print(f"\nPacket {len(jrouter_nbp)}:")
                print(f"  DDP: {parsed['ddp_src_net']}.{parsed['ddp_src_node']}:{parsed['ddp_src_sock']} -> {parsed['ddp_dst_net']}.{parsed['ddp_dst_node']}:{parsed['ddp_dst_sock']}")
                print(f"  NBP: op={parsed['nbp_op']} (FwdReq) id={parsed['nbp_id']} count={parsed['nbp_count']}")
                print(f"  Proto: {parsed['ddp_proto']}")
    
    print(f"\nTotal jrouter FwdReq packets: {len(jrouter_nbp)}")
    
    print("\n=== Comparison ===")
    if netatalk_nbp and jrouter_nbp:
        n = netatalk_nbp[0]
        j = jrouter_nbp[0]
        
        print(f"Source network: netatalk={n['ddp_src_net']} jrouter={j['ddp_src_net']}")
        print(f"Source node: netatalk={n['ddp_src_node']} jrouter={j['ddp_src_node']}")
        print(f"Source socket: netatalk={n['ddp_src_sock']} jrouter={j['ddp_src_sock']}")
        print(f"Dest network: netatalk={n['ddp_dst_net']} jrouter={j['ddp_dst_net']}")
        print(f"Dest node: netatalk={n['ddp_dst_node']} jrouter={j['ddp_dst_node']}")
        print(f"Dest socket: netatalk={n['ddp_dst_sock']} jrouter={j['ddp_dst_sock']}")
        print(f"DDP proto: netatalk={n['ddp_proto']} jrouter={j['ddp_proto']}")
        
        if n['ddp_src_net'] != j['ddp_src_net']:
            print(f"\n⚠️  SOURCE NETWORK MISMATCH!")
        if n['ddp_src_node'] != j['ddp_src_node']:
            print(f"\n⚠️  SOURCE NODE MISMATCH!")
        if n['ddp_src_sock'] != j['ddp_src_sock']:
            print(f"\n⚠️  SOURCE SOCKET MISMATCH!")

if __name__ == '__main__':
    main()
