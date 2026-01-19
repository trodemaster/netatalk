#!/usr/bin/env python3
import argparse
import struct
from collections import Counter
from ipaddress import ip_address

AURP_PORT = 387
AURP_PKT_APPLETALK = 0x0002
AURP_PKT_ROUTING = 0x0003
DDP_TYPE_NBP = 0x02
DDP_TYPE_ZIP = 0x04
DDP_TYPE_AEP = 0x03

NBP_OPS = {
    0x01: "BrRq",
    0x02: "LkUp",
    0x03: "LkUpReply",
    0x04: "FwdReq",
    0x05: "FwdReply",
}

AURP_CMDS = {
    0x0001: "RI-Req",
    0x0002: "RI-Rsp",
    0x0003: "RI-Ack",
    0x0004: "RI-Upd",
    0x0005: "RD",
    0x0006: "ZI-Req",
    0x0007: "ZI-Rsp",
    0x0008: "Open-Req",
    0x0009: "Open-Rsp",
    0x000e: "Tickle",
    0x000f: "Tickle-Ack",
}


def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("pcap too short")
        magic = struct.unpack("<I", gh[:4])[0]
        endian = "<" if magic == 0xA1B2C3D4 else ">"
        linktype = struct.unpack(endian + "I", gh[20:24])[0]

        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", ph)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            yield linktype, data


def parse_udp387_packets(path):
    packets = []
    src_counter = Counter()

    for linktype, data in read_pcap(path):
        if len(data) < 20:
            continue

        if linktype == 1:  # LINKTYPE_ETHERNET
            if len(data) < 14:
                continue
            ethertype = struct.unpack("!H", data[12:14])[0]
            l2_len = 14
            if ethertype in (0x8100, 0x88A8):
                if len(data) < 18:
                    continue
                l2_len += 4
        elif linktype == 113:  # LINUX_SLL
            l2_len = 16
        elif linktype == 276:  # LINUX_SLL2
            l2_len = 20
        elif linktype in (0, 101, 228):  # NULL/RAW/IPV4
            l2_len = 0
        else:
            continue

        if len(data) < l2_len + 20:
            continue
        ip = data[l2_len:]
        vihl = ip[0]
        if vihl >> 4 != 4:
            continue
        ihl = (vihl & 0x0F) * 4
        if len(ip) < ihl + 8:
            continue
        if ip[9] != 17:
            continue
        src = ip_address(ip[12:16]).compressed
        dst = ip_address(ip[16:20]).compressed
        sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
        if sport != AURP_PORT and dport != AURP_PORT:
            continue
        udp_payload = ip[ihl + 8:]
        packets.append((src, dst, udp_payload))
        src_counter[src] += 1

    return packets, src_counter


def infer_local_ip(src_counter, fallback):
    if src_counter:
        return src_counter.most_common(1)[0][0]
    return fallback


def summarize(path, local_ip=None, top_n=10, sample_inbound=False, sample_count=3):
    packets, src_counter = parse_udp387_packets(path)
    local_ip = infer_local_ip(src_counter, local_ip or "")

    in_0002 = out_0002 = in_0003 = out_0003 = 0
    in_peers = Counter()
    out_peers = Counter()
    inbound_samples = []
    outbound_samples = []
    in_ddp_types = Counter()
    out_ddp_types = Counter()
    in_nbp_ops = Counter()
    out_nbp_ops = Counter()
    in_nbp_ops_by_peer = {}
    out_nbp_ops_by_peer = {}
    in_cmds = Counter()
    out_cmds = Counter()
    in_cmds_by_peer = {}
    out_cmds_by_peer = {}

    for src, dst, payload in packets:
        if len(payload) < 22:
            continue
        pkt_type = struct.unpack("!H", payload[20:22])[0]
        direction = "out" if src == local_ip else "in"

        if direction == "out":
            out_peers[dst] += 1
            if pkt_type == AURP_PKT_APPLETALK:
                out_0002 += 1
                ddp = payload[22:]
                if len(ddp) >= 13:
                    ddp_type = ddp[12]
                    out_ddp_types[ddp_type] += 1
                    if ddp_type == DDP_TYPE_NBP and len(ddp) >= 15:
                        nbp_op = (ddp[13] >> 4) & 0x0F
                        out_nbp_ops[nbp_op] += 1
                        out_nbp_ops_by_peer.setdefault(dst, Counter())[nbp_op] += 1
                if sample_inbound and len(outbound_samples) < sample_count:
                    outbound_samples.append((src, dst, payload[:64]))
            elif pkt_type == AURP_PKT_ROUTING:
                out_0003 += 1
                if len(payload) >= 30:
                    cmd = struct.unpack("!H", payload[26:28])[0]
                    out_cmds[cmd] += 1
                    out_cmds_by_peer.setdefault(dst, Counter())[cmd] += 1
        else:
            in_peers[src] += 1
            if pkt_type == AURP_PKT_APPLETALK:
                in_0002 += 1
                ddp = payload[22:]
                if len(ddp) >= 13:
                    ddp_type = ddp[12]
                    in_ddp_types[ddp_type] += 1
                    if ddp_type == DDP_TYPE_NBP and len(ddp) >= 15:
                        nbp_op = (ddp[13] >> 4) & 0x0F
                        in_nbp_ops[nbp_op] += 1
                        in_nbp_ops_by_peer.setdefault(src, Counter())[nbp_op] += 1
                if sample_inbound and len(inbound_samples) < sample_count:
                    inbound_samples.append((src, dst, payload[:64]))
            elif pkt_type == AURP_PKT_ROUTING:
                in_0003 += 1
                if len(payload) >= 30:
                    cmd = struct.unpack("!H", payload[26:28])[0]
                    in_cmds[cmd] += 1
                    in_cmds_by_peer.setdefault(src, Counter())[cmd] += 1

    print(f"local_ip {local_ip}")
    print(f"in_type0002 {in_0002}")
    print(f"out_type0002 {out_0002}")
    print(f"in_type0003 {in_0003}")
    print(f"out_type0003 {out_0003}")

    print("\nTop inbound peers:")
    for ip, count in in_peers.most_common(top_n):
        print(f"  {ip} {count}")

    print("\nTop outbound peers:")
    for ip, count in out_peers.most_common(top_n):
        print(f"  {ip} {count}")

    if in_ddp_types:
        print("\nInbound DDP types (type0002):")
        for ddp_type, count in in_ddp_types.most_common():
            label = {DDP_TYPE_NBP: "NBP", DDP_TYPE_ZIP: "ZIP", DDP_TYPE_AEP: "AEP"}.get(ddp_type, "OTHER")
            print(f"  0x{ddp_type:02x} {label} {count}")

    if out_ddp_types:
        print("\nOutbound DDP types (type0002):")
        for ddp_type, count in out_ddp_types.most_common():
            label = {DDP_TYPE_NBP: "NBP", DDP_TYPE_ZIP: "ZIP", DDP_TYPE_AEP: "AEP"}.get(ddp_type, "OTHER")
            print(f"  0x{ddp_type:02x} {label} {count}")

    if in_nbp_ops:
        print("\nInbound NBP ops (type0002 + NBP):")
        for op, count in in_nbp_ops.most_common():
            print(f"  0x{op:01x} {NBP_OPS.get(op, 'Unknown')} {count}")

    if out_nbp_ops:
        print("\nOutbound NBP ops (type0002 + NBP):")
        for op, count in out_nbp_ops.most_common():
            print(f"  0x{op:01x} {NBP_OPS.get(op, 'Unknown')} {count}")

    if in_cmds:
        print("\nInbound AURP commands (type0003):")
        for cmd, count in in_cmds.most_common():
            print(f"  0x{cmd:04x} {AURP_CMDS.get(cmd, 'Unknown')} {count}")

    if out_cmds:
        print("\nOutbound AURP commands (type0003):")
        for cmd, count in out_cmds.most_common():
            print(f"  0x{cmd:04x} {AURP_CMDS.get(cmd, 'Unknown')} {count}")

    if in_nbp_ops_by_peer:
        print("\nInbound NBP ops by peer:")
        peers = sorted(in_nbp_ops_by_peer.items(), key=lambda kv: -sum(kv[1].values()))
        for peer, ops in peers[:top_n]:
            summary = ", ".join(f"{NBP_OPS.get(op, 'Unknown')}={count}" for op, count in ops.most_common())
            print(f"  {peer}: {summary}")

    if out_nbp_ops_by_peer:
        print("\nOutbound NBP ops by peer:")
        peers = sorted(out_nbp_ops_by_peer.items(), key=lambda kv: -sum(kv[1].values()))
        for peer, ops in peers[:top_n]:
            summary = ", ".join(f"{NBP_OPS.get(op, 'Unknown')}={count}" for op, count in ops.most_common())
            print(f"  {peer}: {summary}")

    if in_cmds_by_peer:
        print("\nInbound AURP commands by peer:")
        peers = sorted(in_cmds_by_peer.items(), key=lambda kv: -sum(kv[1].values()))
        for peer, cmds in peers[:top_n]:
            summary = ", ".join(f"{AURP_CMDS.get(cmd, 'Unknown')}={count}" for cmd, count in cmds.most_common())
            print(f"  {peer}: {summary}")

    if out_cmds_by_peer:
        print("\nOutbound AURP commands by peer:")
        peers = sorted(out_cmds_by_peer.items(), key=lambda kv: -sum(kv[1].values()))
        for peer, cmds in peers[:top_n]:
            summary = ", ".join(f"{AURP_CMDS.get(cmd, 'Unknown')}={count}" for cmd, count in cmds.most_common())
            print(f"  {peer}: {summary}")

    if inbound_samples:
        print("\nInbound type0002 samples (first 64 bytes):")
        for src, dst, payload in inbound_samples:
            hexbytes = " ".join(f"{b:02x}" for b in payload)
            print(f"  {src} -> {dst}: {hexbytes}")

            ddp = payload[22:]
            if len(ddp) >= 13:
                hop_len = (ddp[0] << 8) | ddp[1]
                hop = (hop_len >> 10) & 0x0F
                length = hop_len & 0x03FF
                checksum = (ddp[2] << 8) | ddp[3]
                dst_net = (ddp[4] << 8) | ddp[5]
                dst_node = ddp[6]
                dst_socket = ddp[7]
                src_net = (ddp[8] << 8) | ddp[9]
                src_node = ddp[10]
                src_socket = ddp[11]
                ddp_type = ddp[12]
                print(f"    DDP hop={hop} len={length} cksum=0x{checksum:04x}")
                print(f"    DDP dst={dst_net}.{dst_node}.{dst_socket} src={src_net}.{src_node}.{src_socket} type=0x{ddp_type:02x}")

    if outbound_samples:
        print("\nOutbound type0002 samples (first 64 bytes):")
        for src, dst, payload in outbound_samples:
            hexbytes = " ".join(f"{b:02x}" for b in payload)
            print(f"  {src} -> {dst}: {hexbytes}")

            ddp = payload[22:]
            if len(ddp) >= 13:
                hop_len = (ddp[0] << 8) | ddp[1]
                hop = (hop_len >> 10) & 0x0F
                length = hop_len & 0x03FF
                checksum = (ddp[2] << 8) | ddp[3]
                dst_net = (ddp[4] << 8) | ddp[5]
                dst_node = ddp[6]
                dst_socket = ddp[7]
                src_net = (ddp[8] << 8) | ddp[9]
                src_node = ddp[10]
                src_socket = ddp[11]
                ddp_type = ddp[12]
                print(f"    DDP hop={hop} len={length} cksum=0x{checksum:04x}")
                print(f"    DDP dst={dst_net}.{dst_node}.{dst_socket} src={src_net}.{src_node}.{src_socket} type=0x{ddp_type:02x}")


def main():
    parser = argparse.ArgumentParser(description="Analyze AURP UDP/387 packet captures.")
    parser.add_argument("pcap", help="Path to .pcap file")
    parser.add_argument("--local-ip", help="Override local IP detection")
    parser.add_argument("--top", type=int, default=10, help="Number of peers to list")
    parser.add_argument("--sample-inbound", action="store_true", help="Show sample inbound type0002 payloads")
    parser.add_argument("--sample-count", type=int, default=3, help="Number of inbound samples to show")
    args = parser.parse_args()

    summarize(
        args.pcap,
        local_ip=args.local_ip,
        top_n=args.top,
        sample_inbound=args.sample_inbound,
        sample_count=args.sample_count,
    )


if __name__ == "__main__":
    main()
