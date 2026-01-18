#!/usr/bin/env python3
import argparse
import os
import random
import socket
import struct
import sys
import time

AURP_PORT = 387
AURP_VERSION = 0x0001
AURP_PKT_ROUTING = 0x0003

AURP_CMD_RI_REQ = 0x0001
AURP_CMD_OPEN_REQ = 0x0008
AURP_CMD_TICKLE = 0x000e


def pack_domain_id(ip_str: str) -> bytes:
    ip = socket.inet_aton(ip_str)
    # len=7, authority=1 (IP), distinguisher=0
    return struct.pack("!BBH4s", 0x07, 0x01, 0x0000, ip)


def build_domain_header(src_ip: str, dst_ip: str, pkt_type: int) -> bytes:
    return (
        pack_domain_id(dst_ip)
        + pack_domain_id(src_ip)
        + struct.pack("!HHH", AURP_VERSION, 0x0000, pkt_type)
    )


def build_transport_header(conn_id: int, seq: int, cmd: int, flags: int) -> bytes:
    return struct.pack("!HHHH", conn_id, seq, cmd, flags)


def pick_local_ip(target_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


def build_packet(mode: str, src_ip: str, dst_ip: str) -> bytes:
    conn_id = random.randint(1, 0xFFFF)
    seq = random.randint(1, 0xFFFF)

    if mode == "tickle":
        cmd = AURP_CMD_TICKLE
        payload = b""
    elif mode == "ri-req":
        cmd = AURP_CMD_RI_REQ
        payload = b""
    elif mode == "open":
        cmd = AURP_CMD_OPEN_REQ
        # version (2 bytes) + option count (1 byte)
        payload = struct.pack("!HB", AURP_VERSION, 0x00)
    else:
        raise ValueError(f"unsupported mode: {mode}")

    header = build_domain_header(src_ip, dst_ip, AURP_PKT_ROUTING)
    transport = build_transport_header(conn_id, seq, cmd, 0x0000)
    return header + transport + payload


def parse_basic(pkt: bytes) -> str:
    if len(pkt) < 30:
        return "packet too short"
    pkt_type = struct.unpack_from("!H", pkt, 20)[0]
    cmd = struct.unpack_from("!H", pkt, 26)[0]
    return f"pkt_type=0x{pkt_type:04x} cmd=0x{cmd:04x} len={len(pkt)}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a minimal AURP packet and wait for a reply.")
    parser.add_argument("--target", required=True, help="Target public IP or hostname")
    parser.add_argument("--mode", choices=["tickle", "ri-req", "open"], default="tickle")
    parser.add_argument("--src-ip", help="Source IP for Domain ID (default: auto-detect)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Seconds to wait for reply")
    args = parser.parse_args()

    target_ip = socket.gethostbyname(args.target)
    src_ip = args.src_ip or pick_local_ip(target_ip)

    pkt = build_packet(args.mode, src_ip, target_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", AURP_PORT))
    except PermissionError:
        print("error: binding UDP/387 requires sudo/root", file=sys.stderr)
        return 2

    sock.settimeout(args.timeout)

    sock.sendto(pkt, (target_ip, AURP_PORT))
    print(f"sent {len(pkt)} bytes to {target_ip}:{AURP_PORT} (src DI {src_ip}) mode={args.mode}")

    try:
        data, addr = sock.recvfrom(4096)
        print(f"received {len(data)} bytes from {addr[0]}:{addr[1]}: {parse_basic(data)}")
        return 0
    except socket.timeout:
        print("no reply within timeout")
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
