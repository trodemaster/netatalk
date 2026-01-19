#!/usr/bin/env python3
import argparse
import subprocess
import sys
from collections import defaultdict

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as exc:
        return exc.output

def get_zones(getzones_path):
    output = run_cmd([getzones_path])
    zones = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        zones.append(line)
    return zones

def build_nbplkup_cmd(args, zone):
    cmd = [args.nbplkup, "-s", "-r", str(args.max_responses)]
    if args.op == "fwd":
        cmd.append("-f")
    elif args.op == "lkup":
        cmd.append("-l")
    if args.source:
        cmd.extend(["-A", args.source])
    if args.dest:
        cmd.extend(["-D", args.dest])
    query = f"{args.obj}:{args.type}@{zone}"
    cmd.append(query)
    return cmd

def main():
    parser = argparse.ArgumentParser(description="Scan AppleTalk zones via nbplkup")
    parser.add_argument("--obj", default="=", help="NBP object (default '=')")
    parser.add_argument("--type", default="=", help="NBP type (default '=')")
    parser.add_argument("--zone", action="append", help="Zone name (can repeat)")
    parser.add_argument("--zones-from-getzones", action="store_true", default=True,
                        help="Pull zones from getzones when --zone not provided (default true)")
    parser.add_argument("--no-zones-from-getzones", dest="zones_from_getzones", action="store_false",
                        help="Disable getzones fallback")
    parser.add_argument("--op", choices=["brrq", "fwd", "lkup"], default="brrq",
                        help="NBP op: brrq (broadcast), fwd (forward), lkup (directed)")
    parser.add_argument("--max-responses", type=int, default=1000, help="Max responses per zone")
    parser.add_argument("--source", help="AppleTalk source address for -A (net.node")
    parser.add_argument("--dest", help="AppleTalk destination address for -D (net.node")
    parser.add_argument("--getzones", default="/usr/local/bin/getzones", help="Path to getzones")
    parser.add_argument("--nbplkup", default="/usr/local/bin/nbplkup", help="Path to nbplkup")
    args = parser.parse_args()

    zones = []
    if args.zone:
        zones = args.zone
    elif args.zones_from_getzones:
        zones = get_zones(args.getzones)

    if not zones:
        zones = ["*"]

    results = defaultdict(list)
    for zone in zones:
        cmd = build_nbplkup_cmd(args, zone)
        output = run_cmd(cmd)
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
        results[zone].extend(lines)

    for zone in zones:
        print(f"\n=== Zone: {zone} ===")
        for line in results[zone]:
            print(line)

    total = sum(len(v) for v in results.values())
    print(f"\nTotal results: {total}")

if __name__ == "__main__":
    sys.exit(main())
