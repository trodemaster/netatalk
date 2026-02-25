#!/usr/bin/env python3
"""
aurp_nbp_flow.py - AURP/NBP flow analyzer for Netatalk debugging

Parses atalkd and netatalk journal logs and reconstructs inbound NBP lookup
events from remote AURP peers, showing each step of the flow:

  1. FwdReq arrives from remote peer
  2. Tuple reply-to rewritten to our local router
  3. LkUp broadcast on local network
  4. LkUpReply received from afpd
  5. Reply forwarded back through AURP tunnel

Also reports: SEGV crashes, service restarts, NBP registration gaps,
and connected/disconnected peer counts.

Usage:
  python3 tools/aurp_nbp_flow.py              # last 2 hours
  python3 tools/aurp_nbp_flow.py -H 6         # last 6 hours
  python3 tools/aurp_nbp_flow.py --since "1 hour ago"
  python3 tools/aurp_nbp_flow.py --tail       # follow live (like tail -f)
  python3 tools/aurp_nbp_flow.py --summary    # summary only, no per-event detail
"""

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


# ── log line regex ────────────────────────────────────────────────────────────

# systemd journal line:  Mon DD HH:MM:SS host unit[pid]: message
LOG_RE = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\w+)\[\d+\]:\s+(.*)'
)

PATTERNS = {
    # Inbound FwdReq from AURP peer
    'fwdreq_entry':   re.compile(r'aurp_handle_data:.*NBP op=4.*id=(\d+).*tuple=(\S+)'),
    'fwdreq_names':   re.compile(r'aurp_handle_data:.*NBP names obj=\'([^\']+)\' type=\'([^\']+)\' zone=\'([^\']+)\''),
    'fwdreq_peer':    re.compile(r'aurp_handle_data: ENTRY - peer=(\S+)'),
    'tuple_rewrite':  re.compile(r'rewrote tuple reply-to (\S+) -> (\S+) \(id=(\d+)\)'),
    'lkup_broadcast': re.compile(r'broadcast FwdReq as LkUp iface=\S+ port=\d+ -> (\S+)'),
    'nbp_lkup':       re.compile(r"nbp lkup: '(.+)' from (\S+)"),

    # LkUpReply / forwarding
    'reply_recv':     re.compile(r'nbp_packet:.*NBP reply received.*id=(\d+).*count=(\d+)'),
    'reply_inbound':  re.compile(r'nbp_packet: inbound reply id=(\d+) -> AURP tunnel to (\S+)'),
    'reply_forwarded':re.compile(r'forwarded LkUpReply via AURP to (\S+)'),
    'reply_local':    re.compile(r'forwarding reply id=(\d+) to local requester (\S+)'),
    'reply_dropped':  re.compile(r'no tracked request found for NBP ID (\d+)'),

    # BrRq (local Mac scanning for a remote zone — outbound)
    'brrq':           re.compile(r"nbp brrq: received BrRq for zone '([^']+)' from (\S+)"),
    'brrq_aurp_fwd':  re.compile(r"nbp brrq: AURP fwd zone '([^']+)' to net (\d+)"),

    # AURP connection events
    'peer_connected':   re.compile(r'bidirectional connection with (\S+) fully established'),
    'peer_disconnected':re.compile(r'aurp_peer_disconnect.*peer=(\S+)'),
    'route_added':      re.compile(r'aurp_rtmp_add_route: added AURP route (\S+) hops \d+ from (\S+)'),
    'route_deleted':    re.compile(r'aurp_rtmp_delete_routes: deleted (\d+) routes from (\S+)'),

    # Health events
    'atalkd_segv':    re.compile(r'Main process exited.*SEGV|code=dumped.*status=11'),
    'atalkd_restart': re.compile(r'restart \('),
    'nbp_rgstr':      re.compile(r'nbp_packet.*received.*from.*650.*'),  # registration activity
    'afp_started':    re.compile(r'throwback:AFPServer@(\S+) started on (\S+)'),
    'netatalk_start': re.compile(r'netatalk\[.*\]: Registered with Zeroconf'),
}


# ── data structures ───────────────────────────────────────────────────────────

@dataclass
class InboundLookup:
    """Tracks a single inbound NBP FwdReq through the full round-trip."""
    nbp_id: int
    peer_ip: str
    orig_tuple: str
    obj: str = ''
    type_: str = ''
    zone: str = ''
    rewritten_to: str = ''
    lkup_broadcast: bool = False
    reply_received: bool = False
    reply_forwarded: bool = False
    reply_dropped: bool = False
    ts: str = ''
    retries: int = 0

    def outcome(self):
        if self.reply_forwarded:
            return '✓ FORWARDED'
        if self.reply_dropped:
            return '✗ DROPPED (no tracked request)'
        if self.reply_received:
            return '~ REPLY RECV, no forward logged'
        if self.lkup_broadcast:
            return '? LKUP BROADCAST, no reply'
        if self.rewritten_to:
            return '? REWRITTEN, no broadcast logged'
        return '? INCOMPLETE'

    def is_afpserver(self):
        return 'AFPServer' in self.type_


@dataclass
class Stats:
    inbound_lookups: int = 0
    afpserver_lookups: int = 0
    replies_forwarded: int = 0
    replies_dropped: int = 0
    outbound_brrqs: int = 0
    peers_connected: int = 0
    peers_disconnected: int = 0
    routes_added: int = 0
    routes_deleted: int = 0
    segv_crashes: int = 0
    atalkd_restarts: int = 0
    netatalk_restarts: int = 0
    afp_re_registrations: int = 0


# ── log fetching ──────────────────────────────────────────────────────────────

def fetch_logs(since: str, units: list[str]) -> list[str]:
    lines = []
    for unit in units:
        cmd = ['journalctl', '-u', unit, '--since', since, '--no-pager', '-o', 'short']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            lines.extend(result.stdout.splitlines())
        except Exception as e:
            print(f"Warning: could not fetch logs for {unit}: {e}", file=sys.stderr)
    # Sort by timestamp (journal lines start with date)
    lines.sort()
    return lines


# ── parsing ───────────────────────────────────────────────────────────────────

def parse_logs(lines: list[str], verbose: bool) -> tuple[list, list, Stats]:
    """
    Returns (inbound_lookups, health_events, stats).
    inbound_lookups: list of InboundLookup
    health_events: list of (ts, description) strings
    """
    stats = Stats()
    health_events = []

    # Active inbound lookups keyed by nbp_id
    active: dict[int, InboundLookup] = {}
    completed: list[InboundLookup] = []

    # Track the most-recently-seen peer IP per aurp_handle_data block
    current_peer: Optional[str] = None

    for raw in lines:
        m = LOG_RE.match(raw)
        if not m:
            continue
        ts, unit, msg = m.group(1), m.group(2), m.group(3)

        # ── SEGV / restarts ──────────────────────────────────────────────────
        if PATTERNS['atalkd_segv'].search(msg):
            stats.segv_crashes += 1
            health_events.append((ts, 'CRASH: atalkd SEGV / core-dump'))
            continue

        if PATTERNS['atalkd_restart'].search(msg) and unit == 'atalkd':
            stats.atalkd_restarts += 1
            health_events.append((ts, 'RESTART: atalkd restarted'))
            # All active tracked lookups are now stale
            for lk in active.values():
                lk.reply_dropped = True
                completed.append(lk)
            active.clear()
            continue

        if PATTERNS['netatalk_start'].search(msg):
            stats.netatalk_restarts += 1
            health_events.append((ts, 'RESTART: netatalk (re)started / Zeroconf registered'))
            continue

        if PATTERNS['afp_started'].search(msg):
            stats.afp_re_registrations += 1
            m2 = PATTERNS['afp_started'].search(msg)
            health_events.append((ts, f'NBP: AFPServer registered at {m2.group(2)} zone={m2.group(1)}'))
            continue

        # ── AURP peer events ─────────────────────────────────────────────────
        if m2 := PATTERNS['peer_connected'].search(msg):
            stats.peers_connected += 1
            if verbose:
                health_events.append((ts, f'AURP: connected to {m2.group(1)}'))
            continue

        if m2 := PATTERNS['peer_disconnected'].search(msg):
            stats.peers_disconnected += 1
            if verbose:
                health_events.append((ts, f'AURP: disconnected from {m2.group(1)}'))
            continue

        if m2 := PATTERNS['route_added'].search(msg):
            stats.routes_added += 1
            continue

        if m2 := PATTERNS['route_deleted'].search(msg):
            stats.routes_deleted += int(m2.group(1))
            continue

        # ── Track current peer IP from ENTRY lines ───────────────────────────
        if m2 := PATTERNS['fwdreq_peer'].search(msg):
            current_peer = m2.group(1)

        # ── Inbound FwdReq (step 1) ──────────────────────────────────────────
        if m2 := PATTERNS['fwdreq_entry'].search(msg):
            nbp_id = int(m2.group(1))
            orig_tuple = m2.group(2)
            if nbp_id in active:
                active[nbp_id].retries += 1
            else:
                lk = InboundLookup(
                    nbp_id=nbp_id,
                    peer_ip=current_peer or '?',
                    orig_tuple=orig_tuple,
                    ts=ts,
                )
                active[nbp_id] = lk
                stats.inbound_lookups += 1
            continue

        # ── Object/type/zone names ───────────────────────────────────────────
        if m2 := PATTERNS['fwdreq_names'].search(msg):
            obj, type_, zone = m2.group(1), m2.group(2), m2.group(3)
            # Associate with the most recent active lookup from this peer
            for lk in reversed(list(active.values())):
                if lk.peer_ip == current_peer and not lk.obj:
                    lk.obj = obj
                    lk.type_ = type_
                    lk.zone = zone
                    if 'AFPServer' in type_:
                        stats.afpserver_lookups += 1
                    break
            continue

        # ── Tuple rewrite (step 2) ───────────────────────────────────────────
        if m2 := PATTERNS['tuple_rewrite'].search(msg):
            nbp_id = int(m2.group(3))
            if nbp_id in active:
                active[nbp_id].rewritten_to = m2.group(2)
            continue

        # ── LkUp broadcast (step 3) ──────────────────────────────────────────
        if m2 := PATTERNS['lkup_broadcast'].search(msg):
            # Mark the most-recently-added inbound lookup that has a rewrite
            for lk in reversed(list(active.values())):
                if lk.peer_ip == current_peer and lk.rewritten_to and not lk.lkup_broadcast:
                    lk.lkup_broadcast = True
                    break
            continue

        # ── LkUpReply received (step 4) ──────────────────────────────────────
        if m2 := PATTERNS['reply_inbound'].search(msg):
            nbp_id = int(m2.group(1))
            if nbp_id in active:
                active[nbp_id].reply_received = True
            continue

        # ── Reply forwarded via AURP (step 5) ────────────────────────────────
        if m2 := PATTERNS['reply_forwarded'].search(msg):
            # Find the matching lookup — associate by most recently reply_received
            for lk in reversed(list(active.values())):
                if lk.reply_received and not lk.reply_forwarded:
                    lk.reply_forwarded = True
                    stats.replies_forwarded += 1
                    completed.append(lk)
                    del active[lk.nbp_id]
                    break
            continue

        # ── Reply dropped (no tracked request) ───────────────────────────────
        if m2 := PATTERNS['reply_dropped'].search(msg):
            nbp_id = int(m2.group(1))
            stats.replies_dropped += 1
            if nbp_id in active:
                active[nbp_id].reply_dropped = True
                completed.append(active.pop(nbp_id))
            continue

        # ── Outbound BrRq (local Mac looking for remote zone) ────────────────
        if m2 := PATTERNS['brrq'].search(msg):
            stats.outbound_brrqs += 1
            continue

    # Any lookups still active at end-of-log are incomplete
    for lk in active.values():
        completed.append(lk)

    return completed, health_events, stats


# ── display ───────────────────────────────────────────────────────────────────

RESET  = '\033[0m'
BOLD   = '\033[1m'
GREEN  = '\033[32m'
YELLOW = '\033[33m'
RED    = '\033[31m'
CYAN   = '\033[36m'
DIM    = '\033[2m'


def color_outcome(outcome: str) -> str:
    if '✓' in outcome:
        return GREEN + outcome + RESET
    if '✗' in outcome or 'DROP' in outcome:
        return RED + outcome + RESET
    return YELLOW + outcome + RESET


def print_summary(stats: Stats, window: str):
    print(f"\n{BOLD}{'═'*60}{RESET}")
    print(f"{BOLD}  AURP/NBP Flow Summary  —  {window}{RESET}")
    print(f"{'═'*60}")

    print(f"\n  {BOLD}Inbound NBP lookups from remote peers:{RESET}")
    print(f"    Total FwdReq received:     {stats.inbound_lookups:>5}")
    print(f"    For AFPServer:             {stats.afpserver_lookups:>5}")
    print(f"    Replies forwarded via AURP:{stats.replies_forwarded:>5}  {GREEN if stats.replies_forwarded > 0 else RED}{'✓' if stats.replies_forwarded > 0 else '✗'}{RESET}")
    print(f"    Replies dropped:           {stats.replies_dropped:>5}  {RED if stats.replies_dropped > 0 else ''}{'' if stats.replies_dropped == 0 else '✗'}{RESET}")

    print(f"\n  {BOLD}Outbound (local Mac → remote zone):{RESET}")
    print(f"    BrRq forwarded to AURP:    {stats.outbound_brrqs:>5}")

    print(f"\n  {BOLD}AURP peers:{RESET}")
    print(f"    Connections established:   {stats.peers_connected:>5}")
    print(f"    Disconnections:            {stats.peers_disconnected:>5}")
    print(f"    Routes added:              {stats.routes_added:>5}")
    print(f"    Routes deleted:            {stats.routes_deleted:>5}")

    print(f"\n  {BOLD}Health:{RESET}")
    crash_color = RED if stats.segv_crashes > 0 else GREEN
    restart_color = RED if stats.atalkd_restarts > 0 else GREEN
    print(f"    SEGV crashes:              {crash_color}{stats.segv_crashes:>5}{RESET}")
    print(f"    atalkd restarts:           {restart_color}{stats.atalkd_restarts:>5}{RESET}")
    print(f"    netatalk restarts:         {stats.netatalk_restarts:>5}")
    print(f"    AFPServer re-registrations:{stats.afp_re_registrations:>5}")
    print(f"\n{'═'*60}\n")


def print_events(lookups: list, health_events: list, afpserver_only: bool, summary_only: bool):
    if summary_only:
        return

    # Interleave health events and lookup completions by timestamp
    items = []

    for ts, desc in health_events:
        items.append((ts, 'health', desc, None))

    for lk in lookups:
        if afpserver_only and not lk.is_afpserver():
            continue
        items.append((lk.ts, 'lookup', '', lk))

    items.sort(key=lambda x: x[0])

    if not items:
        print("  (no events in window)")
        return

    print(f"{BOLD}  Event log:{RESET}")
    print(f"  {'─'*56}")

    for ts, kind, desc, lk in items:
        if kind == 'health':
            icon = '⚡' if 'CRASH' in desc or 'RESTART' in desc else 'ℹ'
            color = RED if ('CRASH' in desc or 'SEGV' in desc) else CYAN
            print(f"  {DIM}{ts}{RESET}  {color}{icon} {desc}{RESET}")

        else:  # lookup
            outcome = lk.outcome()
            retry_note = f" (+{lk.retries} retries)" if lk.retries else ""
            name = f"{lk.obj}:{lk.type_}@{lk.zone}" if lk.obj else f"id={lk.nbp_id}"
            print(f"  {DIM}{ts}{RESET}  {BOLD}{name}{RESET}{retry_note}")
            print(f"    peer={lk.peer_ip}  orig_tuple={lk.orig_tuple}")
            if lk.rewritten_to:
                print(f"    → tuple rewritten to {lk.rewritten_to}")
            if lk.lkup_broadcast:
                print(f"    → LkUp broadcast on local net")
            if lk.reply_received:
                print(f"    → LkUpReply received from afpd")
            print(f"    {color_outcome(outcome)}")
            print()


def live_tail(since: str, afpserver_only: bool):
    """Stream journal lines in real time and print events as they complete."""
    print(f"{CYAN}Tailing atalkd/netatalk logs (Ctrl-C to stop)...{RESET}\n")
    cmd = ['journalctl', '-u', 'atalkd', '-u', 'netatalk',
           '--since', since, '--no-pager', '-f', '-o', 'short']
    pending: list[str] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        for raw in proc.stdout:
            raw = raw.rstrip()
            pending.append(raw)
            # Re-parse the growing buffer periodically
            lookups, health, stats = parse_logs(pending, verbose=False)
            # Print newly completed items
            for lk in lookups:
                if afpserver_only and not lk.is_afpserver():
                    continue
                outcome = lk.outcome()
                if lk.reply_forwarded or lk.reply_dropped:
                    name = f"{lk.obj}:{lk.type_}@{lk.zone}" if lk.obj else f"id={lk.nbp_id}"
                    print(f"{DIM}{lk.ts}{RESET}  {BOLD}{name}{RESET}  {color_outcome(outcome)}")
            for ts, desc in health:
                color = RED if ('CRASH' in desc or 'SEGV' in desc) else CYAN
                print(f"{DIM}{ts}{RESET}  {color}⚡ {desc}{RESET}")
            pending.clear()
    except KeyboardInterrupt:
        print("\nStopped.")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Analyze AURP/NBP inbound flow from atalkd journal logs.'
    )
    parser.add_argument('-H', '--hours', type=float, default=2.0,
                        help='Look back N hours (default: 2)')
    parser.add_argument('--since', default='',
                        help='Passed directly to journalctl --since (overrides --hours)')
    parser.add_argument('--tail', action='store_true',
                        help='Follow log in real time')
    parser.add_argument('--summary', action='store_true',
                        help='Print summary counts only (no per-event detail)')
    parser.add_argument('--verbose', action='store_true',
                        help='Include peer connect/disconnect events')
    parser.add_argument('--all', dest='all_types', action='store_true',
                        help='Show all inbound lookups, not just AFPServer')
    args = parser.parse_args()

    if args.since:
        window = args.since
    else:
        window = f"{args.hours} hours ago"

    afpserver_only = not args.all_types

    if args.tail:
        live_tail(window, afpserver_only)
        return

    lines = fetch_logs(window, ['atalkd', 'netatalk'])
    lookups, health_events, stats = parse_logs(lines, verbose=args.verbose)

    label = f"last {args.hours}h" if not args.since else args.since
    print_summary(stats, label)

    # Filter lookups for display
    display = [lk for lk in lookups if (not afpserver_only or lk.is_afpserver())]
    # Show most recent first
    display.sort(key=lambda x: x.ts, reverse=True)

    print_events(display, health_events, afpserver_only, args.summary)

    # Exit 1 if we have crashes or the AFPServer reply path looks broken
    if stats.segv_crashes > 0:
        sys.exit(1)
    if stats.afpserver_lookups > 0 and stats.replies_forwarded == 0:
        sys.exit(2)


if __name__ == '__main__':
    main()
