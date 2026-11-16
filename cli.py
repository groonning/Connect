#!/usr/bin/env python3
"""WiFi security testing agent — CLI entrypoint. Authorised use only."""
from __future__ import annotations
import argparse
import sys
from wifi_agent.scope import Scope, ScopeError
from wifi_agent.tools import Airodump, Wifite, Aircrack, Tshark
from wifi_agent.agent import RuleBasedPlanner
from wifi_agent.report import write_report

CONFIG = "config/authorized_targets.yaml"


def _load_scope() -> Scope:
    try:
        return Scope.load(CONFIG)
    except ScopeError as e:
        print(f"[scope] {e}", file=sys.stderr)
        sys.exit(2)


def cmd_scan(args):
    scope = _load_scope()
    air = Airodump(scope, iface=args.iface, dry_run=args.dry_run)
    if not air.available() and not args.dry_run:
        print("airodump-ng not installed on this host.", file=sys.stderr)
        sys.exit(1)
    aps = air.scan(seconds=args.seconds)
    print(f"Saw {len(aps)} access points.")
    plan = RuleBasedPlanner(scope).assess(aps)
    for s in plan.steps:
        print(" -", s)
    paths = write_report(plan)
    print(f"Report: {paths['markdown']}")


def cmd_targets(args):
    scope = _load_scope()
    print("Authorised targets:")
    for t in scope.all():
        print(f"  {t.bssid}  {t.ssid}  ({t.note})")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(required=True)

    s = sub.add_parser("scan", help="recon nearby APs and assess")
    s.add_argument("--iface", required=True, help="monitor-mode interface, e.g. wlan0mon")
    s.add_argument("--seconds", type=int, default=20)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(func=cmd_scan)

    t = sub.add_parser("targets", help="list authorised targets")
    t.set_defaults(func=cmd_targets)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
