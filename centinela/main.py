"""WASP / Centinela CLI entrypoint.

Usage:
    python -m centinela.main scan <path>
"""

import argparse
import sys

from centinela.guards import static_guard
from centinela.ledger import hash_chain

_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _cmd_scan(args: argparse.Namespace) -> int:
    findings = static_guard.scan(args.path)

    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        severity = finding.get("severity", "low")
        counts[severity] = counts.get(severity, 0) + 1

    print(f"Scan complete for: {args.path}")
    print(f"Total findings: {len(findings)}")
    for severity in _SEVERITY_ORDER:
        print(f"  {severity}: {counts[severity]}")

    entries = hash_chain.read_entries()
    print(f"Ledger entries written this run: {len(findings)}")
    print(f"Ledger total entries: {len(entries)}")
    print(f"Ledger chain valid: {hash_chain.verify_chain()}")

    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m centinela.main")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run the static guard scan on a path")
    scan_parser.add_argument("path", help="File or directory to scan")
    scan_parser.set_defaults(func=_cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
