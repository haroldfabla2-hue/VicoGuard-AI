"""WASP / Centinela CLI entrypoint.

Usage:
    python -m centinela.main scan <path>
"""

import argparse
import sys

from dotenv import load_dotenv

from centinela.guards import static_guard
from centinela.interpreter import interpret
from centinela.ledger import hash_chain
from centinela.orchestrator import unify

load_dotenv()  # loads .env from the project root into os.environ, if present

# Windows' console defaults to cp1252, which can't encode the emoji/accented
# characters the interpreter and attack messages use (e.g. the WASP bee, the
# severity dots). Force UTF-8 on stdout/stderr so `python -m centinela.main`
# never crashes on print() during a live demo -- this bit us for real while
# testing the "status" command against actual LLM output.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")

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


def _cmd_status(args: argparse.Namespace) -> int:
    """Prints interpret.summarize() -- LLM mode if ANTHROPIC_API_KEY is set
    (via .env or the real environment), heuristic fallback otherwise. Exists
    so the interpreter can be checked end-to-end without needing Telegram.
    """
    print(interpret.summarize())
    return 0


def _cmd_unify(args: argparse.Namespace) -> int:
    """Run the full unified WASP + VicoGuard-AI analysis end-to-end."""
    result = unify.run_unified(
        url=args.url,
        repo=args.repo,
        vicoguard_base_url=args.vicoguard_url,
        attack_target_url=args.attack_target,
        run_attack=not args.no_attack,
        notify=not args.no_notify,
        concern=args.concern,
        confirmed=args.confirm,
        interactive=not args.no_interactive,
    )

    print(f"Run ID: {result['run_id']}")
    print(f"Inicio: {result['started_at']}  Fin: {result['finished_at']}")
    print(f"Consentimiento otorgado: {result['consent'].get('confirmed')}")

    dast = result["dast"]
    print(f"Hallazgos DAST: {dast['count'] if dast else 0}")

    sast = result["sast"]
    print(f"Hallazgos SAST: {sast['count'] if sast else 0}")

    attack = result["attack"]
    if attack is not None:
        print(f"Ataque simulado: {attack['count']} pasos ejecutados")
    else:
        print("Ataque simulado: no ejecutado")

    print(f"Notificación enviada: {result['notified']}")
    print(f"Reporte: {result['report_path']}")

    if result["errors"]:
        print(f"Errores ({len(result['errors'])}):")
        for error in result["errors"]:
            print(f"  - {error}")
    else:
        print("Errores: ninguno")

    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m centinela.main")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run the static guard scan on a path")
    scan_parser.add_argument("path", help="File or directory to scan")
    scan_parser.set_defaults(func=_cmd_scan)

    status_parser = subparsers.add_parser("status", help="Print the interpreter's ledger summary")
    status_parser.set_defaults(func=_cmd_status)

    unify_parser = subparsers.add_parser(
        "unify", help="Run the full unified WASP + VicoGuard-AI analysis (DAST + SAST + attack sim)"
    )
    unify_parser.add_argument("--url", required=True, help="Target URL to analyze (DAST + consent)")
    unify_parser.add_argument("--repo", required=True, help="Local repo/path to run the static guard (SAST) on")
    unify_parser.add_argument(
        "--attack-target",
        default=unify.DEFAULT_ATTACK_TARGET_URL,
        help=f"Localhost-only target for the attack simulation (default: {unify.DEFAULT_ATTACK_TARGET_URL})",
    )
    unify_parser.add_argument(
        "--vicoguard-url",
        default=unify.DEFAULT_VICOGUARD_BASE_URL,
        help=f"VicoGuard-AI base URL (default: {unify.DEFAULT_VICOGUARD_BASE_URL})",
    )
    unify_parser.add_argument("--no-attack", action="store_true", help="Skip the simulated attack step")
    unify_parser.add_argument("--no-notify", action="store_true", help="Skip the Telegram notification")
    unify_parser.add_argument("--concern", default=None, help="Concern to record with the consent (non-interactive mode)")
    unify_parser.add_argument("--confirm", action="store_true", help="Confirm consent non-interactively")
    unify_parser.add_argument(
        "--no-interactive", action="store_true", help="Do not prompt on the console; use --confirm/--concern as-is"
    )
    unify_parser.set_defaults(func=_cmd_unify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
