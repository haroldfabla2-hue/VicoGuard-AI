"""Unified orchestrator run: consent -> DAST -> SAST -> attack -> report -> notify.

This is the single entry point that ties together every already-built piece
of Centinela/WASP into one end-to-end run against a target ``url`` (scanned
via VicoGuard-AI's DAST) and a local ``repo`` (scanned via the static guard).
Every step writes to the same tamper-evident hash-chain ledger, so the whole
run is auditable afterwards regardless of which individual steps failed.

Design principle: **no single failing step should ever take down the rest of
the run.** DAST unreachable, SAST erroring on a bad path, the attack
simulator rejecting a misconfigured target, the LLM interpreter failing, the
report builder not being ready yet, Telegram not being configured -- none of
these should raise out of ``run_unified``. Each stage is wrapped in its own
try/except and any failure is recorded in the returned ``errors`` list
instead.

SAFETY (non-negotiable): the simulated attack (``simulator.run_attack``)
is ALWAYS invoked with ``attack_target_url`` -- the caller-controlled,
localhost-only demo target -- and never with ``url``, the arbitrary
(possibly remote) third-party target the operator is scanning. Mixing the
two up would turn a local attack demo into an unauthorized attack against a
real target. ``simulator.py`` also enforces this at its own layer (it
rejects non-localhost hosts before sending any request), but this module
does not rely on that as its only safeguard.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import httpx

from centinela.adapters import vicoguard_adapter
from centinela.attack import simulator
from centinela.guards import static_guard
from centinela.interpreter import interpret
from centinela.ledger import hash_chain
from centinela.orchestrator import consent as consent_service
from centinela.orchestrator import notify as notify_service
from centinela.orchestrator import report

DEFAULT_LEDGER_PATH = "centinela/data/ledger.jsonl"
DEFAULT_REPORTS_DIR = "centinela/data/reports"
DEFAULT_VICOGUARD_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_ATTACK_TARGET_URL = "http://127.0.0.1:8899"

_PREFLIGHT_TIMEOUT_SECONDS = 2.0


def _is_reachable(check_url: str) -> bool:
    """Return True if a GET to ``check_url`` completes at the transport level.

    Any HTTP status code (including 404/500) counts as "alive" -- only a
    connection-level failure (refused, timed out, DNS error, ...) counts as
    "down". Never raises.
    """
    try:
        httpx.get(check_url, timeout=_PREFLIGHT_TIMEOUT_SECONDS)
        return True
    except Exception:
        return False


def run_unified(
    url: str,
    repo: str,
    vicoguard_base_url: str = DEFAULT_VICOGUARD_BASE_URL,
    attack_target_url: str = DEFAULT_ATTACK_TARGET_URL,
    ledger_path: str = DEFAULT_LEDGER_PATH,
    run_attack: bool = True,
    notify: bool = True,
    concern: str | None = None,
    confirmed: bool = False,
    interactive: bool = True,
    reports_dir: str = DEFAULT_REPORTS_DIR,
) -> dict:
    """Run a full Centinela/WASP analysis and return a structured summary.

    Order: preflight checks, consent, DAST (VicoGuard-AI, gated on
    consent), SAST (static guard), simulated attack (localhost-only,
    gated on ``run_attack``), LLM interpretation of the ledger, report
    generation, and (optionally) a Telegram notification. Every stage is
    isolated so that a failure in one never prevents the others from
    running.

    ``run_attack`` always targets ``attack_target_url`` (a localhost-only
    demo target), never ``url`` -- see the module docstring.
    """
    run_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []

    # 1. Preflight -- informational only, never aborts the run.
    vicoguard_up = _is_reachable(f"{vicoguard_base_url}/api/v1/health")
    attack_target_up = _is_reachable(attack_target_url) if run_attack else None

    # 2. Ledger start index, captured before this run writes anything.
    ledger_start_index = len(hash_chain.read_entries(ledger_path))

    # 3. Consent.
    try:
        consent_result = consent_service.ask_consent(
            url,
            concern=concern,
            confirmed=confirmed,
            interactive=interactive,
            ledger_path=ledger_path,
        )
    except Exception as exc:  # noqa: BLE001 -- consent must never abort the run
        errors.append(f"Consentimiento falló, se trata como no otorgado: {exc}")
        consent_result = {
            "url": url,
            "concern": concern,
            "confirmed": False,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    # 4. DAST -- only if consent was confirmed.
    dast = None
    if consent_result.get("confirmed"):
        try:
            vg_result = vicoguard_adapter.run_dast_scan(url, base_url=vicoguard_base_url)
            dast_findings = vicoguard_adapter.ingest_dast_findings(
                vg_result.get("findings", []), url, ledger_path=ledger_path
            )
            dast = {"findings": dast_findings, "count": len(dast_findings)}
        except vicoguard_adapter.VicoGuardUnavailableError as exc:
            hint = " (preflight ya había detectado VicoGuard caído)" if not vicoguard_up else ""
            errors.append(f"DAST falló: {exc}{hint}")
        except Exception as exc:  # noqa: BLE001 -- DAST must never abort the run
            errors.append(f"DAST falló con un error inesperado: {exc}")
    else:
        errors.append("DAST omitido: consentimiento no otorgado")

    # 5. SAST.
    sast = None
    try:
        sast_findings = static_guard.scan(repo)
        sast = {"findings": sast_findings, "count": len(sast_findings)}
    except Exception as exc:  # noqa: BLE001 -- SAST must never abort the run
        errors.append(f"SAST falló: {exc}")

    # 6. Simulated attack -- CRITICAL: always attack_target_url, never url.
    attack = None
    if run_attack:
        try:
            attack_steps = simulator.run_attack(target_url=attack_target_url, ledger_path=ledger_path)
            attack = {"steps": attack_steps, "count": len(attack_steps)}
        except Exception as exc:  # noqa: BLE001 -- attack sim must never abort the run
            hint = " (preflight ya había detectado el target caído)" if attack_target_up is False else ""
            errors.append(f"Ataque simulado falló: {exc}{hint}")

    # 7. Interpretation.
    try:
        summary_text = interpret.summarize(ledger_path)
    except Exception:  # noqa: BLE001 -- interpret.py already has its own fallback
        summary_text = (
            "No se pudo generar el resumen automático de esta corrida. "
            "Consultá el ledger directamente para el detalle completo."
        )

    # 8. Ledger end index.
    ledger_end_index = len(hash_chain.read_entries(ledger_path))
    finished_at = datetime.now(timezone.utc).isoformat()

    # 9. Report.
    run_summary = {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "url": url,
        "repo": repo,
        "consent": consent_result,
        "dast": dast,
        "sast": sast,
        "attack": attack,
        "summary_text": summary_text,
        "ledger_start_index": ledger_start_index,
        "ledger_end_index": ledger_end_index,
        "errors": errors,
    }
    report_path = None
    try:
        report_path = report.build_report(run_summary, ledger_path=ledger_path, reports_dir=reports_dir)
    except Exception as exc:  # noqa: BLE001 -- report generation must never abort the run
        errors.append(f"No se pudo generar el reporte: {exc}")

    # 10. Notification.
    notified = False
    if notify:
        try:
            notified = notify_service.send_message(summary_text)
        except Exception as exc:  # noqa: BLE001 -- notify.send_message already never raises
            errors.append(f"No se pudo enviar la notificación: {exc}")

    return {
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "consent": consent_result,
        "dast": dast,
        "sast": sast,
        "attack": attack,
        "ledger_start_index": ledger_start_index,
        "ledger_end_index": ledger_end_index,
        "report_path": report_path,
        "notified": notified,
        "errors": errors,
    }
