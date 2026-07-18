"""Adapter that bridges VicoGuard-AI's DAST scan results into WASP.

VicoGuard-AI exposes a repository scan endpoint (``POST /api/v1/scan/repository``)
that runs a dynamic application security test (DAST) against a target and
returns a list of findings with its own schema. This module calls that
endpoint, normalizes each finding into WASP's shared finding schema (the same
shape produced by ``centinela.guards.static_guard.scan``), and records every
finding in the tamper-evident ledger via ``hash_chain``.

DAST findings are intentionally NOT passed through ``noise_guard``: static
analysis (SAST) and dynamic analysis (DAST) are different detection
universes, so deduplicating one against the other would not make sense.
"""

import time

import httpx

from centinela.ledger import hash_chain

DEFAULT_VICOGUARD_BASE_URL = "http://127.0.0.1:8000"

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class VicoGuardUnavailableError(Exception):
    """Raised when VicoGuard-AI cannot be reached or returns an error."""


_POLL_INTERVAL_SECONDS = 3.0


def run_dast_scan(
    url: str,
    base_url: str = DEFAULT_VICOGUARD_BASE_URL,
    timeout: float = 120.0,
    use_agent_team: bool = False,
) -> dict:
    """Trigger a VicoGuard-AI DAST scan against ``url`` and return its result.

    Uses VicoGuard-AI's ASYNC endpoint, ``POST {base_url}/api/v1/scan/start``
    (not the synchronous ``/api/v1/scan/repository``), then polls
    ``GET {base_url}/api/v1/scan/{scan_id}`` until it finishes. This matters
    for a real, confirmed reason: ``/scan/repository`` runs the whole
    pipeline inline in the request-handling coroutine, which blocks
    VicoGuard-AI's single event loop -- if ``url`` points back at VicoGuard
    itself (e.g. its own ``/demo/vulnerable`` fixture, which is exactly what
    it's *for*), the scanner's own outgoing requests back to that same
    process can never get served, and every check times out (confirmed live:
    3 checks x 10s timeout, "0 findings" even though the target genuinely has
    10). ``/scan/start`` runs the pipeline on a separate thread pool
    (``_scan_executor``), so the event loop stays free and self-scans work.

    ``use_agent_team`` maps to VicoGuard-AI's ``ScanRequest.use_agent_team``
    -- routes analysis through the 3-agent team (SecOps Auditor/Threat
    Analyst/Remediation Architect) instead of a single LLM call. This is
    slow (~140s confirmed live, vs a few seconds for the single call) --
    default is False so callers opt into the slower, richer path explicitly.

    Returns the full ``result`` object (same shape either way -- includes
    ``result["findings"]``, ``result["security_score"]``, etc).

    Raises ``VicoGuardUnavailableError`` if VicoGuard-AI cannot be reached,
    responds with an error status, or the scan doesn't finish within
    ``timeout`` seconds.
    """
    payload = {"repo_url": url, "notify": False, "use_agent_team": use_agent_team}

    try:
        start_response = httpx.post(f"{base_url}/api/v1/scan/start", json=payload, timeout=10.0)
    except httpx.RequestError as exc:
        raise VicoGuardUnavailableError(
            f"VicoGuard no responde en {base_url} -- "
            f"¿está corriendo `uvicorn api.main:app --port 8000`?"
        ) from exc

    if start_response.status_code >= 400:
        raise VicoGuardUnavailableError(
            f"VicoGuard no responde en {base_url} -- "
            f"¿está corriendo `uvicorn api.main:app --port 8000`? "
            f"(status {start_response.status_code})"
        )

    scan_id = start_response.json()["scan_id"]
    poll_url = f"{base_url}/api/v1/scan/{scan_id}"

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL_SECONDS)
        try:
            poll_response = httpx.get(poll_url, timeout=10.0)
        except httpx.RequestError as exc:
            raise VicoGuardUnavailableError(
                f"VicoGuard dejó de responder en {base_url} mientras se esperaba el scan {scan_id}"
            ) from exc

        if poll_response.status_code >= 400:
            raise VicoGuardUnavailableError(
                f"VicoGuard devolvió un error consultando el scan {scan_id} (status {poll_response.status_code})"
            )

        job = poll_response.json()
        status = job.get("status")
        if status == "completed":
            return job["result"]
        if status in ("failed", "error"):
            raise VicoGuardUnavailableError(
                f"El scan {scan_id} de VicoGuard terminó con estado '{status}'"
            )
        # "queued" / "running": keep polling.

    raise VicoGuardUnavailableError(
        f"El scan {scan_id} de VicoGuard no terminó dentro de los {timeout}s de timeout"
    )


def adapt_finding(vg_finding: dict, target_url: str) -> dict:
    """Convert one VicoGuard finding into WASP's shared finding schema.

    Uses ``.get()`` with fallbacks throughout because a finding may come
    "raw" from the scanner (only ``id``/``severity``/``title_business``/
    ``category``) or "enriched" by the LLM with extra fields (``analogy``,
    ``impact``, ``remediation_steps``, ``status``, ...) -- a missing key must
    never break this conversion.
    """
    return {
        "id": f"vicoguard:{vg_finding.get('id', 'unknown')}",
        "source": "vicoguard-dast",
        "severity": _SEVERITY_MAP.get(str(vg_finding.get("severity", "")).upper(), "low"),
        "rule_id": vg_finding.get("category", "unknown"),
        "file": f"(dast) {target_url}",
        "line": 0,
        "message": vg_finding.get("title_business") or vg_finding.get("title_technical") or "sin descripción",
        "raw": vg_finding,
    }


def ingest_dast_findings(
    vg_findings: list,
    target_url: str,
    ledger_path: str = "centinela/data/ledger.jsonl",
) -> list:
    """Adapt VicoGuard findings to WASP schema and record them in the ledger.

    Same return contract as ``centinela.guards.static_guard.scan``: the list
    of adapted findings, so an orchestrator can treat both sources
    identically. Each adapted finding is appended to the ledger as a
    ``"finding"`` entry.
    """
    adapted_findings = [adapt_finding(vg_finding, target_url) for vg_finding in vg_findings]

    for finding in adapted_findings:
        hash_chain.append("finding", finding, ledger_path=ledger_path)

    return adapted_findings
