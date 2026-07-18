"""Thin wrapper around the Semgrep CLI.

Invokes the real ``semgrep`` binary via ``subprocess`` (no MCP server — the
static guard talks to CLI tools directly for speed/reliability, per the
project decision documented in the Phase 2A task brief) and normalizes its
JSON output to the shared finding schema used across WASP's guards.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from centinela.guards import noise_guard

# Semgrep only distinguishes two real severities (ERROR / WARNING) plus an
# informational tier (INFO) — it has no native "critical" level. We map
# ERROR to "high" rather than "critical" because gitleaks-found secrets are
# reserved for "critical" (a leaked credential is categorically worse than a
# static-analysis pattern match); this keeps the severity ordering meaningful
# for noise_guard.prioritize().
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

_SEMGREP_EXE = "semgrep.exe" if sys.platform == "win32" else "semgrep"


def _resolve_semgrep_path() -> str:
    """Resolve the semgrep executable, preferring the project's venv."""
    project_root = Path(__file__).resolve().parents[2]
    venv_semgrep = project_root / ".venv" / "Scripts" / _SEMGREP_EXE
    if venv_semgrep.exists():
        return str(venv_semgrep)
    # Fall back to whatever is on PATH.
    return "semgrep"


def run_semgrep(target_path: str) -> list:
    """Run semgrep against ``target_path`` and return normalized findings.

    Uses ``--config=auto`` and writes JSON output to a temp file (more
    reliable on Windows than parsing stdout, which can be polluted by
    progress/warning text). Returns an empty list if semgrep produces no
    results or the output can't be parsed.
    """
    semgrep_exe = _resolve_semgrep_path()

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = str(Path(tmp_dir) / "semgrep_output.json")

        subprocess.run(
            [
                semgrep_exe,
                "scan",
                "--config=auto",
                # This repo (and scan targets like tests/fixtures/...) has no
                # git commits yet, so semgrep's default "only scan files
                # tracked by git" behavior finds nothing — --no-git-ignore
                # disables that. Semgrep also ships a *default* semgrepignore
                # template that excludes conventional test/fixture paths
                # (e.g. "tests/", "fixtures/"), which would silently skip our
                # deliberately-vulnerable fixture repo; --x-ignore-semgrepignore-files
                # (an internal-but-working flag) disables that template too.
                "--no-git-ignore",
                "--x-ignore-semgrepignore-files",
                target_path,
                "--json",
                "--output",
                output_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw_output = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    findings = []
    for result in raw_output.get("results", []):
        rule_id = result.get("check_id", "")
        file_path = result.get("path", "")
        line = result.get("start", {}).get("line", 0)
        extra = result.get("extra", {})
        semgrep_severity = extra.get("severity", "INFO")
        severity = _SEVERITY_MAP.get(semgrep_severity, "low")
        message = extra.get("message", "")

        findings.append(
            {
                "id": noise_guard.make_finding_id("semgrep", rule_id, file_path, line),
                "source": "semgrep",
                "severity": severity,
                "rule_id": rule_id,
                "file": file_path,
                "line": line,
                "message": message,
                "raw": result,
            }
        )

    return findings
