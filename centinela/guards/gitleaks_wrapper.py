"""Thin wrapper around the Gitleaks CLI.

Invokes the ``bin/gitleaks.exe`` binary via ``subprocess`` and normalizes its
JSON output to the shared finding schema used across WASP's guards. Every
secret gitleaks finds is normalized to severity "critical" — a leaked
credential is always a critical issue regardless of what gitleaks itself
reports.
"""

import json
import subprocess
import tempfile
from pathlib import Path

from centinela.guards import noise_guard


def _resolve_gitleaks_path() -> Path:
    """Resolve bin/gitleaks.exe relative to the project root, regardless of cwd."""
    project_root = Path(__file__).resolve().parents[2]
    return project_root / "bin" / "gitleaks.exe"


def run_gitleaks(target_path: str) -> list:
    """Run gitleaks against ``target_path`` and return normalized findings.

    Gitleaks exits with code 1 when it finds leaks (not an error condition)
    and exit code 0 when it finds none — both are treated as a normal run.
    Returns an empty list if the report can't be parsed.
    """
    gitleaks_exe = _resolve_gitleaks_path()

    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = str(Path(tmp_dir) / "gitleaks_report.json")

        subprocess.run(
            [
                str(gitleaks_exe),
                "detect",
                "--source",
                target_path,
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-git",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                raw_output = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    if not raw_output:
        return []

    findings = []
    for leak in raw_output:
        rule_id = leak.get("RuleID", "")
        file_path = leak.get("File", "")
        line = leak.get("StartLine", 0)
        message = leak.get("Description", "")

        findings.append(
            {
                "id": noise_guard.make_finding_id("gitleaks", rule_id, file_path, line),
                "source": "gitleaks",
                "severity": "critical",
                "rule_id": rule_id,
                "file": file_path,
                "line": line,
                "message": message,
                "raw": leak,
            }
        )

    return findings
