"""Tests for centinela.orchestrator.report.build_report."""

import os

import pytest

from centinela.interpreter import interpret
from centinela.ledger import hash_chain
from centinela.orchestrator import report


def _seed_ledger(ledger_path):
    """Build a realistic ledger: two findings, one attack entry, one
    consent entry -- mirrors what a real unified run would append.
    """
    hash_chain.append(
        "finding",
        {
            "id": "aaa111",
            "source": "semgrep",
            "severity": "medium",
            "rule_id": "some-medium-rule",
            "file": "app.py",
            "line": 5,
            "message": "Medium severity issue",
            "raw": {},
        },
        ledger_path=ledger_path,
    )
    hash_chain.append(
        "finding",
        {
            "id": "bbb222",
            "source": "gitleaks",
            "severity": "critical",
            "rule_id": "generic-api-key",
            "file": "config.py",
            "line": 12,
            "message": "Hardcoded API key detected",
            "raw": {},
        },
        ledger_path=ledger_path,
    )
    hash_chain.append(
        "attack",
        {"vector": "sqli", "success": True, "evidence": "dumped users table"},
        ledger_path=ledger_path,
    )
    hash_chain.append(
        "consent",
        {
            "url": "https://example.com",
            "concern": "Fuga de datos",
            "confirmed": True,
            "ts": "2026-07-18T00:00:00+00:00",
        },
        ledger_path=ledger_path,
    )


def _base_run_summary(run_id="run-123"):
    return {
        "run_id": run_id,
        "started_at": "2026-07-18T00:00:00Z",
        "finished_at": "2026-07-18T00:05:00Z",
        "consent": {
            "url": "https://example.com",
            "concern": "Fuga de datos",
            "confirmed": True,
            "ts": "2026-07-18T00:00:00+00:00",
        },
        "dast": {
            "findings": [
                {
                    "id": "d1",
                    "source": "vicoguard",
                    "severity": "high",
                    "rule_id": "xss-reflected",
                    "file": "https://example.com/search",
                    "line": None,
                    "message": "Reflected XSS in search param",
                    "raw": {},
                }
            ],
            "count": 1,
        },
        "sast": {
            "findings": [
                {
                    "id": "aaa111",
                    "source": "semgrep",
                    "severity": "medium",
                    "rule_id": "some-medium-rule",
                    "file": "app.py",
                    "line": 5,
                    "message": "Medium severity issue",
                    "raw": {},
                },
                {
                    "id": "bbb222",
                    "source": "gitleaks",
                    "severity": "critical",
                    "rule_id": "generic-api-key",
                    "file": "config.py",
                    "line": 12,
                    "message": "Hardcoded API key detected",
                    "raw": {},
                },
            ],
            "count": 2,
        },
        "attack": {
            "steps": [
                {"vector": "sqli", "success": True, "evidence": "dumped users table"},
            ],
            "count": 1,
        },
        "ledger_start_index": 0,
        "ledger_end_index": 3,
        "report_path": None,
        "notified": False,
        "errors": [],
    }


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    """None of these tests should depend on real LLM credentials -- the
    interpret.summarize() call is either heuristic (no key) or mocked.
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_build_report_full_run(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    reports_dir = str(tmp_path / "reports")
    _seed_ledger(ledger_path)

    run_summary = _base_run_summary(run_id="run-full")

    path = report.build_report(
        run_summary,
        ledger_path=ledger_path,
        api_key=None,
        reports_dir=reports_dir,
    )

    assert os.path.exists(path)
    assert path.endswith(os.path.join("reports", "run-full.md")) or path.endswith(
        "run-full.md"
    )

    content = open(path, "r", encoding="utf-8").read()
    assert content.strip() != ""
    assert "run-full" in content

    assert "## Integridad del registro" in content
    expected_chain_ok = hash_chain.verify_chain(ledger_path=ledger_path)
    assert f"Cadena verificada: {expected_chain_ok}" in content

    # DAST/SAST/attack sections should have real content since all three
    # ran in this run_summary.
    assert "xss-reflected" in content
    assert "generic-api-key" in content
    assert "sqli" in content


def test_build_report_without_dast_and_attack(tmp_path):
    """Simulates a SAST-only run: no URL consent granted, so dast and
    attack are both None. The report must say so explicitly and must not
    crash.
    """
    ledger_path = str(tmp_path / "ledger.jsonl")
    reports_dir = str(tmp_path / "reports")

    hash_chain.append(
        "finding",
        {
            "id": "ccc333",
            "source": "semgrep",
            "severity": "low",
            "rule_id": "minor-rule",
            "file": "utils.py",
            "line": 1,
            "message": "Minor issue",
            "raw": {},
        },
        ledger_path=ledger_path,
    )

    run_summary = {
        "run_id": "run-sast-only",
        "started_at": "2026-07-18T00:00:00Z",
        "finished_at": "2026-07-18T00:01:00Z",
        "consent": None,
        "dast": None,
        "sast": {
            "findings": [
                {
                    "id": "ccc333",
                    "source": "semgrep",
                    "severity": "low",
                    "rule_id": "minor-rule",
                    "file": "utils.py",
                    "line": 1,
                    "message": "Minor issue",
                    "raw": {},
                }
            ],
            "count": 1,
        },
        "attack": None,
        "ledger_start_index": 0,
        "ledger_end_index": 0,
        "report_path": None,
        "notified": False,
        "errors": [],
    }

    path = report.build_report(
        run_summary,
        ledger_path=ledger_path,
        api_key=None,
        reports_dir=reports_dir,
    )

    assert os.path.exists(path)
    content = open(path, "r", encoding="utf-8").read()

    assert "No se corrió (sin consentimiento o VicoGuard no disponible)" in content
    assert "No se ejecutó" in content
    assert "(ninguna)" in content  # no consent URL
    assert "minor-rule" in content  # sast still rendered


def test_build_report_finding_with_missing_field_does_not_crash(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    reports_dir = str(tmp_path / "reports")

    run_summary = _base_run_summary(run_id="run-missing-field")
    # Drop the "message" key entirely from one SAST finding.
    del run_summary["sast"]["findings"][0]["message"]

    path = report.build_report(
        run_summary,
        ledger_path=ledger_path,
        api_key=None,
        reports_dir=reports_dir,
    )

    assert os.path.exists(path)
    content = open(path, "r", encoding="utf-8").read()
    assert content.strip() != ""
    # The row for that finding should still render, with a placeholder
    # instead of a crash.
    assert "some-medium-rule" in content


def test_build_report_uses_interpret_summarize_output_literally(tmp_path, monkeypatch):
    ledger_path = str(tmp_path / "ledger.jsonl")
    reports_dir = str(tmp_path / "reports")
    _seed_ledger(ledger_path)

    sentinel_summary = "RESUMEN DE PRUEBA - texto centinela único 12345"

    def fake_summarize(ledger_path=None, api_key=None):
        return sentinel_summary

    monkeypatch.setattr(interpret, "summarize", fake_summarize)

    run_summary = _base_run_summary(run_id="run-mocked-summary")

    path = report.build_report(
        run_summary,
        ledger_path=ledger_path,
        api_key=None,
        reports_dir=reports_dir,
    )

    content = open(path, "r", encoding="utf-8").read()
    assert sentinel_summary in content
    assert "## Resumen" in content
