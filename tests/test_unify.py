"""Tests for centinela.orchestrator.unify -- the unified WASP + VicoGuard-AI run.

These tests mock every external collaborator (static_guard, simulator,
vicoguard_adapter, notify, report) so they never depend on real services
(Semgrep, Gitleaks, a running VicoGuard-AI instance, a live localhost demo
target, or Telegram credentials) being available. ``interpret.summarize`` is
left real but forced onto its heuristic (no-LLM, no-network) fallback path
via the ``no_api_key`` fixture, matching the pattern used in
tests/test_interpret.py.

Test #4 (test_attack_always_targets_attack_target_url_never_user_url) is the
most important test in this file: it is the hard safety guarantee that the
simulated attack can never be pointed at the arbitrary, possibly remote
target URL the operator is scanning.
"""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from centinela.adapters import vicoguard_adapter
from centinela.orchestrator import unify


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    """Force interpret.summarize() onto its heuristic fallback in every test."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _patch_all(tmp_path, sast_findings=None, dast_findings=None, attack_steps=None, report_path=None):
    """Common set of patches used across most tests, returned as a dict of
    the individual mock objects so callers can add assertions on them.
    """
    ledger_path = str(tmp_path / "ledger.jsonl")
    reports_dir = str(tmp_path / "reports")

    mocks = {
        "scan": patch("centinela.orchestrator.unify.static_guard.scan", return_value=sast_findings or []),
        "run_attack": patch(
            "centinela.orchestrator.unify.simulator.run_attack", return_value=attack_steps or []
        ),
        "run_dast_scan": patch(
            "centinela.orchestrator.unify.vicoguard_adapter.run_dast_scan",
            return_value={"findings": dast_findings or []},
        ),
        "ingest_dast_findings": patch(
            "centinela.orchestrator.unify.vicoguard_adapter.ingest_dast_findings",
            return_value=dast_findings or [],
        ),
        "send_message": patch("centinela.orchestrator.unify.notify_service.send_message", return_value=True),
        "build_report": patch(
            "centinela.orchestrator.unify.report.build_report",
            return_value=report_path or str(tmp_path / "reports" / "fake-run.md"),
        ),
    }
    return ledger_path, reports_dir, mocks


def test_happy_path_all_findings_present_no_errors_notified(tmp_path):
    ledger_path, reports_dir, mocks = _patch_all(
        tmp_path,
        sast_findings=[{"id": "sast-1", "severity": "high"}],
        dast_findings=[{"id": "dast-1", "severity": "critical"}],
        attack_steps=[{"vector": "sql_injection", "success": True}],
    )

    with mocks["scan"], mocks["run_attack"], mocks["run_dast_scan"], mocks["ingest_dast_findings"], mocks[
        "send_message"
    ], mocks["build_report"]:
        result = unify.run_unified(
            url="http://127.0.0.1:8899",
            repo="some/repo",
            ledger_path=ledger_path,
            reports_dir=reports_dir,
            confirmed=True,
            interactive=False,
            concern="fuga de datos",
        )

    assert result["errors"] == []
    assert result["notified"] is True
    assert result["dast"]["count"] == 1
    assert result["sast"]["count"] == 1
    assert result["attack"]["count"] == 1
    assert result["consent"]["confirmed"] is True
    assert result["report_path"] is not None
    assert result["run_id"]
    assert result["ledger_end_index"] >= result["ledger_start_index"]


def test_consent_refused_skips_dast_but_runs_sast_and_attack(tmp_path):
    ledger_path, reports_dir, mocks = _patch_all(
        tmp_path,
        sast_findings=[{"id": "sast-1", "severity": "medium"}],
        attack_steps=[{"vector": "fuerza_bruta", "success": False}],
    )

    with mocks["scan"], mocks["run_attack"], mocks["run_dast_scan"] as mock_run_dast, mocks[
        "ingest_dast_findings"
    ] as mock_ingest, mocks["send_message"], mocks["build_report"]:
        result = unify.run_unified(
            url="https://example.com",
            repo="some/repo",
            ledger_path=ledger_path,
            reports_dir=reports_dir,
            confirmed=False,
            interactive=False,
        )

    mock_run_dast.assert_not_called()
    mock_ingest.assert_not_called()

    assert result["dast"] is None
    assert result["sast"]["count"] == 1
    assert result["attack"]["count"] == 1
    assert any("DAST omitido" in e for e in result["errors"])
    assert result["report_path"] is not None


def test_vicoguard_unavailable_is_captured_but_rest_of_run_completes(tmp_path):
    ledger_path, reports_dir, mocks = _patch_all(
        tmp_path,
        sast_findings=[{"id": "sast-1", "severity": "low"}],
        attack_steps=[{"vector": "command_injection", "success": False}],
    )

    with mocks["scan"], mocks["run_attack"], patch(
        "centinela.orchestrator.unify.vicoguard_adapter.run_dast_scan",
        side_effect=vicoguard_adapter.VicoGuardUnavailableError("VicoGuard no responde en http://127.0.0.1:8000"),
    ), mocks["ingest_dast_findings"] as mock_ingest, mocks["send_message"], mocks["build_report"]:
        result = unify.run_unified(
            url="https://example.com",
            repo="some/repo",
            ledger_path=ledger_path,
            reports_dir=reports_dir,
            confirmed=True,
            interactive=False,
            concern="disponibilidad",
        )

    mock_ingest.assert_not_called()
    assert result["dast"] is None
    assert any("DAST falló" in e for e in result["errors"])
    assert result["sast"]["count"] == 1
    assert result["attack"]["count"] == 1
    assert result["report_path"] is not None


def test_attack_always_targets_attack_target_url_never_user_url(tmp_path):
    """THE most important test in this file.

    run_attack() must always be called with attack_target_url (the
    localhost-only demo default), and it must NEVER be called with `url`
    (the arbitrary, possibly remote target the operator is scanning) --
    even though `url` here is a clearly non-local, real-looking address.
    """
    ledger_path, reports_dir, mocks = _patch_all(tmp_path, sast_findings=[], dast_findings=[])

    with mocks["scan"], mocks["run_attack"] as mock_run_attack, mocks["run_dast_scan"], mocks[
        "ingest_dast_findings"
    ], mocks["send_message"], mocks["build_report"]:
        unify.run_unified(
            url="https://example.com",
            repo="algun/path",
            ledger_path=ledger_path,
            reports_dir=reports_dir,
            confirmed=True,
            interactive=False,
            concern="test",
        )

    mock_run_attack.assert_called_once()
    _, call_kwargs = mock_run_attack.call_args

    assert call_kwargs["target_url"] == "http://127.0.0.1:8899"
    assert call_kwargs["target_url"] == unify.DEFAULT_ATTACK_TARGET_URL
    assert call_kwargs["target_url"] != "https://example.com"


def test_cli_unify_help_does_not_crash(tmp_path):
    from centinela import main

    with pytest.raises(SystemExit) as exc_info:
        main.main(["unify", "--help"])
    assert exc_info.value.code == 0


def test_cli_unify_help_subprocess_shows_expected_flags():
    project_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "centinela.main", "unify", "--help"],
        capture_output=True,
        text=True,
        cwd=str(project_root),
    )
    assert result.returncode == 0
    for flag in (
        "--url",
        "--repo",
        "--no-attack",
        "--attack-target",
        "--vicoguard-url",
        "--no-notify",
        "--concern",
        "--confirm",
        "--no-interactive",
    ):
        assert flag in result.stdout
