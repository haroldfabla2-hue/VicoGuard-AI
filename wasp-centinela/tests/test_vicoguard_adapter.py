from unittest.mock import MagicMock, patch

import httpx
import pytest

from centinela.adapters import vicoguard_adapter
from centinela.ledger import hash_chain


def test_adapt_finding_raw_produces_wasp_schema():
    raw_finding = {
        "id": "vg-001",
        "severity": "HIGH",
        "title_business": "Login endpoint leaks stack traces",
        "category": "information-disclosure",
    }

    adapted = vicoguard_adapter.adapt_finding(raw_finding, "https://example.com/login")

    assert set(adapted.keys()) == {
        "id",
        "source",
        "severity",
        "rule_id",
        "file",
        "line",
        "message",
        "raw",
    }
    assert adapted["id"] == "vicoguard:vg-001"
    assert adapted["source"] == "vicoguard-dast"
    assert adapted["severity"] == "high"
    assert adapted["rule_id"] == "information-disclosure"
    assert adapted["file"] == "(dast) https://example.com/login"
    assert adapted["line"] == 0
    assert adapted["message"] == "Login endpoint leaks stack traces"
    assert adapted["raw"] == raw_finding


def test_adapt_finding_enriched_keeps_extra_fields_in_raw():
    enriched_finding = {
        "id": "vg-002",
        "severity": "critical",
        "title_business": "Payment API allows SQL injection",
        "title_technical": "SQLi in /api/payments",
        "category": "sql-injection",
        "evidence": "' OR 1=1 --",
        "remediation_code": "use parameterized queries",
        "analogy": "like leaving your front door unlocked",
        "impact": "attacker can read the whole database",
        "remediation_steps": ["use an ORM", "add input validation"],
        "status": "confirmed",
    }

    adapted = vicoguard_adapter.adapt_finding(enriched_finding, "https://example.com/pay")

    assert adapted["severity"] == "critical"
    assert adapted["message"] == "Payment API allows SQL injection"
    assert adapted["raw"] == enriched_finding
    assert adapted["raw"]["analogy"] == "like leaving your front door unlocked"
    assert adapted["raw"]["remediation_steps"] == ["use an ORM", "add input validation"]


def test_adapt_finding_missing_fields_falls_back_gracefully():
    sparse_finding = {}

    adapted = vicoguard_adapter.adapt_finding(sparse_finding, "https://example.com")

    assert adapted["id"] == "vicoguard:unknown"
    assert adapted["severity"] == "low"
    assert adapted["rule_id"] == "unknown"
    assert adapted["message"] == "sin descripción"


def test_ingest_dast_findings_writes_to_ledger_and_chain_verifies(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    vg_findings = [
        {"id": "vg-001", "severity": "HIGH", "title_business": "Finding one", "category": "xss"},
        {"id": "vg-002", "severity": "MEDIUM", "title_business": "Finding two", "category": "csrf"},
        {"id": "vg-003", "severity": "LOW", "title_technical": "Finding three", "category": "info"},
    ]

    result = vicoguard_adapter.ingest_dast_findings(
        vg_findings, "https://example.com", ledger_path=ledger_path
    )

    assert len(result) == 3
    assert all(f["source"] == "vicoguard-dast" for f in result)

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert len(entries) == 3
    assert all(entry["type"] == "finding" for entry in entries)
    assert all(entry["data"]["source"] == "vicoguard-dast" for entry in entries)

    assert hash_chain.verify_chain(ledger_path=ledger_path) is True


def _fake_start_response(scan_id="scan-123"):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"scan_id": scan_id, "status": "queued"}
    return resp


def _fake_poll_response(status, result=None):
    resp = MagicMock()
    resp.status_code = 200
    body = {"status": status}
    if result is not None:
        body["result"] = result
    resp.json.return_value = body
    return resp


def test_run_dast_scan_happy_path_async_start_and_poll():
    """Uses the async /scan/start + poll /scan/{id} pattern (not the
    synchronous /scan/repository, which deadlocks on self-referential
    targets -- confirmed live)."""
    start_resp = _fake_start_response()
    completed_resp = _fake_poll_response(
        "completed",
        result={"findings": [{"id": "vg-001", "severity": "HIGH"}], "security_score": 72},
    )

    with patch("centinela.adapters.vicoguard_adapter.httpx.post", return_value=start_resp) as mock_post, \
         patch("centinela.adapters.vicoguard_adapter.httpx.get", return_value=completed_resp) as mock_get, \
         patch("centinela.adapters.vicoguard_adapter.time.sleep"):
        result = vicoguard_adapter.run_dast_scan("https://target.example.com")

    assert result["security_score"] == 72
    assert result["findings"] == [{"id": "vg-001", "severity": "HIGH"}]

    mock_post.assert_called_once()
    call_args, call_kwargs = mock_post.call_args
    assert call_args[0] == f"{vicoguard_adapter.DEFAULT_VICOGUARD_BASE_URL}/api/v1/scan/start"
    assert call_kwargs["json"] == {
        "repo_url": "https://target.example.com",
        "notify": False,
        "use_agent_team": False,
    }
    mock_get.assert_called_once()
    assert "scan-123" in mock_get.call_args[0][0]


def test_run_dast_scan_polls_until_completed():
    """Confirms it actually polls (queued -> running -> completed), not
    just a single lucky GET."""
    start_resp = _fake_start_response()
    responses = [
        _fake_poll_response("queued"),
        _fake_poll_response("running"),
        _fake_poll_response("completed", result={"findings": [], "security_score": 100}),
    ]

    with patch("centinela.adapters.vicoguard_adapter.httpx.post", return_value=start_resp), \
         patch("centinela.adapters.vicoguard_adapter.httpx.get", side_effect=responses) as mock_get, \
         patch("centinela.adapters.vicoguard_adapter.time.sleep"):
        result = vicoguard_adapter.run_dast_scan("https://target.example.com")

    assert result["security_score"] == 100
    assert mock_get.call_count == 3


def test_run_dast_scan_use_agent_team_flag_forwarded():
    start_resp = _fake_start_response()
    completed_resp = _fake_poll_response("completed", result={"findings": [], "security_score": 50})

    with patch("centinela.adapters.vicoguard_adapter.httpx.post", return_value=start_resp) as mock_post, \
         patch("centinela.adapters.vicoguard_adapter.httpx.get", return_value=completed_resp), \
         patch("centinela.adapters.vicoguard_adapter.time.sleep"):
        vicoguard_adapter.run_dast_scan("https://target.example.com", use_agent_team=True)

    assert mock_post.call_args[1]["json"]["use_agent_team"] is True


def test_run_dast_scan_connection_refused_raises_clear_error():
    with patch(
        "centinela.adapters.vicoguard_adapter.httpx.post",
        side_effect=httpx.ConnectError("connection refused"),
    ):
        with pytest.raises(vicoguard_adapter.VicoGuardUnavailableError) as exc_info:
            vicoguard_adapter.run_dast_scan("https://target.example.com")

    assert "VicoGuard no responde" in str(exc_info.value)
    assert vicoguard_adapter.DEFAULT_VICOGUARD_BASE_URL in str(exc_info.value)


def test_run_dast_scan_start_timeout_raises_clear_error():
    with patch(
        "centinela.adapters.vicoguard_adapter.httpx.post",
        side_effect=httpx.TimeoutException("timed out"),
    ):
        with pytest.raises(vicoguard_adapter.VicoGuardUnavailableError):
            vicoguard_adapter.run_dast_scan("https://target.example.com")


def test_run_dast_scan_start_error_status_raises_clear_error():
    fake_response = MagicMock()
    fake_response.status_code = 500

    with patch("centinela.adapters.vicoguard_adapter.httpx.post", return_value=fake_response):
        with pytest.raises(vicoguard_adapter.VicoGuardUnavailableError):
            vicoguard_adapter.run_dast_scan("https://target.example.com")


def test_run_dast_scan_job_failed_status_raises_clear_error():
    start_resp = _fake_start_response()
    failed_resp = _fake_poll_response("failed")

    with patch("centinela.adapters.vicoguard_adapter.httpx.post", return_value=start_resp), \
         patch("centinela.adapters.vicoguard_adapter.httpx.get", return_value=failed_resp), \
         patch("centinela.adapters.vicoguard_adapter.time.sleep"):
        with pytest.raises(vicoguard_adapter.VicoGuardUnavailableError):
            vicoguard_adapter.run_dast_scan("https://target.example.com")


def test_run_dast_scan_poll_timeout_raises_clear_error():
    """If the job never reaches a terminal status within `timeout`, raise
    instead of polling forever."""
    start_resp = _fake_start_response()
    running_resp = _fake_poll_response("running")

    fake_time = [0.0]

    def fake_monotonic():
        return fake_time[0]

    def fake_sleep(seconds):
        fake_time[0] += seconds

    with patch("centinela.adapters.vicoguard_adapter.httpx.post", return_value=start_resp), \
         patch("centinela.adapters.vicoguard_adapter.httpx.get", return_value=running_resp), \
         patch("centinela.adapters.vicoguard_adapter.time.sleep", side_effect=fake_sleep), \
         patch("centinela.adapters.vicoguard_adapter.time.monotonic", side_effect=fake_monotonic):
        with pytest.raises(vicoguard_adapter.VicoGuardUnavailableError, match="no terminó"):
            vicoguard_adapter.run_dast_scan("https://target.example.com", timeout=5.0)
