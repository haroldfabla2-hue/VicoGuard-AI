"""Tests for centinela.interpreter.interpret -- heuristic (no-LLM) path.

These tests never set ANTHROPIC_API_KEY, so summarize()/explain() always
run the fallback heuristic branch -- the LLM branch requires real
credentials that aren't available in this environment yet and is
intentionally not covered here.
"""

import pytest

from centinela.interpreter import interpret
from centinela.ledger import hash_chain


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    """Ensure every test in this file exercises the heuristic fallback."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _seed_ledger(ledger_path):
    """Build a small, realistic ledger: two findings (medium + critical)
    and one denied governance decision, mirroring the real shapes produced
    by static_guard.scan() and the governance audit hook.
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
        "denied",
        {
            "tool": "Bash",
            "command": "git push --force origin main",
            "decision": "deny",
            "reason": "Comando bloqueado por el contrato de capacidades.",
            "ts": "2026-07-18T00:00:00Z",
        },
        ledger_path=ledger_path,
    )


def test_summarize_heuristic_mentions_highest_severity(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    _seed_ledger(ledger_path)

    result = interpret.summarize(ledger_path=ledger_path)

    assert isinstance(result, str)
    assert result.strip() != ""
    # highest severity present across the seeded findings is "critical"
    assert "crítico" in result.lower() or "critical" in result.lower()


def test_summarize_heuristic_empty_ledger_is_honest_not_crash(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    result = interpret.summarize(ledger_path=ledger_path)

    assert isinstance(result, str)
    assert result.strip() != ""
    assert "vacío" in result.lower()


def test_explain_unknown_id_returns_clear_error_not_exception(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    _seed_ledger(ledger_path)

    result = interpret.explain("does-not-exist", ledger_path=ledger_path)

    assert isinstance(result, str)
    assert "no encontr" in result.lower()


def test_explain_unknown_id_on_empty_ledger_does_not_raise(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    result = interpret.explain("anything", ledger_path=ledger_path)

    assert isinstance(result, str)
    assert "no encontr" in result.lower()


def test_explain_known_finding_id_heuristic(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    _seed_ledger(ledger_path)

    result = interpret.explain("bbb222", ledger_path=ledger_path)

    assert isinstance(result, str)
    assert "bbb222" in result
    assert "crítico" in result.lower()


def test_explain_decision_by_ledger_index_heuristic(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    _seed_ledger(ledger_path)

    # the denied entry is the 3rd appended -> ledger index 2
    result = interpret.explain("2", ledger_path=ledger_path)

    assert isinstance(result, str)
    assert "bloqueada" in result.lower()
    assert "git push" in result.lower()


def test_answer_question_without_api_key_is_honest(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    _seed_ledger(ledger_path)

    result = interpret.answer_question("¿qué hallazgos hay?", ledger_path=ledger_path)

    assert isinstance(result, str)
    assert "sin ia" in result.lower() or "sin la ia" in result.lower()


def test_list_recent_findings_returns_short_lines(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")
    _seed_ledger(ledger_path)

    lines = interpret.list_recent_findings(ledger_path=ledger_path, limit=10)

    assert len(lines) == 2
    assert all(isinstance(line, str) for line in lines)
    # most recent finding first
    assert "bbb222" not in lines[0]  # id isn't rendered, but file/line is
    assert "config.py:12" in lines[0]


def test_module_importable_and_callable_without_api_key():
    # Import already happened at module load; this just documents the
    # structural requirement explicitly: no crash without ANTHROPIC_API_KEY.
    assert callable(interpret.summarize)
    assert callable(interpret.explain)
    assert callable(interpret.answer_question)
