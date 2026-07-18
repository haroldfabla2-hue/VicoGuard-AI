"""Tests for centinela.orchestrator.cronos.

All tests use tmp_path for the ledger/state files and monkeypatch
notify.send_message so nothing ever hits the real Telegram API.
"""

import pytest

from centinela.ledger import hash_chain
from centinela.orchestrator import cronos


@pytest.fixture
def ledger_path(tmp_path):
    return str(tmp_path / "ledger.jsonl")


@pytest.fixture
def state_path(tmp_path):
    return str(tmp_path / "cronos_state.json")


@pytest.fixture
def fake_notify(monkeypatch):
    calls = []

    def fake_send_message(text, chat_id=None, token=None):
        calls.append(text)
        return True

    monkeypatch.setattr(cronos.notify, "send_message", fake_send_message)
    return calls


def test_empty_ledger_first_run_does_not_notify(ledger_path, state_path, fake_notify):
    result = cronos.run_one_cycle(ledger_path=ledger_path, state_path=state_path)

    assert result["notified"] is False
    assert result["new_denied"] == []
    assert result["new_attacks"] == []
    assert result["new_critical_findings"] == []
    assert result["last_seen_index"] == -1
    assert fake_notify == []


def test_non_critical_findings_do_not_notify_but_advance_checkpoint(
    ledger_path, state_path, fake_notify
):
    hash_chain.append("finding", {"severity": "low"}, ledger_path=ledger_path)
    hash_chain.append("finding", {"severity": "medium"}, ledger_path=ledger_path)

    result = cronos.run_one_cycle(ledger_path=ledger_path, state_path=state_path)

    assert result["notified"] is False
    assert result["new_denied"] == []
    assert result["new_attacks"] == []
    assert result["new_critical_findings"] == []
    assert result["last_seen_index"] != -1
    assert fake_notify == []


def test_new_denied_entry_triggers_notification(ledger_path, state_path, fake_notify):
    hash_chain.append("finding", {"severity": "low"}, ledger_path=ledger_path)
    # First cycle establishes a checkpoint past the non-critical finding.
    cronos.run_one_cycle(ledger_path=ledger_path, state_path=state_path)

    hash_chain.append("denied", {"action": "rm -rf /"}, ledger_path=ledger_path)

    result = cronos.run_one_cycle(ledger_path=ledger_path, state_path=state_path)

    assert result["notified"] is True
    assert len(result["new_denied"]) == 1
    assert len(fake_notify) == 1


def test_second_run_with_no_new_entries_does_not_notify(ledger_path, state_path, fake_notify):
    hash_chain.append("denied", {"action": "rm -rf /"}, ledger_path=ledger_path)
    first_result = cronos.run_one_cycle(ledger_path=ledger_path, state_path=state_path)
    assert first_result["notified"] is True

    second_result = cronos.run_one_cycle(ledger_path=ledger_path, state_path=state_path)

    assert second_result["notified"] is False
    assert second_result["new_denied"] == []
    assert second_result["new_attacks"] == []
    assert second_result["new_critical_findings"] == []


def test_run_forever_rejects_interval_below_one_minute():
    with pytest.raises(ValueError):
        cronos.run_forever(interval_minutes=0)
