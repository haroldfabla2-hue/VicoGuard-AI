"""Tests for centinela.orchestrator.notify -- proactive Telegram push.

These tests never make real network calls: httpx.post is monkeypatched.
The credential-leak check (test_send_message_success_does_not_leak_token)
is the important one -- it guards against repeating the exact incident
that already happened once in this project with httpx logging the full
request URL (token embedded) at INFO level.
"""

import httpx
import pytest

from centinela.orchestrator import notify


class _FakeResponse:
    def __init__(self, status_code: int, json_data: dict):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


def test_send_message_without_token_returns_false(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    result = notify.send_message("hola")

    assert result is False


def test_send_message_without_chat_id_returns_false(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token-123")
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

    result = notify.send_message("hola")

    assert result is False


def test_send_message_success_does_not_leak_token(monkeypatch, capsys):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token-123")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "999")

    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append((url, json, timeout))
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr(httpx, "post", fake_post)

    result = notify.send_message("análisis terminado")

    assert result is True
    assert len(calls) == 1
    # sanity: the URL really does carry the token internally...
    assert "test-token-123" in calls[0][0]

    # ...but it must never end up printed to stdout.
    captured = capsys.readouterr()
    assert "test-token-123" not in captured.out
    assert "test-token-123" not in captured.err


def test_send_message_http_error_status_returns_false(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "test-token-123")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "999")

    def fake_post(url, json=None, timeout=None):
        return _FakeResponse(401, {"ok": False, "description": "Unauthorized"})

    monkeypatch.setattr(httpx, "post", fake_post)

    result = notify.send_message("hola")

    assert result is False
