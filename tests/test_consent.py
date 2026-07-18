from centinela.ledger import hash_chain
from centinela.orchestrator import consent


def test_non_interactive_confirmed_records_entry(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    result = consent.ask_consent(
        "https://example.com",
        concern="fuga de datos",
        confirmed=True,
        interactive=False,
        ledger_path=ledger_path,
    )

    assert result["url"] == "https://example.com"
    assert result["concern"] == "fuga de datos"
    assert result["confirmed"] is True

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert len(entries) == 1
    assert entries[0]["type"] == "consent"
    assert entries[0]["data"]["confirmed"] is True
    assert entries[0]["data"]["concern"] == "fuga de datos"


def test_non_interactive_refused_does_not_raise(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    result = consent.ask_consent(
        "https://example.com",
        interactive=False,
        ledger_path=ledger_path,
    )

    assert result["confirmed"] is False

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert len(entries) == 1
    assert entries[0]["type"] == "consent"
    assert entries[0]["data"]["confirmed"] is False


def test_non_interactive_confirmed_without_concern_defaults(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    result = consent.ask_consent(
        "https://example.com",
        confirmed=True,
        interactive=False,
        ledger_path=ledger_path,
    )

    assert result["concern"] == "no especificado"
    assert result["confirmed"] is True

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert entries[0]["data"]["concern"] == "no especificado"


def test_interactive_accepts_confirmation(tmp_path, monkeypatch):
    ledger_path = str(tmp_path / "ledger.jsonl")

    answers = iter(["1", "s"])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(answers))

    result = consent.ask_consent(
        "https://example.com",
        interactive=True,
        ledger_path=ledger_path,
    )

    assert result["confirmed"] is True
    assert result["concern"] == "Fuga de datos"

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert entries[0]["data"]["confirmed"] is True
    assert entries[0]["data"]["concern"] == "Fuga de datos"


def test_interactive_rejects_confirmation(tmp_path, monkeypatch):
    ledger_path = str(tmp_path / "ledger.jsonl")

    answers = iter(["2", ""])
    monkeypatch.setattr("builtins.input", lambda *_args, **_kwargs: next(answers))

    result = consent.ask_consent(
        "https://example.com",
        interactive=True,
        ledger_path=ledger_path,
    )

    assert result["confirmed"] is False

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert entries[0]["data"]["confirmed"] is False
