import json

from centinela.ledger import hash_chain


def test_append_and_verify_chain_valid(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    entry0 = hash_chain.append("finding", {"msg": "first"}, ledger_path=ledger_path)
    entry1 = hash_chain.append("allowed", {"msg": "second"}, ledger_path=ledger_path)
    entry2 = hash_chain.append("denied", {"msg": "third"}, ledger_path=ledger_path)

    assert entry0["index"] == 0
    assert entry0["prev_hash"] == "0" * 64
    assert entry1["index"] == 1
    assert entry1["prev_hash"] == entry0["hash"]
    assert entry2["index"] == 2
    assert entry2["prev_hash"] == entry1["hash"]

    entries = hash_chain.read_entries(ledger_path=ledger_path)
    assert len(entries) == 3

    assert hash_chain.verify_chain(ledger_path=ledger_path) is True


def test_verify_chain_detects_tampering(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    hash_chain.append("finding", {"msg": "first"}, ledger_path=ledger_path)
    hash_chain.append("allowed", {"msg": "second"}, ledger_path=ledger_path)
    hash_chain.append("denied", {"msg": "third"}, ledger_path=ledger_path)

    assert hash_chain.verify_chain(ledger_path=ledger_path) is True

    # Corrupt the middle entry's data without recalculating its hash.
    with open(ledger_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    middle = json.loads(lines[1])
    middle["data"] = {"msg": "TAMPERED"}
    lines[1] = json.dumps(middle) + "\n"

    with open(ledger_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    assert hash_chain.verify_chain(ledger_path=ledger_path) is False


def test_verify_chain_empty_or_missing_is_valid(tmp_path):
    missing_path = str(tmp_path / "does_not_exist.jsonl")
    assert hash_chain.verify_chain(ledger_path=missing_path) is True

    empty_path = tmp_path / "empty.jsonl"
    empty_path.write_text("", encoding="utf-8")
    assert hash_chain.verify_chain(ledger_path=str(empty_path)) is True
