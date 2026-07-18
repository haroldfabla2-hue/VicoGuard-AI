"""Append-only, tamper-evident audit log using a SHA-256 hash chain.

Each entry embeds the hash of the previous entry, so any modification to a
past entry breaks the chain and is detectable via ``verify_chain``.

A simple hash-chain (not a Merkle tree) was chosen deliberately: the ledger
is a linear, append-only sequence of events (findings, governance
decisions), and a Merkle tree's branching structure adds no value for a
purely sequential log while adding unnecessary complexity.
"""

import hashlib
import json
import os
from datetime import datetime

from filelock import FileLock

GENESIS_HASH = "0" * 64

DEFAULT_LEDGER_PATH = "centinela/data/ledger.jsonl"

# append() does read-modify-write (read the last entry to compute the next
# index/prev_hash, then write). Without a lock, two processes calling
# append() at the same instant (e.g. the governance hook firing on a Bash
# call while a `scan` is also writing findings) can both read the same
# "last entry" snapshot and append two entries claiming the same index,
# silently corrupting the chain. The lock serializes the whole
# read-compute-write critical section across processes, not just threads.
_LOCK_SUFFIX = ".lock"


def _compute_hash(index: int, ts: str, entry_type: str, data: dict, prev_hash: str) -> str:
    payload = f"{index}|{ts}|{entry_type}|{json.dumps(data, sort_keys=True)}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def read_entries(ledger_path: str = DEFAULT_LEDGER_PATH) -> list:
    """Read all entries from the ledger file, in order.

    Returns an empty list if the file does not exist or is empty.
    """
    if not os.path.exists(ledger_path):
        return []

    entries = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def append(entry_type: str, data: dict, ledger_path: str = DEFAULT_LEDGER_PATH) -> dict:
    """Append a new entry to the ledger, chaining it to the previous one.

    Computes the next sequential index and the previous entry's hash by
    reading the existing ledger file, creates the parent directory if
    needed, appends the new entry as a JSON line, and returns the full
    entry (including its computed hash).

    The whole read-compute-write sequence is serialized with a cross-process
    file lock so concurrent callers (the governance hook and a scan running
    at the same time, for example) can never both compute the same index.
    """
    parent_dir = os.path.dirname(ledger_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    lock = FileLock(ledger_path + _LOCK_SUFFIX)
    with lock:
        existing = read_entries(ledger_path)

        if existing:
            index = existing[-1]["index"] + 1
            prev_hash = existing[-1]["hash"]
        else:
            index = 0
            prev_hash = GENESIS_HASH

        ts = datetime.utcnow().isoformat()
        entry_hash = _compute_hash(index, ts, entry_type, data, prev_hash)

        entry = {
            "index": index,
            "ts": ts,
            "type": entry_type,
            "data": data,
            "prev_hash": prev_hash,
            "hash": entry_hash,
        }

        with open(ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    return entry


def verify_chain(ledger_path: str = DEFAULT_LEDGER_PATH) -> bool:
    """Recompute every entry's hash from scratch and confirm chain integrity.

    Checks that indices are sequential starting at 0, that each entry's
    ``prev_hash`` matches the previous entry's recomputed ``hash``, and that
    each entry's stored ``hash`` matches its recomputed hash.

    An empty or missing ledger is considered a valid (trivially intact)
    chain, so this returns True in that case.
    """
    entries = read_entries(ledger_path)
    if not entries:
        return True

    expected_prev_hash = GENESIS_HASH
    for expected_index, entry in enumerate(entries):
        if entry.get("index") != expected_index:
            return False

        if entry.get("prev_hash") != expected_prev_hash:
            return False

        recomputed = _compute_hash(
            entry["index"],
            entry["ts"],
            entry["type"],
            entry["data"],
            entry["prev_hash"],
        )
        if recomputed != entry.get("hash"):
            return False

        expected_prev_hash = entry["hash"]

    return True
