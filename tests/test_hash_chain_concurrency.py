"""Proves hash_chain.append() is safe under real concurrent processes.

This is a regression test for a race condition found during Fase 2: two
separate builder agents wrote to the same ledger file at nearly the same
time, and it happened to come out consistent by luck (the writes didn't
land at the exact same instant). append() does read-modify-write (read the
last entry to compute the next index/prev_hash, then write) — without a
lock, two truly-simultaneous callers can both read the same "last entry"
and both compute the same next index, corrupting the chain. This test
forces that collision on purpose, across real OS processes (not threads,
since threads share the GIL and would hide a cross-process file race),
and confirms the FileLock fix in hash_chain.append() prevents it.
"""

import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from centinela.ledger import hash_chain  # noqa: E402

NUM_WORKERS = 8
APPENDS_PER_WORKER = 10


def _worker_append_many(ledger_path: str, worker_id: int) -> int:
    """Runs in a separate process: appends APPENDS_PER_WORKER entries back to back."""
    for i in range(APPENDS_PER_WORKER):
        hash_chain.append("finding", {"worker": worker_id, "n": i}, ledger_path=ledger_path)
    return worker_id


def test_concurrent_appends_from_multiple_processes_stay_consistent(tmp_path):
    ledger_path = str(tmp_path / "ledger.jsonl")

    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = [
            executor.submit(_worker_append_many, ledger_path, worker_id)
            for worker_id in range(NUM_WORKERS)
        ]
        for future in as_completed(futures):
            future.result()  # re-raises any exception from the worker process

    entries = hash_chain.read_entries(ledger_path)
    expected_total = NUM_WORKERS * APPENDS_PER_WORKER

    assert len(entries) == expected_total, (
        f"expected {expected_total} entries, got {len(entries)} — "
        "a lost write means the lock let two processes overwrite each other"
    )

    indices = sorted(e["index"] for e in entries)
    assert indices == list(range(expected_total)), (
        "indices are not a contiguous 0..N-1 sequence — "
        "duplicate or skipped indices mean two processes raced on the same slot"
    )

    assert hash_chain.verify_chain(ledger_path) is True, (
        "chain failed verification after concurrent writes — "
        "prev_hash linkage broke under concurrency"
    )
