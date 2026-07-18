"""Cronos -- periodic watcher over the Centinela ledger.

Cronos wakes up on a fixed interval, looks at every ledger entry that
appeared since its last run, and pushes a single consolidated Telegram
notification when it finds anything worth flagging: a governance action
that got denied, a new simulated attack, or a critical finding. This is
deliberately a polling loop (not a subscription/webhook) because the
ledger is a plain append-only JSONL file with no event bus behind it --
polling the file and tracking a "last seen index" checkpoint is the
simplest correct way to avoid re-notifying about the same entries every
cycle, and avoiding missing new ones.

The "last seen index" is persisted to disk (state_path) so that Cronos
can be killed and restarted without re-sending old notifications.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from centinela.ledger import hash_chain
from centinela.orchestrator import notify

DEFAULT_STATE_PATH = "centinela/data/cronos_state.json"


def _load_last_seen_index(state_path: str = DEFAULT_STATE_PATH) -> int:
    """Read {"last_seen_index": N} from state_path.

    Returns -1 if the file does not exist, is empty, or is corrupted --
    treating any of those as "nothing has been seen yet" rather than
    raising, so a missing/corrupt checkpoint file never crashes a cycle.
    """
    if not os.path.exists(state_path):
        return -1

    try:
        with open(state_path, "r", encoding="utf-8") as f:
            content = json.load(f)
    except (json.JSONDecodeError, OSError, ValueError):
        return -1

    if not isinstance(content, dict):
        return -1

    index = content.get("last_seen_index", -1)
    if not isinstance(index, int):
        return -1

    return index


def _save_last_seen_index(index: int, state_path: str = DEFAULT_STATE_PATH) -> None:
    """Persist {"last_seen_index": index} to state_path.

    Creates the parent directory if it doesn't exist yet.
    """
    parent_dir = os.path.dirname(state_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"last_seen_index": index}, f)


def run_one_cycle(
    ledger_path: str = "centinela/data/ledger.jsonl",
    state_path: str = DEFAULT_STATE_PATH,
) -> dict:
    """Run a single Cronos pass: check for new ledger activity and notify.

    Reads the last seen index, reads all ledger entries, and looks only at
    entries with index greater than the last seen one. Among those "new"
    entries it separates out denied governance actions, simulated attacks,
    and critical findings. If any of the three categories is non-empty, a
    single consolidated Spanish-language message is sent via
    notify.send_message(); otherwise no notification is sent at all.

    The checkpoint is always advanced to the highest index present in the
    whole ledger (not just the new entries), so a cycle that finds nothing
    new still moves the checkpoint forward if the ledger already covered
    that ground -- and an empty ledger leaves the checkpoint at -1.
    """
    last_seen_index = _load_last_seen_index(state_path)
    entries = hash_chain.read_entries(ledger_path)

    new_entries = [e for e in entries if e.get("index", -1) > last_seen_index]

    new_denied = [e for e in new_entries if e.get("type") == "denied"]
    new_attacks = [e for e in new_entries if e.get("type") == "attack"]
    new_critical_findings = [
        e
        for e in new_entries
        if e.get("type") == "finding" and e.get("data", {}).get("severity") == "critical"
    ]

    if entries:
        max_index = max(e.get("index", -1) for e in entries)
    else:
        max_index = -1

    notified = False
    if new_denied or new_attacks or new_critical_findings:
        lines = ["🕐 Cronos -- actividad nueva detectada:"]
        if new_denied:
            lines.append(f"- {len(new_denied)} acciones bloqueadas por gobernanza")
        if new_attacks:
            lines.append(f"- {len(new_attacks)} ataques simulados")
        if new_critical_findings:
            lines.append(f"- {len(new_critical_findings)} hallazgos críticos nuevos")
        lines.append(f"Último índice revisado: {max_index}")
        message = "\n".join(lines)

        notified = notify.send_message(message)

    _save_last_seen_index(max_index, state_path)

    return {
        "new_denied": new_denied,
        "new_attacks": new_attacks,
        "new_critical_findings": new_critical_findings,
        "notified": notified,
        "last_seen_index": max_index,
    }


def run_forever(
    interval_minutes: int = 15,
    ledger_path: str = "centinela/data/ledger.jsonl",
    state_path: str = DEFAULT_STATE_PATH,
) -> None:
    """Run run_one_cycle() forever, sleeping interval_minutes between runs.

    Raises ValueError immediately (before entering the loop) if
    interval_minutes is less than 1, so a bad config fails fast instead of
    busy-looping.
    """
    if interval_minutes < 1:
        raise ValueError("interval_minutes must be >= 1")

    while True:
        result = run_one_cycle(ledger_path=ledger_path, state_path=state_path)
        timestamp = datetime.now(timezone.utc).isoformat()
        summary = (
            f"denied={len(result['new_denied'])} "
            f"attacks={len(result['new_attacks'])} "
            f"critical_findings={len(result['new_critical_findings'])} "
            f"notified={result['notified']} "
            f"last_seen_index={result['last_seen_index']}"
        )
        print(f"[cronos] {timestamp} -- {summary}")

        time.sleep(interval_minutes * 60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog="python -m centinela.orchestrator.cronos")
    parser.add_argument("--interval", type=int, default=15, help="minutos entre ciclos")
    args = parser.parse_args()
    run_forever(interval_minutes=args.interval)
