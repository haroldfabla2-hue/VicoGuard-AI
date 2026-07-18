"""Publishes an anonymized, aggregated summary of this node's ledger to the
WASP Network hub.

Consent gate: publishing is strictly opt-in via config/node.yaml
(`network.enabled: true`). When disabled (the default), publish_summary
does not perform any network call — it returns a dict flagging that
publishing is disabled instead of failing or silently proceeding. This is
the project's real consent mechanism and must never be bypassed.

Only aggregated severity counts and a denied-actions count leave this node;
no raw finding data (file, line, message, rule_id) is ever sent. See
wasp_network/models.py for the wire format.
"""

from datetime import datetime
from pathlib import Path

import httpx
import yaml

from centinela.ledger import hash_chain

DEFAULT_CONFIG_PATH = "config/node.yaml"
_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        # Fail closed: no config means no consent to publish.
        return {"node_id": "nodo-local", "network": {"enabled": False}}

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _build_summary(node_id: str, team_name: str | None, ledger_path: str) -> dict:
    entries = hash_chain.read_entries(ledger_path=ledger_path)

    severity_counts = {severity: 0 for severity in _SEVERITY_ORDER}
    total_findings = 0
    denied_actions = 0

    for entry in entries:
        entry_type = entry.get("type")
        data = entry.get("data", {})

        if entry_type == "finding":
            total_findings += 1
            severity = data.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        elif entry_type == "denied":
            denied_actions += 1

    return {
        "node_id": node_id,
        "team_name": team_name,
        "severity_counts": severity_counts,
        "total_findings": total_findings,
        "denied_actions": denied_actions,
        "last_updated": datetime.utcnow().isoformat(),
    }


def publish_summary(
    network_url: str,
    node_id: str,
    ledger_path: str = "centinela/data/ledger.jsonl",
    team_name: str | None = None,
    config_path: str = DEFAULT_CONFIG_PATH,
) -> dict:
    """Compute an aggregated NodeSummary from the local ledger and POST it
    to the WASP Network hub — but only if network.enabled is true in
    config/node.yaml.

    Returns the hub's JSON response on success, or a dict with
    {"status": "disabled", ...} when publishing is turned off. Never
    raises on the opt-out path; network/HTTP errors from an enabled
    publish attempt propagate normally (httpx exceptions).
    """
    config = _load_config(config_path)
    network_config = config.get("network") or {}

    if not network_config.get("enabled", False):
        return {
            "status": "disabled",
            "reason": "network publishing is disabled in config/node.yaml (network.enabled: false)",
        }

    summary = _build_summary(node_id, team_name, ledger_path)

    response = httpx.post(f"{network_url}/ingest", json=summary)
    response.raise_for_status()
    return response.json()
