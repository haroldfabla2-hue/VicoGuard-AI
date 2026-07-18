"""Pydantic models for the WASP Network aggregation dashboard.

These models define the ONLY shape of data that crosses the wire between a
Centinela node and the network hub. By design they carry aggregated counts
only — no raw finding data (file, line, message, rule_id) ever appears here.
Do not add such fields; that would violate the project's non-negotiable
anonymization principle (see wasp_network/server.py module docstring).
"""

from pydantic import BaseModel


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class NodeSummary(BaseModel):
    node_id: str
    team_name: str | None = None
    severity_counts: SeverityCounts
    total_findings: int
    denied_actions: int = 0  # count only — no detail on which actions were denied
    last_updated: str  # ISO8601
