"""In-memory store of the latest NodeSummary received from each Centinela node.

A module-level dict is intentional and sufficient for a hackathon-scale
network hub (a handful of teams, one process, no persistence requirement
across restarts). Do not add a database here without a real need.
"""

from wasp_network.models import NodeSummary

_nodes: dict[str, NodeSummary] = {}


def upsert_node(summary: NodeSummary) -> None:
    """Insert or replace the summary for a node, keyed by node_id."""
    _nodes[summary.node_id] = summary


def get_all_nodes() -> list[NodeSummary]:
    """Return all known node summaries."""
    return list(_nodes.values())


def get_node(node_id: str) -> NodeSummary | None:
    """Return the summary for a single node, or None if unknown."""
    return _nodes.get(node_id)
