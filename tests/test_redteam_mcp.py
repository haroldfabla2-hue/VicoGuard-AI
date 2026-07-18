"""Tests for the ``vicoguard-redteam`` MCP server and its toolkit.

These tests never touch the network: they only exercise the offensive
toolkit's local event generation, the security guard, and the MCP tool
registration. The authenticated-forwarding path (login + telemetry POST)
requires the defensive API running and is covered by the manual
end-to-end verification in ``redteam/README.md``, not here.
"""

import asyncio

import pytest

from redteam import attack_toolkit as tk
from redteam import mcp_redteam_server as srv


# ---------------------------------------------------------------------------
# MCP tool registration
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = {
    "synthetic_drill", "bruteforce_drill", "sqli_drill", "portscan_drill",
    "dirfuzz_drill", "flood_drill", "forward_telemetry",
}


def test_all_seven_tools_registered():
    tools = asyncio.run(srv.mcp.list_tools())
    names = {t.name for t in tools}
    assert EXPECTED_TOOLS <= names, f"faltan tools: {EXPECTED_TOOLS - names}"


# ---------------------------------------------------------------------------
# Event shape (what /api/v1/telemetry/ingest reads)
# ---------------------------------------------------------------------------

REQUIRED_KEYS = {"timestamp", "type", "source_ip", "status_code", "path"}


def test_synthetic_drill_event_shape_and_mix():
    result = srv.synthetic_drill(count=5)
    events = result["events"]

    assert result["mode"] == "synthetic"
    assert result["forwarded_to"] is None  # no forward URL given
    assert events, "synthetic debe generar eventos"
    for ev in events:
        assert REQUIRED_KEYS <= set(ev), f"evento sin claves requeridas: {ev}"

    types = {ev["type"] for ev in events}
    # Mezcla amenazas reales con ruido benigno (HTTP_REQUEST) para que la IA
    # demuestre que filtra lo real del ruido.
    assert {"BRUTE_FORCE", "PORT_SCAN", "SQLI_ATTEMPT"} <= types
    assert "HTTP_REQUEST" in types


@pytest.mark.parametrize("tool,mode", [
    (srv.bruteforce_drill, "bruteforce"),
    (srv.sqli_drill, "sqli"),
    (srv.portscan_drill, "portscan"),
    (srv.dirfuzz_drill, "dirfuzz"),
    (srv.flood_drill, "flood"),
])
def test_drills_dry_run_generate_events_without_network(tool, mode):
    # dry_run=True must never touch the network but still produce events.
    result = tool(dry_run=True)
    assert result["mode"] == mode
    assert result["dry_run"] is True
    assert result["forwarded_to"] is None
    assert result["forward_result"] is None
    assert result["event_count"] > 0
    for ev in result["events"]:
        assert REQUIRED_KEYS <= set(ev)


# ---------------------------------------------------------------------------
# Security guard — scope discipline
# ---------------------------------------------------------------------------

def test_guard_allows_localhost_and_private():
    # No exception / no exit for local + private targets.
    tk.guard_target("http://127.0.0.1:8080/login", force=False)
    tk.guard_target("http://10.0.0.5/", force=False)


def test_guard_blocks_external_target_without_force():
    with pytest.raises(SystemExit):
        tk.guard_target("http://example.com/", force=False)


def test_drill_against_external_target_is_rejected():
    # A public target without force=True must be blocked by the guard,
    # surfacing as SystemExit before any traffic is generated.
    with pytest.raises(SystemExit):
        srv.bruteforce_drill(target="http://example.com/login", dry_run=True, force=False)
