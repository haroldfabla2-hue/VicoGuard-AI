"""MCP server exposing the governance guard as a real MCP tool.

WASP Phase 2B narrative: governance is not "just a script" bolted onto a
hook — it is a real MCP capability (`wasp-governor`) that any MCP client
(Claude Code, another agent, a manual test client) can call over the MCP
protocol to ask "is this action allowed under our capability contract?".

This module wraps ``policy.load_contract`` + ``policy.evaluate`` (owned by
another agent, not modified here) behind a single tool, ``check_action``.

The project's PreToolUse hook (``audit_hook.py``) calls ``policy.evaluate``
directly instead of going through this MCP server, purely for hook-response
latency (Claude Code blocks the tool call while the hook runs). This server
is what makes the governance guard verifiable as "real MCP" independent of
that shortcut: it is registered in ``.claude/.mcp.json`` and can be started
and queried like any other MCP server.

Run standalone (stdio transport, for use as a registered MCP server):
    .venv\\Scripts\\python.exe centinela\\guards\\governance_guard\\mcp_governor_server.py
"""

import os
import sys

# Resolve paths relative to this file rather than the process cwd: when
# registered in .claude/.mcp.json, Claude Code launches this file directly
# (python mcp_governor_server.py), so sys.path[0] is this file's own
# directory, not the repo root, and the launch cwd may vary.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP  # noqa: E402

from centinela.guards.governance_guard import policy  # noqa: E402

mcp = FastMCP("wasp-governor")

_CONTRACT_PATH = os.path.join(_PROJECT_ROOT, "capability_contract.yaml")


@mcp.tool()
def check_action(tool: str, command: str) -> dict:
    """Check a proposed action against the WASP capability contract.

    ``tool`` is the name of the tool the agent wants to invoke (e.g.
    ``"Bash"``); ``command`` is the concrete command/argument it wants to
    run. Loads the contract fresh on every call (so edits to
    ``capability_contract.yaml`` take effect without restarting the
    server) and returns ``{"decision": "allow"|"deny", "reason": str}``.
    """
    contract = policy.load_contract(_CONTRACT_PATH)
    action = {"tool": tool, "command": command}
    return policy.evaluate(action, contract)


if __name__ == "__main__":
    mcp.run()
