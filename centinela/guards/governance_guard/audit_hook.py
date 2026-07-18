#!/usr/bin/env python
"""PreToolUse hook: enforces the WASP capability contract on Bash commands.

Claude Code invokes this script as a ``PreToolUse`` hook (matcher: ``Bash``)
before running a Bash command. Schema confirmed against the official docs:

    https://code.claude.com/docs/en/hooks
    (canonical redirect target of https://docs.claude.com/en/docs/claude-code/hooks,
     fetched 2026-07-18)

Input (stdin, JSON): Claude Code writes a JSON object with, among other
fields, ``hook_event_name`` ("PreToolUse"), ``tool_name`` (e.g. "Bash") and
``tool_input`` (an object whose ``command`` field holds the shell command
for the Bash tool):

    {
      "session_id": "...",
      "cwd": "...",
      "hook_event_name": "PreToolUse",
      "tool_name": "Bash",
      "tool_input": {"command": "git push --force origin main"}
    }

Output (stdout, JSON, with exit code 0): the decision is communicated back
to Claude Code as JSON on stdout, nested under ``hookSpecificOutput``:

    {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" | "allow" | "ask",
        "permissionDecisionReason": "<shown to Claude/user>"
      }
    }

``permissionDecision: "deny"`` is what actually blocks execution — it is
not enough to just log the denial to the ledger. Exit code 0 is used in
both allow and deny cases (the JSON payload carries the decision); a
non-zero/uncaught-exception exit would instead fall back to Claude Code's
normal permission flow, which is not what we want for a governance guard.

Production/Phase-2 note: for hook-response latency, this script calls
``policy.evaluate()`` directly instead of going through the ``wasp-governor``
MCP server (see ``mcp_governor_server.py``) over the MCP protocol. In a
later phase, this hook would instead act as an MCP *client*, calling the
``check_action`` tool on the running ``wasp-governor`` server, so that a
single governance service can be shared/audited/scaled independently of
each hook invocation's process lifetime.
"""

import json
import os
import sys
from datetime import datetime, timezone

# Resolve paths relative to this file rather than the process cwd: Claude
# Code invokes this script directly (python audit_hook.py), so sys.path[0]
# is this file's own directory, not the repo root, and it may be launched
# from whatever directory the session was started in. Both the project-root
# import path and the data file paths below are anchored to __file__.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from centinela.guards.governance_guard import policy  # noqa: E402
from centinela.ledger import hash_chain  # noqa: E402

_CONTRACT_PATH = os.path.join(_PROJECT_ROOT, "capability_contract.yaml")
_LEDGER_PATH = os.path.join(_PROJECT_ROOT, "centinela", "data", "ledger.jsonl")


def main() -> int:
    try:
        raw_payload = sys.stdin.read()
        payload = json.loads(raw_payload) if raw_payload.strip() else {}
    except json.JSONDecodeError:
        payload = {}

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command", "") or ""

    action = {"tool": tool_name, "command": command}

    contract = policy.load_contract(_CONTRACT_PATH)
    result = policy.evaluate(action, contract)

    decision = result.get("decision", "allow")
    reason = result.get("reason", "")

    entry_type = "denied" if decision == "deny" else "allowed"
    hash_chain.append(
        entry_type,
        {
            "tool": tool_name,
            "command": command,
            "decision": decision,
            "reason": reason,
            "ts": datetime.now(timezone.utc).isoformat(),
        },
        ledger_path=_LEDGER_PATH,
    )

    permission_decision = "deny" if decision == "deny" else "allow"
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        }
    }

    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
