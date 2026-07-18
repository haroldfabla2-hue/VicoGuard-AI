"""MCP server exposing the VicoGuard Red Team toolkit as real MCP tools.

WASP / VicoGuard narrative: the offensive drill toolkit
(``attack_toolkit.py``) is not just a CLI you run by hand during the demo —
it is a real MCP capability (``vicoguard-redteam``) that any MCP client
(Claude Code, the Centinela node, another agent) can call over the MCP
protocol to launch a *controlled* attack drill and forward the resulting
telemetry to VicoGuard's ``/api/v1/telemetry/ingest`` endpoint, so the AI
correlates it and fires the Telegram alert (the "beat" of the demo).

This module wraps ``attack_toolkit`` (imported, not modified) behind one
tool per attack mode. Each tool builds the same argparse-style namespace the
CLI would build, calls the matching ``mode_*`` function, and returns the
generated events plus a forwarding summary as structured JSON.

AUTH: ``/api/v1/telemetry/ingest`` is multi-tenant and requires a session
cookie (``require_user``), so a bare ``api_key`` POST would get a 401. This
server therefore keeps its own authenticated ``requests.Session``: it logs
in with demo credentials (``VICOGUARD_DEMO_EMAIL`` / ``VICOGUARD_DEMO_PASSWORD``),
registering the account on first use, caches the cookie per base URL, and
forwards telemetry with it. We deliberately do *not* add a session-less
telemetry route to the defensive API — that is exactly the class of
vulnerability VicoGuard is meant to catch, and the brain needs a real
tenant to correlate and notify.

SAFETY: the underlying toolkit only permits localhost / private targets
unless ``force=True`` is passed (assuming you have explicit authorization).
That guard is enforced in ``attack_toolkit.guard_target`` and is preserved
here — these tools are for your own decoy / DVWA, not general offense.

Run standalone (stdio transport, for use as a registered MCP server):
    .venv/bin/python redteam/mcp_redteam_server.py
"""

import io
import os
import sys
from contextlib import redirect_stdout
from types import SimpleNamespace

# Resolve paths relative to this file: when registered in .mcp.json, the
# client launches this file directly, so make sure its own directory (which
# holds attack_toolkit.py) is importable regardless of the launch cwd.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from mcp.server.fastmcp import FastMCP  # noqa: E402

import attack_toolkit as tk  # noqa: E402

mcp = FastMCP("vicoguard-redteam")

# Demo credentials for the automatic login/register against VicoGuard.
# The email has a dev-only default (not a secret); the password must come
# from the environment so no credential is ever committed to source.
DEMO_EMAIL = os.environ.get("VICOGUARD_DEMO_EMAIL", "redteam@vicoguard.local")

# One authenticated session per base URL, so we don't re-login every call.
_SESSIONS: dict = {}


def _demo_password() -> str:
    """Return the demo account password from the environment.

    Read at call time (not import time) so nothing sensitive is hardcoded and
    tests can set it via monkeypatch. Raises if unset so the failure is loud
    instead of forwarding with an empty password.
    """
    pw = os.environ.get("VICOGUARD_DEMO_PASSWORD")
    if not pw:
        raise RuntimeError(
            "VICOGUARD_DEMO_PASSWORD no está definida. El reenvío autenticado a "
            "VicoGuard necesita la contraseña de la cuenta demo por entorno "
            "(no se hardcodea ninguna credencial). Expórtala antes de reenviar."
        )
    return pw


# ---------------------------------------------------------------------------
# Authenticated forwarding (the only new logic vs. the CLI)
# ---------------------------------------------------------------------------

def _vicoguard_session(base_url: str):
    """Return a ``requests.Session`` already carrying VicoGuard's session
    cookie, logging in (and registering on first use) with the demo account.

    Cached per ``base_url`` at module level. Raises ``RuntimeError`` if the
    session cannot be established so the caller can surface it in the tool
    result instead of silently forwarding without a cookie (→ 401).
    """
    base = base_url.rstrip("/")
    cached = _SESSIONS.get(base)
    if cached is not None:
        return cached

    import requests  # local import: keeps the module importable without deps

    password = _demo_password()
    s = requests.Session()
    s.headers.update({"User-Agent": "VicoGuard-RedTeam-Drill/1.0"})

    def _logged_in(resp) -> bool:
        return resp.status_code == 200 and bool(s.cookies)

    # Try login first; if the demo account doesn't exist yet, register it
    # (register both creates the account and starts the session).
    login = s.post(f"{base}/api/v1/auth/login",
                   json={"email": DEMO_EMAIL, "password": password}, timeout=15)
    if not _logged_in(login):
        register = s.post(f"{base}/api/v1/auth/register",
                          json={"email": DEMO_EMAIL, "password": password,
                                "full_name": "VicoGuard Red Team", "company": "RedTeam Drill"},
                          timeout=15)
        if not _logged_in(register):
            # Account may already exist (register 400) but login failed too —
            # give login one more chance in case of a transient error.
            login = s.post(f"{base}/api/v1/auth/login",
                           json={"email": DEMO_EMAIL, "password": password}, timeout=15)
            if not _logged_in(login):
                raise RuntimeError(
                    f"No pude autenticar contra VicoGuard en {base} "
                    f"(login={login.status_code}, register={register.status_code}). "
                    "Revisa VICOGUARD_DEMO_EMAIL/PASSWORD y que la API esté levantada."
                )

    _SESSIONS[base] = s
    return s


def _authenticated_forward(base_url: str, events: list, api_key: str) -> dict:
    """Forward ``events`` to VicoGuard's telemetry endpoint using an
    authenticated session, and return the endpoint's response summary
    (status, processed_events, correlation)."""
    if not events:
        return {"forwarded_to": base_url, "event_count": 0, "response": None}

    session = _vicoguard_session(base_url)
    url = base_url.rstrip("/") + tk.TELEMETRY_PATH
    r = session.post(url, json={"api_key": api_key, "events": events}, timeout=30)
    summary = {
        "forwarded_to": url,
        "status_code": r.status_code,
        "event_count": len(events),
    }
    try:
        body = r.json()
        corr = body.get("correlation", {}) or {}
        summary["response"] = {
            "status": body.get("status"),
            "processed_events": body.get("processed_events"),
            "latency_ms": body.get("latency_ms"),
            "overall_status": corr.get("overall_status"),
            "real_threats": len(corr.get("real_threats", [])),
            "threat_summary": corr.get("threat_summary"),
        }
    except Exception:  # noqa: BLE001
        summary["response"] = {"raw": r.text[:500]}
    return summary


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------

def _make_args(**overrides) -> SimpleNamespace:
    """Build the argparse-style namespace the toolkit's mode_* funcs expect.

    Mirrors the defaults declared in ``attack_toolkit.build_parser`` so any
    field a mode reads is always present.
    """
    base = dict(
        mode=None,
        target="http://127.0.0.1:8080",
        forward=None,
        count=20,
        rounds=2,
        delay=0.1,
        api_key=tk.DEFAULT_API_KEY,
        force=False,
        dry_run=False,
        logfile=None,
        no_follow=False,
        batch=10,
        flush_interval=3.0,
        flood_threshold=50,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _run_mode(mode: str, args: SimpleNamespace) -> dict:
    """Run one attack mode, capturing the toolkit's stdout, and return a
    structured result (events + forwarding summary).

    Unlike the CLI's fire-and-forget ``forward_events``, forwarding here goes
    through the authenticated session so the multi-tenant endpoint accepts it,
    and the endpoint's correlation summary is returned in the result.
    """
    fn = tk.MODES[mode]
    buf = io.StringIO()
    forward_result = None
    forward_error = None
    with redirect_stdout(buf):
        events = fn(args)
        # Reproduce the CLI's forwarding step so the demo "beat" still fires
        # when a forward URL is supplied and we're not in dry-run — but via
        # the authenticated session (the endpoint requires a tenant cookie).
        if args.forward and not args.dry_run and events:
            try:
                forward_result = _authenticated_forward(args.forward, events, args.api_key)
            except Exception as e:  # noqa: BLE001
                forward_error = str(e)
    return {
        "mode": mode,
        "target": None if mode in ("synthetic", "tail") else args.target,
        "dry_run": args.dry_run,
        "forwarded_to": args.forward if (args.forward and not args.dry_run) else None,
        "forward_result": forward_result,
        "forward_error": forward_error,
        "event_count": len(events),
        "events": events,
        "log": buf.getvalue().strip(),
    }


# ---------------------------------------------------------------------------
# Tools — one per attack mode
# ---------------------------------------------------------------------------

@mcp.tool()
def synthetic_drill(count: int = 20, forward: str = "", api_key: str = tk.DEFAULT_API_KEY) -> dict:
    """Plan B: fabricate a realistic attack burst WITHOUT touching any host.

    Generates a mixed burst (brute force + port scan + SQLi + benign noise)
    and, if ``forward`` (a VicoGuard base URL like ``http://localhost:8000``)
    is given, ships it to the telemetry endpoint so the AI correlates it and
    fires the alert. This is the network-free demo path — always safe to run.
    """
    args = _make_args(mode="synthetic", count=count, forward=forward or None, api_key=api_key)
    return _run_mode("synthetic", args)


@mcp.tool()
def bruteforce_drill(target: str = "http://127.0.0.1:8080/login", count: int = 20,
                     forward: str = "", api_key: str = tk.DEFAULT_API_KEY,
                     delay: float = 0.1, dry_run: bool = False, force: bool = False) -> dict:
    """Burst of failed logins against ``target`` → BRUTE_FORCE events.

    Only localhost/private targets are allowed unless ``force=True``. Set
    ``dry_run=True`` to generate events without sending any network traffic.
    """
    args = _make_args(mode="bruteforce", target=target, count=count, forward=forward or None,
                      api_key=api_key, delay=delay, dry_run=dry_run, force=force)
    return _run_mode("bruteforce", args)


@mcp.tool()
def sqli_drill(target: str = "http://127.0.0.1:8080/", rounds: int = 2,
               forward: str = "", api_key: str = tk.DEFAULT_API_KEY,
               delay: float = 0.1, dry_run: bool = False, force: bool = False) -> dict:
    """Send classic SQLi payloads to ``target`` → SQLI_ATTEMPT events.

    ``rounds`` repeats the payload set. Localhost/private only unless
    ``force=True``; ``dry_run=True`` skips all network traffic.
    """
    args = _make_args(mode="sqli", target=target, rounds=rounds, forward=forward or None,
                      api_key=api_key, delay=delay, dry_run=dry_run, force=force)
    return _run_mode("sqli", args)


@mcp.tool()
def portscan_drill(target: str = "127.0.0.1", forward: str = "",
                   api_key: str = tk.DEFAULT_API_KEY, dry_run: bool = False,
                   force: bool = False) -> dict:
    """TCP connect scan of common ports on ``target`` → PORT_SCAN events.

    Localhost/private only unless ``force=True``; ``dry_run=True`` fabricates
    the events without opening any sockets.
    """
    args = _make_args(mode="portscan", target=target, forward=forward or None,
                      api_key=api_key, dry_run=dry_run, force=force)
    return _run_mode("portscan", args)


@mcp.tool()
def dirfuzz_drill(target: str = "http://127.0.0.1:8080", forward: str = "",
                  api_key: str = tk.DEFAULT_API_KEY, dry_run: bool = False,
                  force: bool = False) -> dict:
    """Request sensitive paths (/.env, /admin, ...) on ``target`` → DIR_ENUM.

    Localhost/private only unless ``force=True``; ``dry_run=True`` skips the
    network and just emits the events.
    """
    args = _make_args(mode="dirfuzz", target=target, forward=forward or None,
                      api_key=api_key, dry_run=dry_run, force=force)
    return _run_mode("dirfuzz", args)


@mcp.tool()
def flood_drill(target: str = "http://127.0.0.1:8080/", count: int = 20,
                forward: str = "", api_key: str = tk.DEFAULT_API_KEY,
                delay: float = 0.1, dry_run: bool = False, force: bool = False) -> dict:
    """Soft, controlled request flood against ``target`` → HTTP_FLOOD events.

    Localhost/private only unless ``force=True``; ``dry_run=True`` skips all
    network traffic.
    """
    args = _make_args(mode="flood", target=target, count=count, forward=forward or None,
                      api_key=api_key, delay=delay, dry_run=dry_run, force=force)
    return _run_mode("flood", args)


@mcp.tool()
def forward_telemetry(forward: str, events: list, api_key: str = tk.DEFAULT_API_KEY) -> dict:
    """Forward an explicit list of telemetry events to VicoGuard.

    ``forward`` is the VicoGuard base URL (e.g. ``http://localhost:8000``);
    ``events`` is a list of event dicts (as produced by the *_drill tools).
    Useful for replaying a previously generated burst. Uses the authenticated
    session, so the multi-tenant endpoint accepts it.
    """
    try:
        result = _authenticated_forward(forward, events, api_key)
        return {"forward_result": result, "forward_error": None}
    except Exception as e:  # noqa: BLE001
        return {"forward_result": None, "forward_error": str(e)}


if __name__ == "__main__":
    mcp.run()
