"""Minimal FastAPI wrapper that exposes the deliberately vulnerable
functions in app.py (get_user, run_diagnostic) as real HTTP endpoints, so
WASP's attack simulator (centinela/attack/simulator.py) can hit them over
the network -- real HTTP requests, not plain Python function calls.

NOT for real use. Deliberately vulnerable. Only for the WASP live demo.

How to start (from the project root, so the "tests" package resolves):

    .venv\\Scripts\\python.exe -m tests.fixtures.vuln_sample_repo.server

Listens on http://127.0.0.1:8899
"""

import os
import sqlite3
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from tests.fixtures.vuln_sample_repo.app import get_user, run_diagnostic

FIXTURE_DIR = Path(__file__).resolve().parent

# get_user() in app.py calls sqlite3.connect("app.db") with a hardcoded,
# *relative* path. We are not allowed to touch app.py, so the only way to
# guarantee that relative path resolves inside this fixture directory
# (instead of wherever the process happens to be launched from) is to
# chdir here, once, before the server starts accepting requests. This is
# a deliberate deviation from the task's suggested filename ("demo.db"):
# app.py's query always opens the literal name "app.db", so the seeded
# demo file has to be named "app.db" for get_user() to actually see it.
os.chdir(FIXTURE_DIR)

DB_PATH = FIXTURE_DIR / "app.db"

DEMO_USERS = [
    (1, "alice", "alice@example.com"),
    (2, "bob", "bob@example.com"),
    (3, "carol", "carol@example.com"),
]


def _init_demo_db() -> None:
    """(Re)create app.db with a small seeded `users` table.

    sqlite3 ":memory:" does not survive across connections, and get_user()
    opens a brand new connection on every call, so a real on-disk file is
    required. Recreated fresh on every server start so the demo is always
    in a known, reproducible state: a normal lookup ("alice") returns one
    row, and a `' OR '1'='1` injection returns all three -- the visual
    proof that the injection worked.
    """
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    conn.executemany(
        "INSERT INTO users (id, username, email) VALUES (?, ?, ?)", DEMO_USERS
    )
    conn.commit()
    conn.close()


_init_demo_db()

app = FastAPI(title="WASP vulnerable demo target")

# Fake, hardcoded, deliberately weak credentials for the brute-force demo.
LOGIN_CREDENTIALS = {
    "admin": "admin123",
    "root": "toor",
}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/user")
def user_endpoint(username: str):
    """Vulnerable to SQL injection via app.get_user() (string concatenation)."""
    try:
        rows = get_user(username)
    except sqlite3.Error as exc:
        # Surfacing the real sqlite error is itself evidence that the raw
        # payload reached the database engine unmodified.
        return {"error": str(exc), "rows": [], "count": 0}
    return {"rows": rows, "count": len(rows)}


@app.get("/ping")
def ping_endpoint(host: str):
    """Vulnerable to OS command injection via app.run_diagnostic() (shell=True)."""
    output = run_diagnostic(host)
    return {"stdout": output.decode("utf-8", errors="replace")}


@app.post("/login")
def login_endpoint(body: LoginRequest):
    """Fake login with weak, hardcoded credentials for the brute-force demo."""
    expected_password = LOGIN_CREDENTIALS.get(body.username)
    success = expected_password is not None and expected_password == body.password
    return {"success": success}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8899)
