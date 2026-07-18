"""
VicoGuard AI — Authentication & Session Service
===============================================
Cuentas de usuario reales para la plataforma multi-tenant.

Seguridad:
  - Hashing de contraseñas con PBKDF2-HMAC-SHA256 (stdlib, sin deps nativas).
    Formato almacenado: `pbkdf2_sha256$<iters>$<salt_hex>$<hash_hex>`.
  - Sesiones: token aleatorio (secrets.token_urlsafe) enviado en cookie HTTP-only;
    en BD se guarda SOLO su SHA-256 (si roban la BD no pueden reusar la cookie).
  - Cookies: HttpOnly + SameSite=Lax + Path=/ (+ Secure configurable en prod).
  - Comparaciones en tiempo constante (hmac.compare_digest).

La BD global de la app (`vicoguard_app.db`) guarda SOLO usuarios y sesiones.
Los datos de seguridad de cada usuario viven en su propia BD (ver tenancy.py),
por lo que NUNCA se mezclan entre cuentas.
"""

import re
import time
import uuid
import hmac
import hashlib
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Optional

PBKDF2_ITERATIONS = 200_000
SESSION_TTL_SECONDS = 7 * 24 * 3600  # 7 días
SESSION_COOKIE = "vg_session"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class User:
    id: str
    email: str
    full_name: str
    company: str
    created_at: float
    last_login: Optional[float] = None
    status: str = "active"


class AuthError(Exception):
    """Error de autenticación con mensaje apto para el usuario (español)."""

    def __init__(self, message: str, code: str = "auth_error"):
        super().__init__(message)
        self.message = message
        self.code = code


# ── hashing ────────────────────────────────────────────────────────────

def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def _token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# ── service ────────────────────────────────────────────────────────────

class AuthService:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            TEXT PRIMARY KEY,
                    email         TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name     TEXT DEFAULT '',
                    company       TEXT DEFAULT '',
                    created_at    REAL,
                    last_login    REAL,
                    status        TEXT DEFAULT 'active'
                )
            """)
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    created_at REAL,
                    expires_at REAL,
                    user_agent TEXT DEFAULT '',
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
            conn.commit()

    # ── registro / login ──────────────────────────────────────────────
    def register(self, email: str, password: str, full_name: str = "", company: str = "") -> User:
        email = (email or "").strip().lower()
        if not _EMAIL_RE.match(email):
            raise AuthError("El correo no tiene un formato válido.", "invalid_email")
        if len(password or "") < 8:
            raise AuthError("La contraseña debe tener al menos 8 caracteres.", "weak_password")

        now = time.time()
        user_id = uuid.uuid4().hex
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, full_name, company, created_at, status) "
                    "VALUES (?,?,?,?,?,?, 'active')",
                    (user_id, email, hash_password(password), full_name.strip(), company.strip(), now),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            raise AuthError("Ya existe una cuenta con ese correo.", "email_taken")
        return User(id=user_id, email=email, full_name=full_name.strip(),
                    company=company.strip(), created_at=now, status="active")

    def authenticate(self, email: str, password: str) -> User:
        email = (email or "").strip().lower()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        # Verifica siempre (aunque no exista) para no filtrar qué correos existen.
        stored = row["password_hash"] if row else "pbkdf2_sha256$1$00$00"
        if not verify_password(password, stored) or row is None:
            raise AuthError("Correo o contraseña incorrectos.", "bad_credentials")
        if row["status"] != "active":
            raise AuthError("La cuenta está deshabilitada.", "disabled")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), row["id"]))
            conn.commit()
        return self._row_to_user(row)

    # ── sesiones ──────────────────────────────────────────────────────
    def create_session(self, user_id: str, user_agent: str = "") -> str:
        raw = secrets.token_urlsafe(32)
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, user_agent) "
                "VALUES (?,?,?,?,?)",
                (_token_hash(raw), user_id, now, now + SESSION_TTL_SECONDS, (user_agent or "")[:300]),
            )
            conn.commit()
        return raw

    def user_for_token(self, raw_token: Optional[str]) -> Optional[User]:
        if not raw_token:
            return None
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ? AND s.expires_at > ?",
                (_token_hash(raw_token), now),
            ).fetchone()
        return self._row_to_user(row) if row else None

    def destroy_session(self, raw_token: Optional[str]):
        if not raw_token:
            return
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(raw_token),))
            conn.commit()

    def purge_expired_sessions(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            conn.commit()

    def get_user(self, user_id: str) -> Optional[User]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._row_to_user(row) if row else None

    def _row_to_user(self, row) -> User:
        return User(
            id=row["id"], email=row["email"], full_name=row["full_name"] or "",
            company=row["company"] or "", created_at=row["created_at"],
            last_login=row["last_login"], status=row["status"],
        )
