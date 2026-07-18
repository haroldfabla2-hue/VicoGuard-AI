"""
VicoGuard AI — Secret Box (cifrado en reposo de secretos por-tenant)
===================================================================
Cifra valores sensibles (p.ej. el bot token de Telegram) antes de guardarlos en
la base de datos del tenant, de modo que el archivo SQLite NO contenga secretos
en texto plano.

- Cifrado simétrico autenticado con Fernet (AES-128-CBC + HMAC-SHA256).
- La clave sale de la env `VG_SECRET_KEY` (derivada con SHA-256) o, si no existe,
  de un archivo persistido `data/.secret_key` generado una sola vez (gitignored).
- `decrypt()` es retro-compatible: si el valor no tiene el prefijo cifrado, lo
  devuelve tal cual (soporta datos antiguos guardados en texto plano).
"""

import os
import base64
import hashlib
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_PREFIX = "enc:v1:"
_SRC_DIR = Path(__file__).resolve().parent.parent
_KEY_PATH = _SRC_DIR / "data" / ".secret_key"


def _load_key() -> bytes:
    env = os.getenv("VG_SECRET_KEY")
    if env:
        # Deriva una clave Fernet válida (32 bytes url-safe base64) del secreto.
        return base64.urlsafe_b64encode(hashlib.sha256(env.encode("utf-8")).digest())
    try:
        _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if _KEY_PATH.exists():
            return _KEY_PATH.read_bytes().strip()
        key = Fernet.generate_key()
        _KEY_PATH.write_bytes(key)
        try:
            os.chmod(_KEY_PATH, 0o600)  # solo el dueño (best-effort en Windows)
        except OSError:
            pass
        return key
    except Exception:
        # Último recurso: clave efímera en memoria (los secretos no persisten).
        return Fernet.generate_key()


_fernet = Fernet(_load_key())


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        return ""
    if plaintext == "":
        return ""
    return _PREFIX + _fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(value: str) -> str:
    if not value:
        return value or ""
    if not value.startswith(_PREFIX):
        return value  # texto plano heredado (retro-compat)
    try:
        return _fernet.decrypt(value[len(_PREFIX):].encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(_PREFIX)
