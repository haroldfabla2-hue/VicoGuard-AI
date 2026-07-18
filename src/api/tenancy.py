"""
VicoGuard AI — Multi-Tenancy Manager
====================================
Aislamiento FÍSICO por usuario: cada cuenta tiene su propia base de datos SQLite
(`<base_dir>/<user_id>.db`) con su cerebro cognitivo, memoria canónica y scans.

No se filtra por `WHERE user_id` (propenso a fugas): los datos de un usuario
simplemente NO existen en la BD de otro. Imposible mezclar información entre
cuentas o entre clientes de seguridad.

El estado en memoria (scan jobs, último scan) también se mantiene por-usuario.
Los contextos se crean bajo demanda y se cachean.
"""

import os
import threading
from typing import Dict, Optional

from scanner.services.cognitive_brain import CognitiveSecurityBrain
from scanner.services.canonical_memory import CanonicalMemory


class UserContext:
    """Todo el estado de seguridad de UN usuario, aislado del resto."""

    def __init__(self, user_id: str, db_path: str):
        self.user_id = user_id
        self.db_path = db_path
        self.brain = CognitiveSecurityBrain(db_path=db_path)
        self.canonical = CanonicalMemory(db_path=db_path)
        # Estado en memoria por-usuario (no compartido con otras cuentas)
        self.scan_jobs: Dict[str, dict] = {}
        self.latest_scan: dict = {}

    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """Recupera una configuración de la base de datos aislada del usuario."""
        import sqlite3
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS tenant_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                row = conn.execute("SELECT value FROM tenant_settings WHERE key = ?", (key,)).fetchone()
                return row[0] if row else default
        except Exception as e:
            print(f"[!] Error al obtener setting {key}: {e}")
            return default

    def set_setting(self, key: str, value: str):
        """Guarda de forma segura una configuración en la base de datos aislada del usuario."""
        import sqlite3
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS tenant_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.execute("INSERT OR REPLACE INTO tenant_settings (key, value) VALUES (?, ?)", (key, value))
                conn.commit()
        except Exception as e:
            print(f"[!] Error al guardar setting {key}: {e}")
            raise


class TenancyManager:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self._contexts: Dict[str, UserContext] = {}
        self._lock = threading.Lock()

    def get(self, user_id: str) -> UserContext:
        # Doble verificación con lock para que scans concurrentes del mismo
        # usuario compartan el MISMO contexto (y no se pisen dos BDs).
        ctx = self._contexts.get(user_id)
        if ctx is not None:
            return ctx
        with self._lock:
            ctx = self._contexts.get(user_id)
            if ctx is None:
                safe_id = "".join(c for c in user_id if c.isalnum())
                db_path = os.path.join(self.base_dir, f"{safe_id}.db")
                ctx = UserContext(user_id, db_path)
                self._contexts[user_id] = ctx
            return ctx

    def peek(self, user_id: str) -> Optional[UserContext]:
        return self._contexts.get(user_id)
