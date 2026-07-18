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
from api import secretbox

# Claves de configuración que se cifran en reposo (no se guardan en texto plano).
SECRET_SETTING_KEYS = {"telegram_bot_token"}


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
        """Recupera una configuración de la BD aislada del usuario.

        Las claves sensibles (SECRET_SETTING_KEYS) se descifran de forma
        transparente; los valores en texto plano heredados se devuelven tal cual.
        """
        import sqlite3
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS tenant_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                row = conn.execute("SELECT value FROM tenant_settings WHERE key = ?", (key,)).fetchone()
            if not row:
                return default
            value = row[0]
            if key in SECRET_SETTING_KEYS:
                return secretbox.decrypt(value)
            return value
        except Exception as e:
            print(f"[!] Error al obtener setting {key}: {e}")
            return default

    def set_setting(self, key: str, value: str):
        """Guarda una configuración cifrando en reposo las claves sensibles."""
        import sqlite3
        stored = secretbox.encrypt(value) if key in SECRET_SETTING_KEYS else value
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS tenant_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                conn.execute("INSERT OR REPLACE INTO tenant_settings (key, value) VALUES (?, ?)", (key, stored))
                conn.commit()
        except Exception as e:
            print(f"[!] Error al guardar setting {key}: {e}")
            raise

    def get_business_profile(self) -> Optional[dict]:
        """Obtiene el perfil de negocio del usuario desde su BD aislada."""
        import json
        raw = self.get_setting("business_profile")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def set_business_profile(self, profile: dict):
        """Guarda el perfil de negocio en la BD aislada del usuario."""
        import json
        self.set_setting("business_profile", json.dumps(profile, ensure_ascii=False))

    def get_plan(self) -> dict:
        """Obtiene el plan SaaS del usuario y su uso actual."""
        import sqlite3
        plan_name = self.get_setting("saas_plan", "Free")
        limits = {"Free": 5, "Pro": 50, "Enterprise": 9999}
        scans_count = 0
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS scan_history (id TEXT PRIMARY KEY, target TEXT, score INTEGER, findings_count INTEGER, created_at TEXT)")
                row = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()
                if row:
                    scans_count = row[0]
        except Exception:
            pass
        
        limit = limits.get(plan_name, 5)
        return {
            "plan": plan_name,
            "scans_used": scans_count,
            "scans_limit": limit,
            "remaining": max(0, limit - scans_count),
            "features": {
                "telegram_alerts": True,
                "ai_causal_cache": True,
                "continuous_monitoring": plan_name in ("Pro", "Enterprise"),
                "white_label_reports": plan_name == "Enterprise"
            }
        }

    def set_plan(self, plan_name: str):
        """Actualiza el plan del usuario."""
        if plan_name in ("Free", "Pro", "Enterprise"):
            self.set_setting("saas_plan", plan_name)

    def save_scan_history(self, scan_id: str, target: str, score: int, findings_count: int):
        """Guarda un registro ligero en el historial de escaneos para métricas y tendencias."""
        import sqlite3, time
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id TEXT PRIMARY KEY,
                        target TEXT,
                        score INTEGER,
                        findings_count INTEGER,
                        created_at TEXT
                    )
                """)
                conn.execute(
                    "INSERT OR REPLACE INTO scan_history (id, target, score, findings_count, created_at) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, target, score, findings_count, time.strftime("%Y-%m-%d %H:%M:%S"))
                )
                conn.commit()
        except Exception as e:
            print(f"[!] Error guardando historial de escaneo: {e}")

    def get_scan_history(self, limit: int = 15) -> list:
        """Obtiene la lista de escaneos pasados con sus puntuaciones."""
        import sqlite3
        out = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id TEXT PRIMARY KEY,
                        target TEXT,
                        score INTEGER,
                        findings_count INTEGER,
                        created_at TEXT
                    )
                """)
                rows = conn.execute(
                    "SELECT id, target, score, findings_count, created_at FROM scan_history ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                for r in rows:
                    out.append({
                        "id": r[0],
                        "target": r[1],
                        "score": r[2],
                        "findings_count": r[3],
                        "created_at": r[4]
                    })
        except Exception as e:
            print(f"[!] Error obteniendo historial: {e}")
        return out



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
