"""
VicoGuard AI - Causal Security Memory
======================================
Adaptado de causalos-python (github.com/haroldfabla2-hue/causalos-python)
Implementa memoria causal para que el agente de seguridad aprenda de ataques
previos y no necesite llamar al LLM si ya resolvio un patron similar.
"""

import sqlite3
import json
import uuid
import hashlib
import logging
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("vicoguard.causal")


# ═══════════════════════════════════════════
# MODELOS (Adaptados de causalos-python/models.py)
# ═══════════════════════════════════════════

class ThreatSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatType(str, Enum):
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    RLS_DISABLED = "rls_disabled"
    SECRET_EXPOSED = "secret_exposed"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    CRYPTOJACKING = "cryptojacking"
    PORT_SCAN = "port_scan"
    UNKNOWN = "unknown"

class RemediationOutcome(str, Enum):
    SUCCESS = "success"            # El usuario aplico el parche y funciono
    FAILED = "failed"              # El parche no sirvio
    PENDING = "pending"            # Aun no se ha aplicado
    AUTO_APPLIED = "auto_applied"  # VicoGuard lo aplico automaticamente


@dataclass
class CausalSecurityRecord:
    """Registro causal: Ataque detectado -> Remediacion propuesta -> Resultado."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Causa (el ataque/vulnerabilidad)
    threat_type: str = ThreatType.UNKNOWN.value
    threat_fingerprint: str = ""      # Hash del patron de ataque para matching rapido
    threat_detail: str = ""           # Descripcion legible del ataque
    source_ip: Optional[str] = None
    target_url: Optional[str] = None
    severity: str = ThreatSeverity.NONE.value

    # Efecto (la remediacion)
    remediation_command: str = ""     # Comando bash/sql generado
    remediation_explanation: str = "" # Explicacion en lenguaje natural
    outcome: str = RemediationOutcome.PENDING.value

    # Metadata
    llm_model_used: Optional[str] = None  # "gemini-1.5-flash" o "gpt-4o"
    llm_tokens_used: int = 0
    context: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════
# SQLITE STORE (Adaptado de causalos-python/store/sqlite.py)
# ═══════════════════════════════════════════

class CausalSecurityStore:
    """Almacen SQLite WAL optimizado para registros causales de seguridad."""

    def __init__(self, db_path: str = "vicoguard_causal.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS causal_records (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    threat_type TEXT,
                    threat_fingerprint TEXT,
                    threat_detail TEXT,
                    source_ip TEXT,
                    target_url TEXT,
                    severity TEXT,
                    remediation_command TEXT,
                    remediation_explanation TEXT,
                    outcome TEXT,
                    llm_model_used TEXT,
                    llm_tokens_used INTEGER DEFAULT 0,
                    context TEXT DEFAULT '{}',
                    tags TEXT DEFAULT '[]'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fingerprint 
                ON causal_records(threat_fingerprint)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_outcome 
                ON causal_records(outcome)
            """)
            conn.commit()

    def save_record(self, record: CausalSecurityRecord) -> str:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO causal_records 
                (id, timestamp, threat_type, threat_fingerprint, threat_detail,
                 source_ip, target_url, severity, remediation_command,
                 remediation_explanation, outcome, llm_model_used, 
                 llm_tokens_used, context, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.id, record.timestamp, record.threat_type,
                record.threat_fingerprint, record.threat_detail,
                record.source_ip, record.target_url, record.severity,
                record.remediation_command, record.remediation_explanation,
                record.outcome, record.llm_model_used, record.llm_tokens_used,
                json.dumps(record.context), json.dumps(record.tags)
            ))
            conn.commit()
        return record.id

    def recall_by_fingerprint(self, fingerprint: str) -> Optional[CausalSecurityRecord]:
        """Busca una remediacion exitosa previa para el mismo patron de ataque."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM causal_records 
                WHERE threat_fingerprint = ? AND outcome = 'success'
                ORDER BY timestamp DESC LIMIT 1
            """, (fingerprint,)).fetchone()

            if row:
                return CausalSecurityRecord(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    threat_type=row["threat_type"],
                    threat_fingerprint=row["threat_fingerprint"],
                    threat_detail=row["threat_detail"],
                    source_ip=row["source_ip"],
                    target_url=row["target_url"],
                    severity=row["severity"],
                    remediation_command=row["remediation_command"],
                    remediation_explanation=row["remediation_explanation"],
                    outcome=row["outcome"],
                    llm_model_used=row["llm_model_used"],
                    llm_tokens_used=row["llm_tokens_used"],
                    context=json.loads(row["context"] or "{}"),
                    tags=json.loads(row["tags"] or "[]")
                )
            return None

    def update_outcome(self, record_id: str, outcome: RemediationOutcome):
        """El usuario reporta si la remediacion funciono o no."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE causal_records SET outcome = ? WHERE id = ?",
                (outcome.value, record_id)
            )
            conn.commit()

    def get_stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM causal_records").fetchone()[0]
            successes = conn.execute(
                "SELECT COUNT(*) FROM causal_records WHERE outcome = 'success'"
            ).fetchone()[0]
            cache_hits = conn.execute(
                "SELECT COUNT(*) FROM causal_records WHERE llm_tokens_used = 0"
            ).fetchone()[0]
            tokens_saved = conn.execute(
                "SELECT SUM(llm_tokens_used) FROM causal_records WHERE outcome = 'success'"
            ).fetchone()[0] or 0
        return {
            "total_records": total,
            "successful_remediations": successes,
            "cache_hits": cache_hits,
            "estimated_tokens_saved": tokens_saved * cache_hits
        }


# ═══════════════════════════════════════════
# CAUSAL MEMORY ENGINE (Motor principal)
# ═══════════════════════════════════════════

class CausalSecurityMemory:
    """
    Motor de memoria causal para VicoGuard AI.
    Decide si llamar al LLM o reutilizar una solucion previa.
    """

    def __init__(self, db_path: str = "vicoguard_causal.db"):
        self.store = CausalSecurityStore(db_path)

    @staticmethod
    def compute_fingerprint(threat_type: str, threat_detail: str) -> str:
        """
        Genera un hash determinista del patron de ataque.
        Normaliza el detalle para que variaciones menores 
        (como IPs diferentes) no cambien el fingerprint.
        """
        # Remover IPs, timestamps y numeros especificos del detalle
        import re
        normalized = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '<IP>', threat_detail)
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', normalized)
        normalized = re.sub(r'\d{2}:\d{2}:\d{2}', '<TIME>', normalized)
        normalized = normalized.lower().strip()

        raw = f"{threat_type}:{normalized}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def process_threat(
        self,
        threat_type: ThreatType,
        threat_detail: str,
        severity: ThreatSeverity,
        source_ip: Optional[str] = None,
        target_url: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Punto de entrada principal. Decide si usar cache o LLM.
        Retorna: {
            "source": "cache" | "llm",
            "record": CausalSecurityRecord,
            "latency_ms": int
        }
        """
        import time
        start = time.time()

        fingerprint = self.compute_fingerprint(threat_type.value, threat_detail)

        # PASO 1: Buscar en memoria causal (cache hit)
        cached = self.store.recall_by_fingerprint(fingerprint)
        if cached:
            logger.info(f"[CACHE HIT] Patron conocido: {fingerprint}. Reutilizando remediacion.")
            elapsed = int((time.time() - start) * 1000)
            return {
                "source": "cache",
                "record": cached,
                "latency_ms": elapsed,
                "tokens_used": 0
            }

        # PASO 2: No hay cache -> crear registro pendiente para el LLM
        logger.info(f"[CACHE MISS] Patron nuevo: {fingerprint}. Requiere LLM.")
        new_record = CausalSecurityRecord(
            threat_type=threat_type.value,
            threat_fingerprint=fingerprint,
            threat_detail=threat_detail,
            source_ip=source_ip,
            target_url=target_url,
            severity=severity.value,
            context=context or {},
            tags=[threat_type.value, severity.value]
        )

        elapsed = int((time.time() - start) * 1000)
        return {
            "source": "llm_required",
            "record": new_record,
            "latency_ms": elapsed,
            "tokens_used": -1  # Pendiente
        }

    def save_with_remediation(
        self,
        record: CausalSecurityRecord,
        remediation_command: str,
        remediation_explanation: str,
        llm_model: str = "gemini-1.5-flash",
        tokens_used: int = 0
    ) -> str:
        """Guarda el registro completo despues de que el LLM genero la remediacion."""
        record.remediation_command = remediation_command
        record.remediation_explanation = remediation_explanation
        record.llm_model_used = llm_model
        record.llm_tokens_used = tokens_used
        return self.store.save_record(record)

    def mark_success(self, record_id: str):
        """El usuario confirma que la remediacion funciono -> se cachea para futuro."""
        self.store.update_outcome(record_id, RemediationOutcome.SUCCESS)
        logger.info(f"[LEARNED] Record {record_id} marcado como exitoso. Se cacheara.")

    def mark_failed(self, record_id: str):
        """La remediacion no funciono -> no se cacheara."""
        self.store.update_outcome(record_id, RemediationOutcome.FAILED)
        logger.info(f"[FAILED] Record {record_id} marcado como fallido. Se regenerara.")


if __name__ == "__main__":
    # Quick test
    memory = CausalSecurityMemory(db_path="test_causal.db")

    # Simular un ataque de fuerza bruta
    result = memory.process_threat(
        threat_type=ThreatType.BRUTE_FORCE,
        threat_detail="500 intentos fallidos de login desde 185.234.72.15 en /admin/login en 60 segundos",
        severity=ThreatSeverity.HIGH,
        source_ip="185.234.72.15",
        target_url="https://mi-app.com/admin/login"
    )
    print(f"Primera vez: source={result['source']}, latency={result['latency_ms']}ms")

    # Guardar remediacion del LLM
    record = result["record"]
    memory.save_with_remediation(
        record,
        remediation_command="sudo ufw deny from 185.234.72.15",
        remediation_explanation="Bloquea la IP atacante en el firewall del servidor",
        tokens_used=150
    )
    memory.mark_success(record.id)

    # Simular el MISMO ataque desde otra IP
    result2 = memory.process_threat(
        threat_type=ThreatType.BRUTE_FORCE,
        threat_detail="500 intentos fallidos de login desde 91.108.56.200 en /admin/login en 60 segundos",
        severity=ThreatSeverity.HIGH,
        source_ip="91.108.56.200"
    )
    print(f"Segunda vez: source={result2['source']}, latency={result2['latency_ms']}ms")
    if result2["source"] == "cache":
        print(f"   Remediacion cacheada: {result2['record'].remediation_command}")

    # Stats
    stats = memory.store.get_stats()
    print(f"Stats: {stats}")

    # Cleanup
    import os
    os.remove("test_causal.db")
