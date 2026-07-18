"""
VicoGuard AI - Cognitive Security Brain
========================================
Fusion del ecosistema completo de Silhouette:

  1. silhouette-brain v3  → 4-Tier Memory (Working→Episodic→Semantic→Deep)
  2. causalos-python      → Causal chains (Ataque→Remediacion→Outcome)
  3. silhouette-mcp       → Security Team orchestration
  4. Agency OS            → Context Engine (4 niveles de contexto)

Este modulo unifica TODO en un solo CognitiveSecurityBrain que:
  - Recuerda ataques pasados y sus soluciones exitosas
  - Consolida patrones en un grafo de amenazas
  - Tiene 4 capas de memoria como el cerebro humano
  - Aprende de cada interaccion (feedback loop)
"""

import sqlite3
import json
import uuid
import hashlib
import time
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("vicoguard.brain")


# ══════════════════════════════════════════════════════════════
# TIER 1: MODELOS (adaptados de silhouette-brain/models.py)
# ══════════════════════════════════════════════════════════════

class MemoryTier(str, Enum):
    """Las 4 capas de memoria del cerebro de seguridad."""
    WORKING = "working"      # Cache inmediato (ultimos 5 min)
    EPISODIC = "episodic"    # Eventos recientes (ultimas 24h)
    SEMANTIC = "semantic"    # Busqueda por similitud (vectores)
    DEEP = "deep"            # Grafo de conocimiento permanente


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
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


class RemediationOutcome(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    AUTO_APPLIED = "auto_applied"


@dataclass
class SecurityMemoryRecord:
    """Unidad atomica de memoria de seguridad (inspirado en MemoryRecord de silhouette-brain)."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    content: str = ""
    tier: str = MemoryTier.WORKING.value
    importance: float = 0.5          # 0.0 - 1.0
    tags: List[str] = field(default_factory=list)
    source: str = "scanner"
    created_at: float = field(default_factory=time.time)
    last_access: float = field(default_factory=time.time)
    access_count: int = 0

    # Campos especificos de seguridad
    threat_type: str = ThreatType.UNKNOWN.value
    threat_fingerprint: str = ""
    severity: str = ThreatSeverity.NONE.value
    source_ip: Optional[str] = None
    target_url: Optional[str] = None

    # Remediacion asociada
    remediation_command: str = ""
    remediation_explanation: str = ""
    outcome: str = RemediationOutcome.PENDING.value

    # LLM tracking
    llm_model_used: Optional[str] = None
    llm_tokens_used: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def touch(self):
        """Marca acceso (patron de silhouette-brain)."""
        self.last_access = time.time()
        self.access_count += 1


@dataclass
class ThreatEntity:
    """Entidad en el grafo de amenazas (adaptado de Entity de silhouette-brain)."""
    name: str                        # IP, URL, tipo de ataque, etc.
    type: str = "threat"             # "ip", "url", "attack_type", "vulnerability"
    mention_count: int = 1
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatRelationship:
    """Relacion en el grafo de amenazas (adaptado de Relationship)."""
    source: str                      # Entidad origen
    target: str                      # Entidad destino
    type: str = "ATTACKS"            # "ATTACKS", "TARGETS", "REMEDIATES", "CO_OCCURRENCE"
    weight: float = 1.0             # Fortaleza de la relacion
    metadata: Dict[str, Any] = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════
# TIER 2: WORKING MEMORY (adaptado de silhouette-brain/working.py)
# ══════════════════════════════════════════════════════════════

class WorkingSecurityMemory:
    """Memoria de trabajo - cache LRU de los ultimos N eventos.
    Inspirado en WorkingMemory de silhouette-brain pero para seguridad."""

    def __init__(self, max_items: int = 100, ttl_seconds: int = 300):
        self.max_items = max_items
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, SecurityMemoryRecord] = {}

    def put(self, record: SecurityMemoryRecord):
        record.tier = MemoryTier.WORKING.value
        self._evict_expired()
        if len(self._cache) >= self.max_items:
            oldest_key = min(self._cache, key=lambda k: self._cache[k].last_access)
            del self._cache[oldest_key]
        self._cache[record.id] = record

    def get(self, record_id: str) -> Optional[SecurityMemoryRecord]:
        rec = self._cache.get(record_id)
        if rec:
            rec.touch()
        return rec

    def get_recent(self, n: int = 10) -> List[SecurityMemoryRecord]:
        self._evict_expired()
        items = sorted(self._cache.values(), key=lambda r: r.created_at, reverse=True)
        return items[:n]

    def _evict_expired(self):
        cutoff = time.time() - self.ttl_seconds
        expired = [k for k, v in self._cache.items() if v.created_at < cutoff]
        for k in expired:
            del self._cache[k]

    @property
    def size(self) -> int:
        return len(self._cache)


# ══════════════════════════════════════════════════════════════
# TIER 3: EPISODIC STORE (adaptado de silhouette-brain/episodic.py)
# ══════════════════════════════════════════════════════════════

class EpisodicSecurityStore:
    """Almacen episodico - eventos recientes persistidos en SQLite.
    Adaptado de EpisodicStore de silhouette-brain."""

    def __init__(self, db_path: str = "vicoguard_brain.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS episodic_memories (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    importance REAL DEFAULT 0.5,
                    tags TEXT DEFAULT '[]',
                    source TEXT DEFAULT 'scanner',
                    created_at REAL,
                    last_access REAL,
                    access_count INTEGER DEFAULT 0,
                    threat_type TEXT,
                    threat_fingerprint TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    target_url TEXT,
                    remediation_command TEXT DEFAULT '',
                    remediation_explanation TEXT DEFAULT '',
                    outcome TEXT DEFAULT 'pending',
                    llm_model_used TEXT,
                    llm_tokens_used INTEGER DEFAULT 0,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ep_fingerprint ON episodic_memories(threat_fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ep_created ON episodic_memories(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ep_outcome ON episodic_memories(outcome)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ep_severity ON episodic_memories(severity)")
            conn.commit()

    def add(self, record: SecurityMemoryRecord):
        record.tier = MemoryTier.EPISODIC.value
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO episodic_memories 
                (id, content, importance, tags, source, created_at, last_access,
                 access_count, threat_type, threat_fingerprint, severity,
                 source_ip, target_url, remediation_command, remediation_explanation,
                 outcome, llm_model_used, llm_tokens_used, metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                record.id, record.content, record.importance,
                json.dumps(record.tags), record.source, record.created_at,
                record.last_access, record.access_count, record.threat_type,
                record.threat_fingerprint, record.severity, record.source_ip,
                record.target_url, record.remediation_command,
                record.remediation_explanation, record.outcome,
                record.llm_model_used, record.llm_tokens_used,
                json.dumps(record.metadata)
            ))
            conn.commit()

    def recent(self, hours: float = 24.0, limit: int = 20) -> List[SecurityMemoryRecord]:
        cutoff = time.time() - (hours * 3600)
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM episodic_memories 
                WHERE created_at > ? ORDER BY created_at DESC LIMIT ?
            """, (cutoff, limit)).fetchall()
            return [self._row_to_record(r) for r in rows]

    def recall_by_fingerprint(self, fingerprint: str) -> Optional[SecurityMemoryRecord]:
        """Busca la remediacion exitosa mas reciente para un patron de ataque."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM episodic_memories 
                WHERE threat_fingerprint = ? AND outcome = 'success'
                ORDER BY created_at DESC LIMIT 1
            """, (fingerprint,)).fetchone()
            return self._row_to_record(row) if row else None

    def update_outcome(self, record_id: str, outcome: RemediationOutcome):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE episodic_memories SET outcome = ? WHERE id = ?",
                        (outcome.value, record_id))
            conn.commit()

    def all(self, limit: int = 500) -> List[SecurityMemoryRecord]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM episodic_memories ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [self._row_to_record(r) for r in rows]

    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM episodic_memories").fetchone()[0]

    def _row_to_record(self, row) -> SecurityMemoryRecord:
        return SecurityMemoryRecord(
            id=row["id"], content=row["content"], importance=row["importance"],
            tags=json.loads(row["tags"] or "[]"), source=row["source"],
            created_at=row["created_at"], last_access=row["last_access"],
            access_count=row["access_count"], threat_type=row["threat_type"],
            threat_fingerprint=row["threat_fingerprint"], severity=row["severity"],
            source_ip=row["source_ip"], target_url=row["target_url"],
            remediation_command=row["remediation_command"],
            remediation_explanation=row["remediation_explanation"],
            outcome=row["outcome"], llm_model_used=row["llm_model_used"],
            llm_tokens_used=row["llm_tokens_used"],
            metadata=json.loads(row["metadata"] or "{}")
        )


# ══════════════════════════════════════════════════════════════
# TIER 4: DEEP GRAPH (adaptado de silhouette-brain/graph.py)
# ══════════════════════════════════════════════════════════════

class ThreatGraphStore:
    """Grafo de amenazas en SQLite (version ligera de SqliteGraphStore de silhouette-brain).
    Almacena entidades (IPs, URLs, tipos de ataque) y sus relaciones."""

    def __init__(self, db_path: str = "vicoguard_brain.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_entities (
                    name TEXT PRIMARY KEY,
                    type TEXT DEFAULT 'threat',
                    mention_count INTEGER DEFAULT 1,
                    first_seen REAL,
                    last_seen REAL,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_relationships (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    type TEXT DEFAULT 'RELATED_TO',
                    weight REAL DEFAULT 1.0,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY(source) REFERENCES threat_entities(name),
                    FOREIGN KEY(target) REFERENCES threat_entities(name)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON threat_relationships(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON threat_relationships(target)")
            conn.commit()

    def upsert_entity(self, entity: ThreatEntity):
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT mention_count FROM threat_entities WHERE name = ?",
                                   (entity.name,)).fetchone()
            if existing:
                conn.execute("""
                    UPDATE threat_entities SET mention_count = mention_count + 1,
                    last_seen = ?, metadata = ? WHERE name = ?
                """, (now, json.dumps(entity.metadata), entity.name))
            else:
                conn.execute("""
                    INSERT INTO threat_entities (name, type, mention_count, first_seen, last_seen, metadata)
                    VALUES (?, ?, 1, ?, ?, ?)
                """, (entity.name, entity.type, now, now, json.dumps(entity.metadata)))
            conn.commit()

    def add_relationship(self, rel: ThreatRelationship):
        with sqlite3.connect(self.db_path) as conn:
            # Reforzar edge existente o crear nuevo
            existing = conn.execute("""
                SELECT id, weight FROM threat_relationships 
                WHERE source = ? AND target = ? AND type = ?
            """, (rel.source, rel.target, rel.type)).fetchone()
            if existing:
                new_weight = existing[1] + rel.weight
                conn.execute("UPDATE threat_relationships SET weight = ? WHERE id = ?",
                           (new_weight, existing[0]))
            else:
                rel_id = uuid.uuid4().hex[:12]
                conn.execute("""
                    INSERT INTO threat_relationships (id, source, target, type, weight, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (rel_id, rel.source, rel.target, rel.type, rel.weight,
                      json.dumps(rel.metadata)))
            conn.commit()

    def neighbors(self, name: str, limit: int = 20) -> List[ThreatRelationship]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM threat_relationships 
                WHERE source = ? OR target = ? ORDER BY weight DESC LIMIT ?
            """, (name, name, limit)).fetchall()
            return [ThreatRelationship(
                source=r["source"], target=r["target"],
                type=r["type"], weight=r["weight"]
            ) for r in rows]

    def entities(self, limit: int = 50, etype: Optional[str] = None) -> List[ThreatEntity]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if etype:
                rows = conn.execute("SELECT * FROM threat_entities WHERE type = ? ORDER BY mention_count DESC LIMIT ?",
                                   (etype, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM threat_entities ORDER BY mention_count DESC LIMIT ?",
                                   (limit,)).fetchall()
            return [ThreatEntity(name=r["name"], type=r["type"], mention_count=r["mention_count"])
                    for r in rows]

    def top_attackers(self, limit: int = 10) -> List[ThreatEntity]:
        return self.entities(limit=limit, etype="ip")

    def stats(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            entities_count = conn.execute("SELECT COUNT(*) FROM threat_entities").fetchone()[0]
            relations_count = conn.execute("SELECT COUNT(*) FROM threat_relationships").fetchone()[0]
            return {"entities": entities_count, "relationships": relations_count}


# ══════════════════════════════════════════════════════════════
# COGNITIVE ENGINE: DREAMER (adaptado de silhouette-brain/dreamer.py)
# ══════════════════════════════════════════════════════════════

class SecurityDreamerEngine:
    """Motor cognitivo que consolida eventos episodicos en el grafo profundo.
    Adaptado del DreamerEngine de silhouette-brain.
    Ejecutar en periodos de baja actividad (ej: cada hora)."""

    name = "security_dreamer"

    def execute(self, episodic: EpisodicSecurityStore, graph: ThreatGraphStore) -> Dict:
        records = episodic.all(limit=500)
        consolidated = 0
        edges_added = 0

        for record in records:
            if record.importance < 0.3:
                continue

            # Extraer entidades del registro
            entities = self._extract_threat_entities(record)
            for entity in entities:
                graph.upsert_entity(entity)

            # Crear relaciones entre entidades co-mencionadas
            names = [e.name for e in entities]
            for i, a in enumerate(names):
                for b in names[i + 1:]:
                    graph.add_relationship(ThreatRelationship(
                        source=a, target=b, type="CO_OCCURRENCE",
                        weight=0.5 + record.importance
                    ))
                    edges_added += 1

            consolidated += 1

        return {
            "engine": self.name,
            "consolidated": consolidated,
            "edges_added": edges_added
        }

    def _extract_threat_entities(self, record: SecurityMemoryRecord) -> List[ThreatEntity]:
        """Extrae entidades de un registro de seguridad."""
        entities = []
        if record.source_ip:
            entities.append(ThreatEntity(name=record.source_ip, type="ip"))
        if record.target_url:
            entities.append(ThreatEntity(name=record.target_url, type="url"))
        if record.threat_type and record.threat_type != ThreatType.UNKNOWN.value:
            entities.append(ThreatEntity(name=record.threat_type, type="attack_type"))
        return entities


# ══════════════════════════════════════════════════════════════
# UNIFIED BRAIN: CognitiveSecurityBrain
# ══════════════════════════════════════════════════════════════

class CognitiveSecurityBrain:
    """
    El cerebro cognitivo de VicoGuard AI.
    Unifica las 4 capas de memoria + motor causal + grafo de amenazas.

    Flujo principal:
        1. INGEST: receive_threat() → Working → Episodic → Graph
        2. RECALL: Ya vimos esto antes? → Causal cache hit (0ms) o LLM call (2s)
        3. LEARN:  Feedback del usuario → mark_success/mark_failed
        4. DREAM:  consolidate() → Dreamer engine → Grafo profundo

    Uso:
        brain = CognitiveSecurityBrain("vicoguard.db")
        result = brain.receive_threat(ThreatType.BRUTE_FORCE, "500 logins...", ThreatSeverity.HIGH)
        if result["source"] == "cache":
            send_telegram(result["record"].remediation_command)
        else:
            remediation = call_llm(result["record"].content)
            brain.save_remediation(result["record"], remediation)
    """

    def __init__(self, db_path: str = "vicoguard_brain.db"):
        self.db_path = db_path
        self.working = WorkingSecurityMemory(max_items=100, ttl_seconds=300)
        self.episodic = EpisodicSecurityStore(db_path)
        self.graph = ThreatGraphStore(db_path)
        self.dreamer = SecurityDreamerEngine()
        logger.info(f"CognitiveSecurityBrain initialized (db={db_path})")

    @staticmethod
    def compute_fingerprint(threat_type: str, detail: str) -> str:
        """Hash determinista del patron de ataque, normalizando IPs y timestamps."""
        import re
        normalized = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '<IP>', detail)
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}', '<DATE>', normalized)
        normalized = re.sub(r'\d{2}:\d{2}:\d{2}', '<TIME>', normalized)
        normalized = normalized.lower().strip()
        return hashlib.sha256(f"{threat_type}:{normalized}".encode()).hexdigest()[:16]

    def receive_threat(
        self,
        threat_type: ThreatType,
        detail: str,
        severity: ThreatSeverity,
        source_ip: Optional[str] = None,
        target_url: Optional[str] = None,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Punto de entrada principal. Decide si usar cache o necesita LLM."""
        start = time.time()
        fingerprint = self.compute_fingerprint(threat_type.value, detail)

        # 1. Buscar en causal cache (episodic con outcome=success)
        cached = self.episodic.recall_by_fingerprint(fingerprint)
        if cached:
            cached.touch()
            elapsed_ms = int((time.time() - start) * 1000)
            logger.info(f"[CACHE HIT] {fingerprint} → {elapsed_ms}ms")
            return {
                "source": "cache",
                "record": cached,
                "latency_ms": elapsed_ms,
                "tokens_used": 0
            }

        # 2. Cache miss → crear nuevo registro
        record = SecurityMemoryRecord(
            content=detail,
            importance=self._severity_to_importance(severity),
            tags=[threat_type.value, severity.value],
            source="scanner",
            threat_type=threat_type.value,
            threat_fingerprint=fingerprint,
            severity=severity.value,
            source_ip=source_ip,
            target_url=target_url,
            metadata=context or {}
        )

        # Ingestar en Working
        self.working.put(record)

        elapsed_ms = int((time.time() - start) * 1000)
        logger.info(f"[CACHE MISS] {fingerprint} → requiere LLM ({elapsed_ms}ms)")
        return {
            "source": "llm_required",
            "record": record,
            "latency_ms": elapsed_ms,
            "tokens_used": -1
        }

    def save_remediation(
        self,
        record: SecurityMemoryRecord,
        command: str,
        explanation: str,
        model: str = "gemini-2.0-flash",
        tokens: int = 0
    ) -> str:
        """Guarda la remediacion generada por el LLM y la persiste."""
        record.remediation_command = command
        record.remediation_explanation = explanation
        record.llm_model_used = model
        record.llm_tokens_used = tokens
        record.outcome = RemediationOutcome.PENDING.value

        # Persistir en episodic
        self.episodic.add(record)

        # Proyectar al grafo
        self._project_to_graph(record)

        return record.id

    def mark_success(self, record_id: str):
        """El usuario confirma que funciono → se cachea para futuro."""
        self.episodic.update_outcome(record_id, RemediationOutcome.SUCCESS)

    def mark_failed(self, record_id: str):
        """No funciono → no se cacheara, se regenerara."""
        self.episodic.update_outcome(record_id, RemediationOutcome.FAILED)

    def consolidate(self) -> Dict:
        """Ejecuta el Dreamer Engine para consolidar memoria episodica en grafo."""
        return self.dreamer.execute(self.episodic, self.graph)

    def get_context(self, query: str = "") -> Dict:
        """Ensamblador de contexto (inspirado en context_engine.py de Agency OS).
        Devuelve un paquete de contexto con las 4 capas."""
        return {
            "query": query,
            "working": [asdict(r) for r in self.working.get_recent(5)],
            "recent_episodes": [asdict(r) for r in self.episodic.recent(hours=24, limit=10)],
            "top_attackers": [asdict(e) for e in self.graph.top_attackers(5)],
            "graph_stats": self.graph.stats(),
            "total_memories": self.episodic.count(),
            "working_memory_size": self.working.size
        }

    def get_stats(self) -> Dict:
        """Dashboard general del cerebro."""
        graph_stats = self.graph.stats()
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM episodic_memories").fetchone()[0]
            successes = conn.execute(
                "SELECT COUNT(*) FROM episodic_memories WHERE outcome = 'success'"
            ).fetchone()[0]
            cache_eligible = successes
            tokens_total = conn.execute(
                "SELECT COALESCE(SUM(llm_tokens_used), 0) FROM episodic_memories"
            ).fetchone()[0]
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM episodic_memories WHERE severity = 'critical'"
            ).fetchone()[0]
        return {
            "total_memories": total,
            "successful_remediations": successes,
            "cache_eligible": cache_eligible,
            "total_llm_tokens_used": tokens_total,
            "estimated_tokens_saved": tokens_total * cache_eligible,
            "critical_threats": critical_count,
            "graph_entities": graph_stats["entities"],
            "graph_relationships": graph_stats["relationships"],
            "working_memory_size": self.working.size
        }

    def _severity_to_importance(self, severity: ThreatSeverity) -> float:
        return {
            ThreatSeverity.NONE: 0.1,
            ThreatSeverity.LOW: 0.3,
            ThreatSeverity.MEDIUM: 0.5,
            ThreatSeverity.HIGH: 0.8,
            ThreatSeverity.CRITICAL: 1.0
        }.get(severity, 0.5)

    def _project_to_graph(self, record: SecurityMemoryRecord):
        """Proyecta un registro al grafo de amenazas."""
        entities = self.dreamer._extract_threat_entities(record)
        for entity in entities:
            self.graph.upsert_entity(entity)
        names = [e.name for e in entities]
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                self.graph.add_relationship(ThreatRelationship(
                    source=a, target=b, type="CO_OCCURRENCE",
                    weight=0.5 + record.importance
                ))


# ══════════════════════════════════════════════════════════════
# DEMO / TEST
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    DB = "test_brain_demo.db"

    brain = CognitiveSecurityBrain(DB)

    print("=" * 60)
    print("DEMO: CognitiveSecurityBrain de VicoGuard AI")
    print("=" * 60)

    # 1. Primer ataque de fuerza bruta
    print("\n[1] Procesando ataque de fuerza bruta...")
    r1 = brain.receive_threat(
        ThreatType.BRUTE_FORCE,
        "500 intentos fallidos de login desde 45.33.49.12 en /admin/login en 60 segundos",
        ThreatSeverity.HIGH,
        source_ip="45.33.49.12",
        target_url="https://mi-app.com/admin/login"
    )
    print(f"   Source: {r1['source']}, Latency: {r1['latency_ms']}ms")

    # Guardar remediacion del LLM
    brain.save_remediation(
        r1["record"],
        command="sudo ufw deny from 45.33.49.12",
        explanation="Bloquea la IP atacante en el firewall del servidor",
        tokens=150
    )
    brain.mark_success(r1["record"].id)
    print("   Remediacion guardada y marcada como exitosa")

    # 2. MISMO ataque, diferente IP → CACHE HIT
    print("\n[2] Procesando MISMO patron desde otra IP...")
    r2 = brain.receive_threat(
        ThreatType.BRUTE_FORCE,
        "500 intentos fallidos de login desde 91.108.56.200 en /admin/login en 60 segundos",
        ThreatSeverity.HIGH,
        source_ip="91.108.56.200"
    )
    print(f"   Source: {r2['source']}, Latency: {r2['latency_ms']}ms")
    if r2["source"] == "cache":
        print(f"   Remediacion cacheada: {r2['record'].remediation_command}")
        print(f"   Tokens ahorrados: ~150")

    # 3. RLS deshabilitado
    print("\n[3] Procesando vulnerabilidad RLS...")
    r3 = brain.receive_threat(
        ThreatType.RLS_DISABLED,
        "Row Level Security deshabilitado en tabla 'users' de Supabase",
        ThreatSeverity.CRITICAL,
        target_url="https://xyzproject.supabase.co"
    )
    print(f"   Source: {r3['source']}, Latency: {r3['latency_ms']}ms")

    # 4. Consolidar en grafo (Dreamer)
    print("\n[4] Ejecutando Dreamer Engine...")
    dream_result = brain.consolidate()
    print(f"   Resultado: {dream_result}")

    # 5. Stats
    print("\n[5] Dashboard del cerebro:")
    stats = brain.get_stats()
    for k, v in stats.items():
        print(f"   {k}: {v}")

    # 6. Contexto
    print("\n[6] Contexto actual:")
    ctx = brain.get_context("fuerza bruta")
    print(f"   Working memory: {ctx['working_memory_size']} items")
    print(f"   Recent episodes: {len(ctx['recent_episodes'])}")
    print(f"   Top attackers: {[a['name'] for a in ctx['top_attackers']]}")

    # Cleanup
    os.remove(DB)
    print("\n[OK] Demo completado exitosamente")
