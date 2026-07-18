"""
VicoGuard AI — Canonical Node Memory System
============================================
Graph-Centric Canonical Memory (alias: Entity-Resolved Memory Graph /
Non-Redundant Semantic Memory / Canonical Node Memory System).

Regla central (NO negociable):
    "Una entidad conocida nunca se almacena como un nuevo nodo/vector si su
     identidad canónica ya existe; solo se agregan evidencias, relaciones o
     revisiones al nodo correspondiente."

    No deduplicar por texto literal: deduplicar por IDENTIDAD SEMÁNTICA.

Este módulo COMPLEMENTA (no reemplaza) el causal cache por fingerprint del
CognitiveSecurityBrain. Vive en la misma SQLite (WAL) y expone un pipeline de
entity resolution que se ejecuta ANTES de persistir hallazgos duplicados.

Pipeline de ingesta (resolve_identity):
    1. extract_entities(finding)      -> tipo + attrs normalizados + strong keys
    2. hybrid_lookup(entity)          -> grafo (normalized_key / aliases) + kNN
    3. resolve_identity(entity, ...)  -> MERGE | LINK_VARIANT | NEW_NODE
    4. update nodo canónico + attach Evidence (+ Revision si cambia belief)
    5. reindex embedding solo si el contenido canónico drift > umbral;
       NUNCA se crea un segundo vector "activo" para la misma canonical_id.

Los embeddings OpenAI son OPCIONALES (env VG_CANONICAL_EMBEDDINGS=1). Sin ellos
el sistema usa similitud léxica local + keys simbólicas fuertes, por lo que la
demo NUNCA se bloquea si la API de embeddings falla.
"""

import os
import re
import json
import time
import uuid
import math
import hashlib
import logging
import sqlite3
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("vicoguard.canonical")


# ══════════════════════════════════════════════════════════════
# Vocabulario del grafo canónico
# ══════════════════════════════════════════════════════════════

class EntityType(str, Enum):
    VULNERABILITY = "Vulnerability"
    PATTERN = "Pattern"
    IP = "IP"
    URL = "URL"
    SERVICE = "Service"
    CWE = "CWE"
    FINDING_INSTANCE = "FindingInstance"
    REMEDIATION = "Remediation"
    ACTOR = "Actor"


class RelationType(str, Enum):
    SAME_AS = "SAME_AS"
    VARIANT_OF = "VARIANT_OF"
    INSTANCE_OF = "INSTANCE_OF"
    AFFECTS = "AFFECTS"
    EVIDENCED_BY = "EVIDENCED_BY"
    REMEDIATES = "REMEDIATES"
    FIXED_BY = "FIXED_BY"
    CO_OCCURS_WITH = "CO_OCCURS_WITH"
    SUPERSEDES = "SUPERSEDES"
    CONTRADICTS = "CONTRADICTS"


class Decision(str, Enum):
    MERGE = "MERGE"
    VARIANT = "LINK_VARIANT"
    NEW = "NEW_NODE"


class EntityStatus(str, Enum):
    ACTIVE = "active"
    MERGED = "merged"
    DEPRECATED = "deprecated"


# Umbrales de coreferencia (documentados en 15_CANONICAL_NODE_MEMORY.md)
SIM_MERGE = 0.92          # >= : misma identidad -> MERGE
SIM_VARIANT_LOW = 0.80    # [0.80, 0.92) : revisar reglas simbólicas -> VARIANT/MERGE
DRIFT_REINDEX = 0.15      # drift de contenido canónico que fuerza reindex del vector

# Mapa categoría del scanner -> CWE (weak key de refuerzo simbólico)
CATEGORY_CWE = {
    "HTTP_HEADERS": "CWE-693",         # Protection Mechanism Failure
    "EXPOSED_SECRETS": "CWE-798",      # Hardcoded Credentials
    "EXPOSED_SECRETS_JS": "CWE-798",
    "SUPABASE_RLS": "CWE-284",         # Improper Access Control
    "DIRECTORY_EXPOSURE": "CWE-538",   # File/Dir Information Exposure
    "RECONNAISSANCE": "CWE-200",       # Information Exposure
}


# ══════════════════════════════════════════════════════════════
# Extracción de entidades desde un finding del scanner
# ══════════════════════════════════════════════════════════════

def _host(url: Optional[str]) -> str:
    if not url:
        return "unknown-host"
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or url).lower()
    except Exception:
        return str(url).lower()


def _tokens(text: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if t]


def _extract_component(finding: Dict[str, Any]) -> Tuple[str, str]:
    """Devuelve (component, kind) — el atributo fuerte que identifica la vuln.

    kind ∈ {header, secret, table, path, generic}. Es la señal simbólica de
    mayor prioridad para la resolución de identidad.
    """
    category = str(finding.get("category", "")).upper()
    tech = finding.get("title_technical", "") or ""

    if category == "HTTP_HEADERS":
        m = re.search(r"Missing\s+([A-Za-z\-]+)\s+header", tech, re.IGNORECASE)
        comp = (m.group(1) if m else finding.get("id", "header")).strip()
        return comp.lower(), "header"

    if category in ("EXPOSED_SECRETS", "EXPOSED_SECRETS_JS"):
        m = re.search(r"Exposed\s+(.+?)\s+in", tech, re.IGNORECASE)
        comp = (m.group(1) if m else "secret").strip()
        return comp.lower(), "secret"

    if category == "SUPABASE_RLS":
        m = re.search(r"on\s+'([^']+)'\s+table", tech, re.IGNORECASE)
        if not m:
            m = re.search(r"tabla\s+'([^']+)'", str(finding.get("title_business", "")))
        comp = (m.group(1) if m else "table").strip()
        return comp.lower(), "table"

    if category == "DIRECTORY_EXPOSURE":
        m = re.search(r"path:\s*(\S+)", tech, re.IGNORECASE)
        comp = (m.group(1) if m else finding.get("id", "path")).strip()
        return comp.lower(), "path"

    return (finding.get("id") or category or "finding").lower(), "generic"


def extract_entity(finding: Dict[str, Any], target_url: Optional[str]) -> Dict[str, Any]:
    """Normaliza un finding del scanner a una entidad canónica candidata.

    Construye el `normalized_key` (identidad simbólica determinista) y las
    `strong_keys` que tienen prioridad sobre cualquier similitud vectorial.
    """
    category = str(finding.get("category", "")).upper()
    host = _host(target_url or finding.get("target_url"))
    component, kind = _extract_component(finding)
    cwe = CATEGORY_CWE.get(category, "CWE-Unknown")

    # normalized_key: identidad semántica estable. Para secretos/headers/paths la
    # identidad es component@host; para RLS la tabla es global al proyecto.
    if kind == "table":
        normalized_key = f"rls:{component}@{host}"
    elif kind == "secret":
        normalized_key = f"secret:{component}@{host}"
    elif kind == "header":
        normalized_key = f"header:{component}@{host}"
    elif kind == "path":
        normalized_key = f"dir:{component}@{host}"
    else:
        normalized_key = f"{category.lower()}:{component}@{host}"

    label = (
        finding.get("title_technical")
        or finding.get("title_business")
        or finding.get("title")
        or normalized_key
    )

    return {
        "entity_type": EntityType.VULNERABILITY.value,
        "normalized_key": normalized_key,
        "label": label,
        "host": host,
        "component": component,
        "kind": kind,
        "cwe": cwe,
        "category": category,
        "severity": str(finding.get("severity", "INFO")).upper(),
        # strong_keys: la resolución las prefiere sobre el embedding
        "strong_keys": {
            "normalized_key": normalized_key,
            "cwe_target": f"{cwe}|{component}|{host}",
        },
        "text_repr": f"{category} {component} {host} {label}",
        "raw": finding,
    }


# ══════════════════════════════════════════════════════════════
# Similitud (léxica local por defecto; embedding opcional)
# ══════════════════════════════════════════════════════════════

def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _lexical_similarity(a: str, b: str) -> float:
    """Cosine sobre conjuntos de tokens — barato, local, sin dependencias."""
    ta, tb = set(_tokens(a)), set(_tokens(b))
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    return inter / math.sqrt(len(ta) * len(tb))


class EmbeddingProvider:
    """Provee el vector activo de una entidad. Embeddings OpenAI son opcionales.

    Si VG_CANONICAL_EMBEDDINGS != '1' o falta la API key, `enabled` es False y el
    sistema cae a similitud léxica local (nunca bloquea la demo).
    """

    def __init__(self):
        self.model = os.getenv("VG_EMBED_MODEL", "text-embedding-3-small")
        self.enabled = (
            os.getenv("VG_CANONICAL_EMBEDDINGS", "0") == "1"
            and bool(os.getenv("OPENAI_API_KEY"))
        )
        self._client = None

    def embed(self, text: str) -> Optional[List[float]]:
        if not self.enabled:
            return None
        try:
            if self._client is None:
                from openai import OpenAI
                self._client = OpenAI()
            resp = self._client.embeddings.create(model=self.model, input=text[:8000])
            return resp.data[0].embedding
        except Exception as e:  # nunca romper el pipeline por embeddings
            logger.warning(f"[canonical] embedding falló, uso similitud léxica: {e}")
            return None


# ══════════════════════════════════════════════════════════════
# Store canónico (SQLite, misma DB que el brain)
# ══════════════════════════════════════════════════════════════

class CanonicalMemory:
    """Grafo de nodos canónicos con entity resolution y dedup no redundante."""

    def __init__(self, db_path: str = "vicoguard_brain.db"):
        self.db_path = db_path
        self.embedder = EmbeddingProvider()
        self._init_db()

    # ---- schema -------------------------------------------------
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS canonical_entities (
                    canonical_id   TEXT PRIMARY KEY,
                    entity_type    TEXT NOT NULL,
                    normalized_key TEXT NOT NULL,
                    label          TEXT,
                    aliases        TEXT DEFAULT '[]',
                    embedding_ref  TEXT,
                    confidence     REAL DEFAULT 0.6,
                    first_seen     REAL,
                    last_seen      REAL,
                    version        INTEGER DEFAULT 1,
                    status         TEXT DEFAULT 'active',
                    attrs          TEXT DEFAULT '{}',
                    current_belief TEXT DEFAULT '{}',
                    evidence_count INTEGER DEFAULT 0
                )
            """)
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_canon_key "
                "ON canonical_entities(normalized_key, entity_type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_canon_type "
                "ON canonical_entities(entity_type, status)"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_evidence (
                    id              TEXT PRIMARY KEY,
                    canonical_id    TEXT NOT NULL,
                    source          TEXT,
                    timestamp       REAL,
                    scan_id         TEXT,
                    severity_observed TEXT,
                    raw_payload     TEXT DEFAULT '{}'
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ev_canon ON entity_evidence(canonical_id)"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_relations (
                    id         TEXT PRIMARY KEY,
                    source_id  TEXT NOT NULL,
                    target_id  TEXT NOT NULL,
                    rel_type   TEXT NOT NULL,
                    weight     REAL DEFAULT 1.0,
                    metadata   TEXT DEFAULT '{}'
                )
            """)
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_rel_triple "
                "ON entity_relations(source_id, target_id, rel_type)"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_revisions (
                    id            TEXT PRIMARY KEY,
                    canonical_id  TEXT NOT NULL,
                    prev_version  INTEGER,
                    diff_summary  TEXT,
                    changed_fields TEXT DEFAULT '[]',
                    reason        TEXT,
                    timestamp     REAL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rev_canon ON entity_revisions(canonical_id)"
            )
            # Un solo vector ACTIVO por canonical_id (la regla central en el schema)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_embeddings (
                    canonical_id TEXT PRIMARY KEY,
                    model        TEXT,
                    dim          INTEGER,
                    vector       TEXT,
                    updated_at   REAL
                )
            """)
            conn.commit()

    # ---- helpers de id -----------------------------------------
    @staticmethod
    def make_canonical_id(entity_type: str, normalized_key: str) -> str:
        prefix = "VG-VULN" if entity_type == EntityType.VULNERABILITY.value else "VG-ENT"
        h = hashlib.sha256(f"{entity_type}:{normalized_key}".encode()).hexdigest()[:10].upper()
        return f"{prefix}-{h}"

    # ---- lookup híbrido ----------------------------------------
    def hybrid_lookup(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        """Recupera candidatos: exact key en grafo + aliases + kNN vectorial/léxico."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            exact = conn.execute(
                "SELECT * FROM canonical_entities "
                "WHERE normalized_key = ? AND entity_type = ? AND status = 'active'",
                (entity["normalized_key"], entity["entity_type"]),
            ).fetchone()

            # Candidatos del mismo tipo para coreferencia por similitud
            same_type = conn.execute(
                "SELECT * FROM canonical_entities "
                "WHERE entity_type = ? AND status = 'active'",
                (entity["entity_type"],),
            ).fetchall()

        # alias match (la key aparece listada como alias de otro nodo canónico)
        alias_hit = None
        for row in same_type:
            aliases = json.loads(row["aliases"] or "[]")
            if entity["normalized_key"] in aliases:
                alias_hit = row
                break

        # ranking por similitud (embedding si existe, si no léxico)
        query_vec = self.embedder.embed(entity["text_repr"]) if self.embedder.enabled else None
        ranked: List[Tuple[float, sqlite3.Row]] = []
        for row in same_type:
            if query_vec is not None:
                cand_vec = self._get_vector(row["canonical_id"])
                sim = _cosine(query_vec, cand_vec) if cand_vec else _lexical_similarity(
                    entity["text_repr"], self._row_text(row)
                )
            else:
                sim = _lexical_similarity(entity["text_repr"], self._row_text(row))
            ranked.append((sim, row))
        ranked.sort(key=lambda x: x[0], reverse=True)

        return {
            "exact": exact,
            "alias": alias_hit,
            "ranked": ranked[:5],
            "query_vec": query_vec,
        }

    def _row_text(self, row: sqlite3.Row) -> str:
        attrs = json.loads(row["attrs"] or "{}")
        return f"{attrs.get('category','')} {attrs.get('component','')} {attrs.get('host','')} {row['label']}"

    # ---- resolución de identidad -------------------------------
    def resolve_identity(self, entity: Dict[str, Any], candidates: Dict[str, Any]) -> Dict[str, Any]:
        """Decide MERGE | VARIANT | NEW.

        Las KEYS SIMBÓLICAS FUERTES tienen prioridad sobre la similitud vectorial
        (regla del diseño). La identidad de una vuln es (category, component, cwe);
        el `host` es su SCOPE. Por eso:
          - mismo component+cwe+host  -> MERGE  (misma entidad; misma evidencia)
          - mismo component+cwe, host distinto -> VARIANT (misma vuln, otro scope)
          - component distinto        -> entidades DISTINTAS aunque compartan CWE
        La similitud léxica/vectorial solo resuelve coreferencia cuando las keys
        simbólicas coinciden en component (evita colapsar headers distintos).
        """
        exact = candidates["exact"] or candidates["alias"]
        if exact is not None:
            return {"decision": Decision.MERGE, "canonical_id": exact["canonical_id"], "score": 1.0}

        # 1) Resolución simbólica: buscar un candidato con el MISMO component+cwe.
        for sim, row in candidates["ranked"]:
            attrs = json.loads(row["attrs"] or "{}")
            same_component = attrs.get("component") == entity["component"]
            same_cwe = attrs.get("cwe") == entity["cwe"]
            same_category = attrs.get("category") == entity["category"]
            if same_component and same_cwe and same_category:
                if attrs.get("host") == entity["host"]:
                    # misma identidad exacta (caso alias) -> MERGE
                    return {"decision": Decision.MERGE, "canonical_id": row["canonical_id"], "score": max(sim, 0.95)}
                # misma vuln, distinto scope/host -> VARIANT del nodo padre
                return {"decision": Decision.VARIANT, "canonical_id": row["canonical_id"], "score": max(sim, SIM_VARIANT_LOW)}

        # 2) Fallback semántico: solo si el vector/léxico es MUY alto y el component
        #    coincide (coreferencia con distinto wording), nunca por CWE solo.
        ranked = candidates["ranked"]
        if ranked:
            top_sim, top_row = ranked[0]
            top_attrs = json.loads(top_row["attrs"] or "{}")
            if (
                top_sim >= SIM_MERGE
                and top_attrs.get("component") == entity["component"]
                and top_attrs.get("category") == entity["category"]
            ):
                return {"decision": Decision.MERGE, "canonical_id": top_row["canonical_id"], "score": top_sim}

        return {"decision": Decision.NEW, "canonical_id": None, "score": 0.0}

    # ---- ingesta de un finding ---------------------------------
    def ingest_finding(
        self, finding: Dict[str, Any], scan_id: str = "", target_url: Optional[str] = None,
        source: str = "scanner",
    ) -> Dict[str, Any]:
        entity = extract_entity(finding, target_url)
        candidates = self.hybrid_lookup(entity)
        resolution = self.resolve_identity(entity, candidates)
        decision = resolution["decision"]

        if decision == Decision.MERGE:
            node = self._merge(resolution["canonical_id"], entity, scan_id, source)
            result = {"decision": decision.value, **node}
        elif decision == Decision.VARIANT:
            node = self._create_node(entity, scan_id, source, query_vec=candidates["query_vec"])
            self._add_relation(node["canonical_id"], resolution["canonical_id"], RelationType.VARIANT_OF)
            result = {"decision": decision.value, "parent_id": resolution["canonical_id"], **node}
        else:
            node = self._create_node(entity, scan_id, source, query_vec=candidates["query_vec"])
            result = {"decision": decision.value, **node}

        # Relación AFFECTS: vuln -> URL/host afectado (nodo Service/URL canónico)
        try:
            svc_id = self._ensure_service_node(entity["host"], scan_id)
            self._add_relation(result["canonical_id"], svc_id, RelationType.AFFECTS)
        except Exception as e:
            logger.debug(f"[canonical] AFFECTS skip: {e}")

        return result

    def ingest_scan(self, scan_results: Dict[str, Any], scan_id: str = "") -> Dict[str, Any]:
        """Deduplica todos los findings de un scan ANTES de persistir.

        Devuelve un resumen con líneas listas para la terminal en vivo
        (p.ej. 'BRAIN: canonical hit VG-VULN-... (merged evidence #N)').
        """
        target_url = scan_results.get("target_url")
        findings = scan_results.get("findings", []) or []
        summary = {
            "scan_id": scan_id, "processed": 0,
            "merges": 0, "variants": 0, "new": 0,
            "canonical_ids": [], "events": [],
        }
        for f in findings:
            res = self.ingest_finding(f, scan_id=scan_id, target_url=target_url)
            summary["processed"] += 1
            cid = res["canonical_id"]
            summary["canonical_ids"].append(cid)
            if res["decision"] == Decision.MERGE.value:
                summary["merges"] += 1
                summary["events"].append(
                    f"BRAIN: canonical hit {cid} (merged evidence #{res['evidence_count']})"
                )
            elif res["decision"] == Decision.VARIANT.value:
                summary["variants"] += 1
                summary["events"].append(
                    f"BRAIN: variante enlazada {cid} VARIANT_OF {res.get('parent_id')}"
                )
            else:
                summary["new"] += 1
                summary["events"].append(f"BRAIN: nueva entidad canónica {cid} ({res['normalized_key']})")
        return summary

    # ---- operaciones de nodo -----------------------------------
    def _create_node(
        self, entity: Dict[str, Any], scan_id: str, source: str,
        query_vec: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        canonical_id = self.make_canonical_id(entity["entity_type"], entity["normalized_key"])
        attrs = {
            "category": entity["category"], "component": entity["component"],
            "host": entity["host"], "cwe": entity["cwe"], "kind": entity["kind"],
        }
        belief = {"severity": entity["severity"], "label": entity["label"]}
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO canonical_entities
                (canonical_id, entity_type, normalized_key, label, aliases, embedding_ref,
                 confidence, first_seen, last_seen, version, status, attrs, current_belief,
                 evidence_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0)
            """, (
                canonical_id, entity["entity_type"], entity["normalized_key"], entity["label"],
                json.dumps([]), canonical_id if query_vec else None, 0.6, now, now, 1,
                EntityStatus.ACTIVE.value, json.dumps(attrs, ensure_ascii=False),
                json.dumps(belief, ensure_ascii=False),
            ))
            conn.commit()
        if query_vec:
            self._store_vector(canonical_id, query_vec)
        self._attach_evidence(canonical_id, entity, scan_id, source)
        row = self.get_entity(canonical_id)
        return {
            "canonical_id": canonical_id, "normalized_key": entity["normalized_key"],
            "version": row["version"], "evidence_count": row["evidence_count"], "created": True,
        }

    def _merge(self, canonical_id: str, entity: Dict[str, Any], scan_id: str, source: str) -> Dict[str, Any]:
        """MERGE: append evidence, last_seen++, bump version si cambia el belief.

        Reutiliza el `embedding_ref` existente; solo reindexa in-place si el
        contenido canónico drift supera el umbral. NUNCA crea un 2º vector activo.
        """
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM canonical_entities WHERE canonical_id = ?", (canonical_id,)
            ).fetchone()
            if row is None:  # carrera improbable: degradar a create
                return self._create_node(entity, scan_id, source)

            belief = json.loads(row["current_belief"] or "{}")
            version = row["version"]
            changed: List[str] = []
            # Severidad puede escalar -> nueva creencia + revisión
            if entity["severity"] != belief.get("severity"):
                changed.append("severity")
            new_belief = dict(belief)
            if changed:
                new_belief["severity"] = entity["severity"]
                new_belief["label"] = entity["label"]
                version += 1

            # aliases: registrar la key entrante si difiere (coreferencia)
            aliases = json.loads(row["aliases"] or "[]")
            if entity["normalized_key"] != row["normalized_key"] and entity["normalized_key"] not in aliases:
                aliases.append(entity["normalized_key"])

            conn.execute("""
                UPDATE canonical_entities
                SET last_seen = ?, version = ?, current_belief = ?, aliases = ?,
                    confidence = MIN(1.0, confidence + 0.1)
                WHERE canonical_id = ?
            """, (now, version, json.dumps(new_belief, ensure_ascii=False),
                  json.dumps(aliases), canonical_id))
            conn.commit()

            if changed:
                self._add_revision(
                    canonical_id, row["version"], f"belief updated: {', '.join(changed)}",
                    changed, reason=f"scan {scan_id or 'n/a'} observó severidad {entity['severity']}",
                )

        self._attach_evidence(canonical_id, entity, scan_id, source)
        self._maybe_reindex(canonical_id, entity)
        node = self.get_entity(canonical_id)
        return {
            "canonical_id": canonical_id, "normalized_key": row["normalized_key"],
            "version": node["version"], "evidence_count": node["evidence_count"], "created": False,
        }

    def _ensure_service_node(self, host: str, scan_id: str) -> str:
        """Crea/recupera el nodo canónico URL/Service del host afectado."""
        normalized_key = f"service:{host}"
        canonical_id = self.make_canonical_id(EntityType.SERVICE.value, normalized_key)
        now = time.time()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO canonical_entities
                (canonical_id, entity_type, normalized_key, label, aliases, confidence,
                 first_seen, last_seen, version, status, attrs, current_belief, evidence_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)
                ON CONFLICT(canonical_id) DO UPDATE SET last_seen = excluded.last_seen
            """, (
                canonical_id, EntityType.SERVICE.value, normalized_key, host, json.dumps([]),
                0.9, now, now, 1, EntityStatus.ACTIVE.value,
                json.dumps({"host": host}), json.dumps({"host": host}),
            ))
            conn.commit()
        return canonical_id

    # ---- evidencia / revisiones / relaciones -------------------
    def _attach_evidence(self, canonical_id: str, entity: Dict[str, Any], scan_id: str, source: str):
        ev_id = uuid.uuid4().hex
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO entity_evidence
                (id, canonical_id, source, timestamp, scan_id, severity_observed, raw_payload)
                VALUES (?,?,?,?,?,?,?)
            """, (
                ev_id, canonical_id, source, time.time(), scan_id, entity["severity"],
                json.dumps(entity["raw"], ensure_ascii=False)[:4000],
            ))
            conn.execute(
                "UPDATE canonical_entities SET evidence_count = evidence_count + 1 WHERE canonical_id = ?",
                (canonical_id,),
            )
            conn.commit()
        return ev_id

    def _add_revision(self, canonical_id: str, prev_version: int, diff_summary: str,
                      changed_fields: List[str], reason: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO entity_revisions
                (id, canonical_id, prev_version, diff_summary, changed_fields, reason, timestamp)
                VALUES (?,?,?,?,?,?,?)
            """, (uuid.uuid4().hex, canonical_id, prev_version, diff_summary,
                  json.dumps(changed_fields), reason, time.time()))
            conn.commit()

    def _add_relation(self, source_id: str, target_id: str, rel_type: RelationType, weight: float = 1.0):
        if source_id == target_id:
            return
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id, weight FROM entity_relations "
                "WHERE source_id = ? AND target_id = ? AND rel_type = ?",
                (source_id, target_id, rel_type.value),
            ).fetchone()
            if existing:
                conn.execute("UPDATE entity_relations SET weight = ? WHERE id = ?",
                             (existing[1] + weight, existing[0]))
            else:
                conn.execute("""
                    INSERT INTO entity_relations (id, source_id, target_id, rel_type, weight, metadata)
                    VALUES (?,?,?,?,?,?)
                """, (uuid.uuid4().hex, source_id, target_id, rel_type.value, weight, "{}"))
            conn.commit()

    # ---- embeddings (un solo vector activo por canonical_id) ---
    def _store_vector(self, canonical_id: str, vector: List[float]):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO entity_embeddings (canonical_id, model, dim, vector, updated_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(canonical_id) DO UPDATE SET
                    model = excluded.model, dim = excluded.dim,
                    vector = excluded.vector, updated_at = excluded.updated_at
            """, (canonical_id, self.embedder.model, len(vector),
                  json.dumps(vector), time.time()))
            conn.commit()

    def _get_vector(self, canonical_id: str) -> Optional[List[float]]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT vector FROM entity_embeddings WHERE canonical_id = ?", (canonical_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def _maybe_reindex(self, canonical_id: str, entity: Dict[str, Any]):
        """Reindexa el vector IN-PLACE solo si el contenido canónico driftó.

        Jamás crea un segundo vector activo: hace UPDATE del mismo canonical_id.
        """
        if not self.embedder.enabled:
            return
        current = self._get_vector(canonical_id)
        new_vec = self.embedder.embed(entity["text_repr"])
        if new_vec is None:
            return
        if current is None:
            self._store_vector(canonical_id, new_vec)
            return
        drift = 1.0 - _cosine(current, new_vec)
        if drift > DRIFT_REINDEX:
            self._store_vector(canonical_id, new_vec)  # UPDATE in-place
            logger.info(f"[canonical] reindex in-place {canonical_id} (drift={drift:.2f})")

    # ---- lectura -----------------------------------------------
    def get_entity(self, canonical_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM canonical_entities WHERE canonical_id = ?", (canonical_id,)
            ).fetchone()
            if not row:
                return None
            evidence = conn.execute(
                "SELECT id, source, timestamp, scan_id, severity_observed "
                "FROM entity_evidence WHERE canonical_id = ? ORDER BY timestamp DESC LIMIT 50",
                (canonical_id,),
            ).fetchall()
            relations = conn.execute(
                "SELECT source_id, target_id, rel_type, weight FROM entity_relations "
                "WHERE source_id = ? OR target_id = ?",
                (canonical_id, canonical_id),
            ).fetchall()
            revisions = conn.execute(
                "SELECT prev_version, diff_summary, changed_fields, reason, timestamp "
                "FROM entity_revisions WHERE canonical_id = ? ORDER BY timestamp DESC",
                (canonical_id,),
            ).fetchall()
        return {
            "canonical_id": row["canonical_id"],
            "entity_type": row["entity_type"],
            "normalized_key": row["normalized_key"],
            "label": row["label"],
            "aliases": json.loads(row["aliases"] or "[]"),
            "confidence": row["confidence"],
            "version": row["version"],
            "status": row["status"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "attrs": json.loads(row["attrs"] or "{}"),
            "current_belief": json.loads(row["current_belief"] or "{}"),
            "evidence_count": row["evidence_count"],
            "has_active_vector": self._get_vector(canonical_id) is not None,
            "evidence": [dict(e) for e in evidence],
            "relations": [dict(r) for r in relations],
            "revisions": [
                {**dict(r), "changed_fields": json.loads(r["changed_fields"] or "[]")}
                for r in revisions
            ],
        }

    def list_entities(self, limit: int = 50, entity_type: Optional[str] = None) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if entity_type:
                rows = conn.execute(
                    "SELECT canonical_id, entity_type, normalized_key, label, version, "
                    "evidence_count, last_seen FROM canonical_entities "
                    "WHERE entity_type = ? AND status = 'active' "
                    "ORDER BY last_seen DESC LIMIT ?", (entity_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT canonical_id, entity_type, normalized_key, label, version, "
                    "evidence_count, last_seen FROM canonical_entities "
                    "WHERE status = 'active' ORDER BY last_seen DESC LIMIT ?", (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_graph(self, limit: int = 200) -> Dict[str, Any]:
        """Devuelve el grafo canónico (nodos + aristas) para el mapa de topología.

        Nodos = entidades canónicas activas (Vulnerability, Service, ...).
        Aristas = relaciones (AFFECTS, VARIANT_OF, ...) entre nodos presentes.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT canonical_id, entity_type, normalized_key, label, attrs, "
                "current_belief, evidence_count, last_seen FROM canonical_entities "
                "WHERE status = 'active' ORDER BY last_seen DESC LIMIT ?", (limit,),
            ).fetchall()
            edges = conn.execute(
                "SELECT source_id, target_id, rel_type, weight FROM entity_relations"
            ).fetchall()
        node_ids = {r["canonical_id"] for r in rows}
        nodes = []
        for r in rows:
            attrs = json.loads(r["attrs"] or "{}")
            belief = json.loads(r["current_belief"] or "{}")
            nodes.append({
                "id": r["canonical_id"], "type": r["entity_type"], "label": r["label"],
                "key": r["normalized_key"], "category": attrs.get("category"),
                "cwe": attrs.get("cwe"), "host": attrs.get("host"),
                "component": attrs.get("component"),
                "severity": (belief.get("severity") or "").upper(),
                "evidence_count": r["evidence_count"],
            })
        out_edges = [
            {"source": e["source_id"], "target": e["target_id"],
             "type": e["rel_type"], "weight": e["weight"]}
            for e in edges if e["source_id"] in node_ids and e["target_id"] in node_ids
        ]
        return {"nodes": nodes, "edges": out_edges}

    def get_stats(self) -> Dict[str, Any]:
        """Métricas de deduplicación para /brain/stats y el pitch."""
        with sqlite3.connect(self.db_path) as conn:
            unique_entities = conn.execute(
                "SELECT COUNT(*) FROM canonical_entities WHERE status = 'active'"
            ).fetchone()[0]
            vulns = conn.execute(
                "SELECT COUNT(*) FROM canonical_entities WHERE entity_type = 'Vulnerability' AND status = 'active'"
            ).fetchone()[0]
            evidences = conn.execute("SELECT COUNT(*) FROM entity_evidence").fetchone()[0]
            relations = conn.execute("SELECT COUNT(*) FROM entity_relations").fetchone()[0]
            revisions = conn.execute("SELECT COUNT(*) FROM entity_revisions").fetchone()[0]
            variants = conn.execute(
                "SELECT COUNT(*) FROM entity_relations WHERE rel_type = 'VARIANT_OF'"
            ).fetchone()[0]
            active_vectors = conn.execute("SELECT COUNT(*) FROM entity_embeddings").fetchone()[0]
            # merges = cada evidencia MÁS ALLÁ de la primera apilada sobre un nodo
            # ya existente (== nodos/vectores redundantes evitados por el dedup).
            merges = conn.execute(
                "SELECT COALESCE(SUM(CASE WHEN evidence_count > 1 "
                "THEN evidence_count - 1 ELSE 0 END), 0) FROM canonical_entities"
            ).fetchone()[0]
        redundancy_avoided = merges  # vectores/nodos NO creados gracias al dedup
        return {
            "unique_entities": unique_entities,
            "unique_vulnerabilities": vulns,
            "evidences": evidences,
            "merges": merges,
            "variants": variants,
            "relations": relations,
            "revisions": revisions,
            "active_vectors": active_vectors,
            "redundant_nodes_avoided": redundancy_avoided,
            "embeddings_enabled": self.embedder.enabled,
        }


# ══════════════════════════════════════════════════════════════
# DEMO / TEST (regla central: 2º scan hace MERGE, no duplica nodo)
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os as _os
    DB = "test_canonical_demo.db"
    if _os.path.exists(DB):
        _os.remove(DB)

    mem = CanonicalMemory(DB)

    scan = {
        "target_url": "http://localhost:8000/demo/vulnerable",
        "findings": [
            {"id": "VG-RLS-001", "severity": "CRITICAL", "category": "SUPABASE_RLS",
             "title_technical": "Supabase RLS Disabled on 'users' table",
             "title_business": "La tabla 'users' está expuesta"},
            {"id": "VG-HDR-CON", "severity": "MEDIUM", "category": "HTTP_HEADERS",
             "title_technical": "Missing Content-Security-Policy header",
             "title_business": "Falta cabecera CSP"},
            {"id": "VG-SEC-SUP", "severity": "HIGH", "category": "EXPOSED_SECRETS",
             "title_technical": "Exposed Supabase Key in client-side code",
             "title_business": "Llave Supabase expuesta"},
        ],
    }

    print("=" * 60)
    print("DEMO: Canonical Node Memory — regla de no redundancia")
    print("=" * 60)

    print("\n[SCAN 1] primera vez que vemos esta URL:")
    s1 = mem.ingest_scan(scan, scan_id="scan-001")
    for e in s1["events"]:
        print("   " + e)
    print(f"   -> new={s1['new']} merges={s1['merges']} variants={s1['variants']}")

    assert s1["new"] == 3 and s1["variants"] == 0, "3 findings distintos deben ser 3 NEW"

    print("\n[SCAN 2] OTRO host, MISMAS vulns (debe LINK_VARIANT, no NEW):")
    scan_b = json.loads(json.dumps(scan))
    scan_b["target_url"] = "http://otra-pyme.example.com/app"
    s2 = mem.ingest_scan(scan_b, scan_id="scan-002")
    for e in s2["events"]:
        print("   " + e)
    print(f"   -> new={s2['new']} merges={s2['merges']} variants={s2['variants']}")
    assert s2["variants"] == 3, "mismo component en otro host debe ser VARIANT"

    print("\n[SCAN 3] MISMA URL del scan 1 re-escaneada (debe MERGE, no duplicar):")
    s3 = mem.ingest_scan(scan, scan_id="scan-003")
    for e in s3["events"]:
        print("   " + e)
    print(f"   -> new={s3['new']} merges={s3['merges']} variants={s3['variants']}")

    print("\n[STATS] deduplicación:")
    for k, v in mem.get_stats().items():
        print(f"   {k}: {v}")

    assert s3["new"] == 0, "REGLA VIOLADA: el re-scan creó nodos nuevos"
    assert s3["merges"] == 3, "El re-scan debía apilar 3 evidencias por MERGE"
    print("\n[OK] Regla central respetada: identidad simbólica -> NEW/VARIANT/MERGE correctos")

    # cleanup best-effort (Windows mantiene lock sobre WAL/SHM)
    del mem
    import gc; gc.collect()
    for suffix in ("", "-wal", "-shm"):
        try:
            _os.remove(DB + suffix)
        except OSError:
            pass
