# 15 — Canonical Node Memory System

**Arquitectura:** Graph-Centric Canonical Memory
(aliases: Entity-Resolved Memory Graph / Non-Redundant Semantic Memory / Canonical Node Memory System)

**Módulo:** `src/scanner/services/canonical_memory.py`
**Persistencia:** misma SQLite WAL que el brain (`vicoguard_brain.db`)
**Estado:** MVP implementado y probado E2E (scan → dedup → endpoints).

---

## Regla central (NO negociable)

> Una entidad conocida **nunca** se almacena como un nuevo nodo/vector si su identidad
> canónica ya existe; solo se agregan **evidencias, relaciones o revisiones** al nodo
> correspondiente.

**No deduplicar por texto literal: deduplicar por IDENTIDAD SEMÁNTICA.**

Complementa —no reemplaza— el *causal cache* por fingerprint SHA-256 del
`CognitiveSecurityBrain`. El fingerprint responde "¿ya resolví ESTE patrón de ataque?"
(cache de remediación); la memoria canónica responde "¿esta vuln es la MISMA entidad
que ya conozco?" (no-redundancia del grafo semántico).

---

## Problema que resuelve

El brain tenía ThreatGraph + fingerprint, pero el *Semantic Store* (embeddings) estaba
marcado FUTURO. Si se agregan vectores sin *entity resolution*, cada hallazgo repetido
crea embeddings redundantes y el agente "olvida" que ya vio la misma vulnerabilidad.
La memoria canónica garantiza **un solo nodo (y un solo vector activo) por identidad**.

---

## 1) Esquema de nodos

Tablas SQLite:

- **`canonical_entities`** — nodo canónico
  `canonical_id` (PK), `entity_type`, `normalized_key`, `label`, `aliases[]`,
  `embedding_ref` (UN solo vector activo), `confidence`, `first_seen`, `last_seen`,
  `version`, `status` (`active|merged|deprecated`), `attrs` (category/component/host/cwe/kind),
  `current_belief`, `evidence_count`.
  Índice ÚNICO `(normalized_key, entity_type)`.
- **`entity_evidence`** — `source`, `timestamp`, `scan_id`, `severity_observed`, `raw_payload`.
- **`entity_relations`** — `source_id`, `target_id`, `rel_type`, `weight`. Índice ÚNICO del triple.
- **`entity_revisions`** — `prev_version`, `diff_summary`, `changed_fields[]`, `reason`, `timestamp`.
- **`entity_embeddings`** — `canonical_id` (PK → **un vector activo por entidad**), `model`, `dim`, `vector`, `updated_at`.

Tipos de entidad (`EntityType`): `Vulnerability | Pattern | IP | URL | Service | CWE |
FindingInstance | Remediation | Actor`. El MVP materializa `Vulnerability` y `Service`
(el host afectado); el resto queda modelado para extensión.

`canonical_id`: `VG-VULN-<sha256(entity_type:normalized_key)[:10]>` (determinista → el mismo
hallazgo produce el mismo id, base de la no-redundancia).

## 2) Relaciones (`RelationType`)

`SAME_AS` · `VARIANT_OF` · `INSTANCE_OF` · `AFFECTS` · `EVIDENCED_BY` · `REMEDIATES` ·
`FIXED_BY` · `CO_OCCURS_WITH` · `SUPERSEDES` · `CONTRADICTS`.
El MVP emite `VARIANT_OF` (coreferencia de variante) y `AFFECTS` (vuln → Service/host).

## 3) `normalized_key` — identidad simbólica

Determinista, construida desde el finding del scanner (`extract_entity`):

| category del scanner | kind   | normalized_key            |
|----------------------|--------|---------------------------|
| `SUPABASE_RLS`       | table  | `rls:<tabla>@<host>`      |
| `EXPOSED_SECRETS(_JS)`| secret | `secret:<clase>@<host>`  |
| `HTTP_HEADERS`       | header | `header:<nombre>@<host>` |
| `DIRECTORY_EXPOSURE` | path   | `dir:<path>@<host>`      |
| (otros)              | generic| `<cat>:<comp>@<host>`    |

**Keys fuertes** (prioridad sobre embeddings): `normalized_key` y `cwe|component|host`.
Mapa `category → CWE`: HTTP_HEADERS→CWE-693, EXPOSED_SECRETS→CWE-798,
SUPABASE_RLS→CWE-284, DIRECTORY_EXPOSURE→CWE-538.

## 4) Deduplicación y umbrales

Pipeline `ingest_finding`:
1. `extract_entity` → tipo + attrs normalizados + strong keys.
2. `hybrid_lookup` → exact `normalized_key`/alias en grafo **+** kNN (embedding si está
   habilitado, si no similitud **léxica local** por coseno de tokens).
3. `resolve_identity` → `MERGE | LINK_VARIANT | NEW_NODE`.
4. update nodo + `attach_evidence` (+ `revision` si cambia el belief).
5. `maybe_reindex` embedding **in-place** solo si drift > umbral; nunca un 2º vector activo.

**Identidad de una vuln = (category, component, cwe). El `host` es su SCOPE.**
Las keys simbólicas mandan sobre la similitud vectorial (evita colapsar headers distintos
que comparten CWE):

| condición                                        | decisión |
|--------------------------------------------------|----------|
| `normalized_key`/alias exacto                    | **MERGE** |
| mismo component + cwe + host                      | **MERGE** |
| mismo component + cwe, **host distinto**          | **VARIANT** (misma vuln, otro scope) |
| component distinto (aunque comparta CWE)          | **NEW** (entidades distintas) |
| fallback: sim ≥ `0.92` **y** mismo component      | **MERGE** (coreferencia por wording) |

Umbrales (ajustables): `SIM_MERGE = 0.92`, `SIM_VARIANT_LOW = 0.80`, `DRIFT_REINDEX = 0.15`.

## 5) Política MERGE vs VARIANT vs NEW

- **MERGE**: `last_seen++`, `confidence += 0.1`, append `Evidence`, `version++` si cambia
  severidad/belief (con `Revision`), reutiliza `embedding_ref` (reindex in-place si drift alto).
- **VARIANT**: nodo hijo enlazado `VARIANT_OF` al padre; no clona el vector del padre.
- **NEW**: solo si falla la resolución; crea EL vector una sola vez.

## 6) Recuperación híbrida

`hybrid_lookup` = filtros de grafo (tipo + `normalized_key`/aliases) → candidatos del mismo
tipo → ranking por vector (o léxico) sobre embeddings canónicos únicos. Boost por
`last_seen` reciente pendiente de conectar al causal cache (éxito de remediación).

## 7) Contradicciones, versiones, fuentes

- Toda claim nueva = `Evidence` con `source` + `scan_id` + `timestamp` (trazabilidad).
- Conflicto con el canónico: no se borra; se sube `version` y se registra `Revision`
  (`current_belief` guarda la creencia vigente + historial). `CONTRADICTS` reservado.
- Feedback Telegram `mark_success/failed` sigue actualizando el `outcome` en el nodo
  episódico de Remediation del brain (no crea nodo paralelo).

## 8) Integración con el código actual

- Nuevo módulo `canonical_memory.py`; **no** toca el fingerprint causal cache.
- `src/api/main.py`: instancia global `canonical`; `_run_scan_pipeline` ejecuta
  `canonical.ingest_scan()` en **PASO 2b** (antes del análisis IA) y emite eventos
  `BRAIN: ...` al stream de la terminal en vivo.
- Endpoints nuevos:
  - `GET /api/v1/brain/entities?entity_type=&limit=` — lista de nodos canónicos + dedup stats.
  - `GET /api/v1/brain/entity/{canonical_id}` — nodo + evidencias + relaciones + revisiones.
  - `GET /api/v1/brain/stats` — ahora incluye bloque `canonical`
    (`unique_entities`, `merges`, `variants`, `evidences`, `redundant_nodes_avoided`, ...).
- UI/demo: al re-escanear la misma URL, la terminal live muestra
  `BRAIN: canonical hit VG-VULN-… (merged evidence #N)` en lugar de crear entidad nueva.

## 9) Embeddings — opcionales y no bloqueantes

Por defecto **desactivados**. Se habilitan con `VG_CANONICAL_EMBEDDINGS=1` +
`OPENAI_API_KEY` (modelo `text-embedding-3-small`, configurable con `VG_EMBED_MODEL`).
Si la API de embeddings falla, cae a **similitud léxica local** → la demo nunca se bloquea.
Fallback de resolución: keys simbólicas + fingerprint.

---

## Verificación (probado)

- `python -m scanner.services.canonical_memory` — self-test:
  scan A (3 NEW) → scan B mismas vulns/otro host (3 VARIANT) → re-scan A (3 MERGE).
- E2E real contra `/demo/vulnerable`:
  **scan 1 = 8 NEW** (5 headers + 3 secretos, componentes distintos),
  **scan 2 = 8 MERGE** (evidencia #2, 0 nodos/vectores duplicados),
  `redundant_nodes_avoided = 8`.

## Definition of done (cumplido)

- [x] Diseño escrito en este archivo.
- [x] Tablas `canonical_entities`, `entity_evidence`, `entity_relations`, `entity_revisions` (+ `entity_embeddings`).
- [x] `normalized_key` + similitud simple (embedding opcional).
- [x] Hook en el pipeline de scan: dedup de findings antes de "nuevo".
- [x] Test: re-escanear la misma URL → MERGE, no duplica nodo/vector.
- [x] No bloquea la demo si los embeddings fallan (fallback simbólico).
