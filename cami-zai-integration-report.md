# 🔍 Reporte de Investigación: VicoGuard-AI × Z.ai Coding Plan × Silhouette

**Investigadora:** Cami  
**Fecha:** 2026-07-20 22:20 UTC  
**Status:** Completo

---

## 1. Z.AI CODING PLAN EN VICOGUARD

### Configuración Actual

VicoGuard-AI (WASP Centinela) usa Z.ai Coding Plan vía el módulo `centinela/interpreter/interpret.py`:

| Parámetro | Valor |
|-----------|-------|
| **Endpoint** | `https://api.z.ai/api/coding/paas/v4/chat/completions` |
| **Modelo** | `glm-4.5` (hardcoded como default) |
| **Protocolo** | OpenAI-compatible (chat/completions) |
| **Cliente HTTP** | `httpx` (Python, sin SDK de OpenAI) |
| **Auth** | Bearer token en header `Authorization` |
| **Env var key** | `ANTHROPIC_API_KEY` (nombre confuso — es un key de Z.ai) |
| **Env var model** | `ANTHROPIC_MODEL` (override opcional, default `glm-4.5`) |
| **Timeout** | **90 segundos** (`_LLM_TIMEOUT_SECONDS = 90`) |
| **Max tokens** | 400-600 según función (summarize=600, explain=400, answer=500) |

### Funciones que usan el LLM

1. **`summarize()`** — Genera resumen Telegram del ledger de seguridad
2. **`explain(finding_id)`** — Explica un hallazgo específico en 3-5 líneas
3. **`answer_question(question)`** — Responde preguntas libres sobre el ledger

### Sistema de Fallback (Crítico)

Toda función LLM tiene un **fallback heurístico determinístico** que funciona sin red ni credenciales:

```python
if resolved_key:
    try:
        return _llm_summarize(entries, resolved_key)
    except Exception:
        return _heuristic_summarize(entries)  # nunca crashea
```

### Limitaciones Detectadas

1. **Endpoint restrictivo**: El key de Coding Plan **solo funciona** en `/api/coding/paas/v4/`. Los endpoints `/api/anthropic` y `/api/paas/v4` rechazan este key (confirmado 2026-07-18: 401 y 429).
2. **GLM-4.5 emite chain-of-thought** antes de responder → latencia extra real (30s no era suficiente, por eso subieron a 90s).
3. **Sin streaming** — espera la respuesta completa antes de procesar.
4. **Nombre confuso de env var**: `ANTHROPIC_API_KEY` contiene un key de Z.ai. Esto es tech debt.
5. **Sin reintentos** — un fallo de red va directo al fallback heurístico.

---

## 2. INTEGRACIÓN ACTUAL EN SILHOUETTE

### Configuración OpenClaw (Silhouette)

Silhouette corre sobre OpenClaw con una configuración **mucho más avanzada**:

| Parámetro | Valor |
|-----------|-------|
| **Endpoint** | `https://open.bigmodel.cn/api/coding/paas/v4` |
| **Modelo primario** | `zai/glm-5.2` ✨ |
| **Fallbacks** | `glm-5.2 → glm-4.7 → glm-5 → minimax → openrouter → anthropic` |
| **Protocolo** | OpenAI-compatible |
| **Agent runtime** | OpenClaw (Node.js) |

### Modelos Z.ai Disponibles en Silhouette

| Modelo | Estado |
|--------|--------|
| `glm-5.2` | ✅ **Activo** (modelo principal) |
| `glm-5.1` | ✅ Disponible |
| `glm-5` | ✅ Disponible |
| `glm-5-turbo` | ✅ Disponible |
| `glm-5v-turbo` | ✅ Disponible (multimodal) |
| `glm-4.7` | ✅ Disponible |
| `glm-4.7-flash` | ✅ Disponible |
| `glm-4.7-flashx` | ✅ Disponible |
| `glm-4.6` | ✅ Disponible |
| `glm-4.5` | ❌ **No listado** (VicoGuard lo usa) |

### Gaps Detectados

1. **Sin integración directa con VicoGuard**: Silhouette no tiene código que llame a VicoGuard-AI. No hay adapter, client, ni referencia.
2. **Endpoint diferente**: Silhouette usa `open.bigmodel.cn` vs VicoGuard usa `api.z.ai` — son mirrors pero pueden tener latencia/SLA distintos.
3. **VicoGuard está 1 generación atrás**: `glm-4.5` vs `glm-5.2`.

---

## 3. COMPATIBILIDAD DE CREDENCIALES

### Análisis

| Aspecto | VicoGuard | Silhouette |
|---------|-----------|------------|
| **Provider** | Z.ai Coding Plan | Z.ai (BigModel) |
| **Endpoint base** | `api.z.ai/api/coding/paas/v4` | `open.bigmodel.cn/api/coding/paas/v4` |
| **Key storage** | `ANTHROPIC_API_KEY` (env) | OpenClaw config (probablemente `.env` o `auth.json`) |
| **Modelo** | `glm-4.5` | `glm-5.2` |

### ¿Pueden compartir credenciales?

**Sí, técnicamente.** Ambos son endpoints del Coding Plan de Z.ai/BigModel. Un mismo Bearer token debería funcionar en ambos dominios (`api.z.ai` y `open.bigmodel.cn` son el mismo servicio con differentes aliases DNS).

### ¿Hay duplicación?

**Sí.** VicoGuard tiene su propio key de Z.ai Coding Plan (en `ANTHROPIC_API_KEY`), y OpenClaw tiene el suyo configurado en `openclaw.json`. Son probablemente el **mismo plan** con dos nombres distintos.

**Recomendación**: Unificar a un solo key compartido vía variable de entorno o secrets manager.

---

## 4. STACK COMPARATIVO

| Dimensión | VicoGuard-AI | Silhouette |
|-----------|-------------|------------|
| **Lenguaje** | Python 3.11+ | Node.js 22 |
| **Framework** | FastAPI (implícito) | OpenClaw runtime |
| **LLM Client** | `httpx` directo (sin SDK) | OpenClaw provider system |
| **Modelo** | GLM-4.5 | GLM-5.2 |
| **Protocolo LLM** | OpenAI-compatible | OpenAI-compatible |
| **Persistence** | JSONL ledger (hash chain) | Redis + SQLite + Neo4j + LanceDB |
| **Messaging** | Telegram Bot | OpenClaw multi-channel |
| **Security scanning** | Semgrep + Gitleaks + DAST | N/A (no tiene) |
| **Governance** | Capability contracts YAML | AGENTS.md rules + safety system |

### Cómo Conectarlos

**Opción A — API Bridge (Recomendada)**:
VicoGuard ya expone una API REST (`POST /api/v1/scan/start`, `GET /api/v1/scan/{id}`). Silhouette/OpenClaw puede consumirla directamente vía HTTP:

```
Silhouette → curl POST http://vicoguard:8000/api/v1/scan/start → poll results
```

**Opción B — MCP Server**:
VicoGuard ya tiene `mcp_governor_server.py`. Se podría registrar como MCP tool en OpenClaw y llamarlo nativamente.

**Opción C — Shared Library**:
Extraer la lógica de interpretación de hallazgos a un microservicio independiente que ambos consuman.

---

## 5. PUNTOS DE MEJORA Y RECOMENDACIONES TÉCNICAS

### 5.1 Migrar VicoGuard a GLM-5.2

**Prioridad: ALTA**

| Métrica | GLM-4.5 (actual) | GLM-5.2 (target) |
|---------|-----------------|-----------------|
| **Calidad reasoning** | Buena | Significativamente mejor |
| **Chain-of-thought** | Sí (latencia +30s) | Optimizado en 5.2 |
| **Multimodal** | No | Sí (image input) |
| **Costo** | Coding Plan included | Coding Plan included |
| **Riesgo migración** | — | Bajo (mismo protocolo) |

**Cómo**:
```python
# interpret.py cambio mínimo:
MODEL = os.environ.get("ANTHROPIC_MODEL", "glm-5.2")  # era "glm-4.5"
```

**Riesgo**: El system prompt está optimizado para GLM-4.5. GLM-5.2 tiene mejor instruction following, así que los prompts deberían funcionar igual o mejor. De todas formas, probar con el suite de tests existente (`tests/test_interpret.py`).

### 5.2 Unificar Endpoints

VicoGuard usa `api.z.ai`, Silhouette usa `open.bigmodel.cn`. Ambos son el mismo servicio. **Recomendación**: estandarizar a `open.bigmodel.cn` (el oficial, con mejor uptime según社区).

### 5.3 Reutilizar VicoGuard en Silhouette

**Caso de uso**: Silhouette podría usar VicoGuard para:
- **Auditar código antes de deploy** (pre-commit hook)
- **Scanning automático en CI/CD** de Brandistry, Shop, Nexus
- **Detección de secretos** en repos del equipo

**Implementación**:
1. Levantar VicoGuard como servicio Docker en Atlantic
2. Registrar como MCP tool en OpenClaw: `mcporter` o config directa
3. Crear skill `vicoguard-scan` que Silhouette pueda invocar
4. Integrar en heartbeat: scan semanal de repos activos

### 5.4 Renombrar `ANTHROPIC_API_KEY`

**Deuda técnica crítica**. La env var se llama `ANTHROPIC_API_KEY` pero contiene un key de Z.ai. Esto causa confusión real.

**Fix**: Renombrar a `ZAI_CODING_PLAN_KEY` o `GLM_API_KEY` con un período de compatibilidad:

```python
def _resolve_api_key(api_key: str | None) -> str | None:
    return (
        api_key
        or os.environ.get("ZAI_CODING_PLAN_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")  # deprecated, kept for compat
        or None
    )
```

### 5.5 Aprovechar Multimodalidad de GLM-5.2

GLM-5.2 soporta image input. VicoGuard podría:
- Analizar screenshots de errores/dashboards
- Detectar vulnerabilidades visuales en UI (missing auth screens, exposed data)
- Analizar diagramas de arquitectura para identificar puntos débiles

---

## 📊 RESUMEN EJECUTIVO

| Área | Estado | Acción |
|------|--------|--------|
| **Modelo LLM** | VicoGuard en GLM-4.5, Silhouette en GLM-5.2 | **Migrar VicoGuard a 5.2** (1 línea de código) |
| **Credenciales** | Duplicadas, naming confuso | Unificar a `ZAI_CODING_PLAN_KEY` |
| **Endpoints** | `api.z.ai` vs `open.bigmodel.cn` | Estandarizar a `open.bigmodel.cn` |
| **Integración** | Ninguna directa | API bridge o MCP tool |
| **Reutilización** | VicoGuard aislado | Dockerizar + registrar como skill en OpenClaw |
| **Fallback** | Heurístico robusto ✅ | Mantener, agregar tests con GLM-5.2 |

**Bottom line**: VicoGuard y Silhouette usan el mismo provider (Z.ai), el mismo protocolo (OpenAI-compatible), pero están separados por stack (Python vs Node.js) y generación de modelo (4.5 vs 5.2). La integración es directa vía HTTP API o MCP. La migración a GLM-5.2 es trivial (1 línea). El mayor valor está en que Silhouette pueda invocar VicoGuard para scanning automático de repos.

---

*Cami — Research Report v1.0*
