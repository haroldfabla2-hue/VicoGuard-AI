# `vicoguard-redteam` — MCP del toolkit de Red Team

Expone el toolkit ofensivo de VicoGuard (`attack_toolkit.py`) como un **servidor
MCP real** (`vicoguard-redteam`). Cualquier cliente MCP (Claude Code, el nodo
Centinela, otro agente) puede lanzar un *drill* de ataque **controlado** y reenviar
la telemetría a `POST /api/v1/telemetry/ingest`, donde la IA la correlaciona y
dispara la alerta de Telegram — el "beat" de la demo.

Sigue el mismo patrón `FastMCP` que el `wasp-governor`
(`centinela/guards/governance_guard/mcp_governor_server.py`).

## Componentes

- `attack_toolkit.py` — el core. Genera ataques controlados (`bruteforce`, `sqli`,
  `portscan`, `dirfuzz`, `flood`, `synthetic`, `tail`) y produce eventos con el
  shape que espera el endpoint de telemetría. También es CLI: `python attack_toolkit.py synthetic --forward http://localhost:8000`.
- `mcp_redteam_server.py` — envuelve el toolkit con **una tool por modo** más
  `forward_telemetry`. Añade el **reenvío autenticado** (única lógica nueva).

## Seguridad

El toolkit **solo** permite objetivos en localhost / rangos privados. Cualquier
otro host requiere `force=True` y asumir que tienes permiso explícito
(`attack_toolkit.guard_target`). Estas tools son para tu propio señuelo / DVWA.

## Auth del reenvío

`/api/v1/telemetry/ingest` es **multi-tenant** y exige **cookie de sesión**
(`require_user`). Un POST con solo `api_key` recibiría **401**. Por eso el MCP
mantiene su propia `requests.Session`: hace `POST /api/v1/auth/login` con las
credenciales demo (y `POST /api/v1/auth/register` la primera vez), cachea la
cookie por base URL y reenvía con ella. **No** se añade una ruta de telemetría
sin sesión a la API defensiva — sería justo la clase de vulnerabilidad que
VicoGuard debe detectar, y el brain necesita un tenant real para correlacionar.

## Tools

| Tool | Modo | Eventos |
|------|------|---------|
| `synthetic_drill` | fabrica una ráfaga sin tocar la red (Plan B) | mezcla + ruido |
| `bruteforce_drill` | logins fallidos contra `target` | `BRUTE_FORCE` |
| `sqli_drill` | payloads SQLi | `SQLI_ATTEMPT` |
| `portscan_drill` | scan TCP de puertos comunes | `PORT_SCAN` |
| `dirfuzz_drill` | rutas sensibles (`/.env`, `/admin`…) | `DIR_ENUM` |
| `flood_drill` | ráfaga de peticiones (DoS suave) | `HTTP_FLOOD` |
| `forward_telemetry` | reenvía una lista de eventos ya generada | — |

Cada `*_drill` acepta `forward` (URL base de VicoGuard), `dry_run` (no toca la
red) y, salvo `synthetic`, `force` para objetivos externos.

## Puesta en marcha

```bash
# 1. venv + dependencias del MCP (desde la raíz del repo)
python -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. (para el loop completo) dependencias + API defensiva
.venv/bin/pip install -r src/requirements.txt
cd src && ../.venv/bin/uvicorn api.main:app --port 8000
```

El servidor MCP ya está registrado en `.claude/.mcp.json`. La ruta es **absoluta**
(igual que `wasp-governor`), así que ajústala al `python` de tu venv por entorno.

### Variables de entorno

| Variable | Default | Para qué |
|----------|---------|----------|
| `VICOGUARD_DEMO_EMAIL` | `redteam@vicoguard.local` | login automático del MCP |
| `VICOGUARD_DEMO_PASSWORD` | **(requerida, sin default)** | login automático del MCP |

`VICOGUARD_DEMO_PASSWORD` **no** tiene default en el código a propósito: no se
hardcodea ninguna credencial. Defínela por entorno (o en tu `.env`) antes de
reenviar; si falta, el reenvío falla con un error claro (las tools de solo
generación / `dry_run` siguen funcionando sin ella). El `api_key` de telemetría
por defecto es `vg_demo` (`attack_toolkit.DEFAULT_API_KEY`).

Para la **demo completa** (alerta real) el server defensivo necesita además
`GEMINI_API_KEY` **o** `OPENAI_API_KEY` (para que `correlate_server_logs` produzca
`real_threats`) y `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (para entregar la
alerta). Sin clave LLM el endpoint responde `200` pero con correlación `UNKNOWN`
y sin alerta. Copia `.env.example` → `.env` y rellénalo.

## Verificación

```bash
# Unit (no toca la red)
.venv/bin/pytest tests/test_redteam_mcp.py -v

# Loop completo (con la API en :8000)
#   invoca synthetic_drill(forward="http://localhost:8000") desde el cliente MCP
#   → login/registro automático, POST /telemetry/ingest 200, correlación + alerta
```
