# Plan: MCP `vicoguard-redteam` — integrar el toolkit de red team al proyecto

## Contexto

El proyecto tiene dos mitades complementarias en el repo `VicoGuard-AI`:

- **Defensa** (`main`, suite unificada): un servidor FastAPI en `src/api/main.py` con el
  endpoint `POST /api/v1/telemetry/ingest` que recibe eventos de ataque, los correlaciona
  (`correlate_server_logs`), alimenta el cerebro cognitivo (`ctx.brain.receive_threat`) y
  dispara la alerta de Telegram. Ese endpoint es el "beat" de la demo.
- **Ataque**: `vicoguard-redteam/attack_toolkit.py` — un CLI que genera ataques *controlados*
  (bruteforce, sqli, portscan, dirfuzz, flood, synthetic) y reenvía la telemetría al endpoint
  anterior.

Hoy esos dos lados solo se conectan corriendo el CLI a mano. El objetivo es exponer el toolkit
como un **servidor MCP real** (`vicoguard-redteam`) que cualquier cliente MCP (Claude Code, el
nodo Centinela, otro agente) pueda invocar por el protocolo MCP, siguiendo el mismo patrón que
el `wasp-governor` ya existente (`centinela/guards/governance_guard/mcp_governor_server.py`,
`FastMCP`). Ya existe un prototipo funcional (`vicoguard-redteam/mcp_redteam_server.py`) validado
por handshake stdio; este plan lo convierte en una integración limpia, portable y versionada.

### Hallazgo que condiciona el diseño

El endpoint `/api/v1/telemetry/ingest` en `main` pasó a ser **multi-tenant** y exige
**cookie de sesión** (`user: User = Depends(require_user)`, `src/api/main.py:567`). El toolkit
reenvía con `api_key` en el body y **sin sesión**, por lo que hoy recibiría **401**. La telemetría
se enruta por tenant (`ctx = tenants.get(user.id)`), así que el reenvío necesita un contexto de
usuario real, no solo un token.

## Decisiones

1. **Rama**: nueva rama `feature/mcp-redteam` partiendo de `main` (elección del usuario). Es la
   única rama con el consumidor de telemetría, así que el loop completo (ataque → telemetría →
   cerebro → Telegram) cierra ahí.
2. **Auth del reenvío — recomendación: el MCP hace login demo** (no modificar la API de VicoGuard).
   El MCP mantiene un `requests.Session`, hace `POST /api/v1/auth/login` con credenciales demo
   (y `POST /api/v1/auth/register` como fallback la primera vez), cachea la cookie y reenvía con
   ella. *Por qué* sobre el bypass de api-key: añadir una ruta de telemetría sin sesión a un
   servidor multi-tenant es exactamente la clase de vulnerabilidad que VicoGuard debe *detectar*
   — mal look e irónico; además el brain necesita un tenant real para correlacionar y notificar.
   `register`/`login` ya existen (`src/api/main.py:461` y `/api/v1/auth/login`), así que es
   autocontenido y no toca el lado defensivo.
3. **Ubicación — recomendación: vendorizar dentro del repo** en `redteam/`. "Implementar el MCP
   *para el proyecto*" implica versionarlo con él; un `.mcp.json` que apunta fuera del repo se
   rompe al clonar en otra máquina. La narrativa de "atacante separado" se conserva con un
   subdirectorio propio, pero portable y versionado.

## Implementación

### 1. Vendorizar el toolkit y el server MCP
> **Punto de partida ya existente**: hay un prototipo funcional en
> `/home/project/hackathones/vicoguard-redteam/` (`mcp_redteam_server.py` + `attack_toolkit.py`),
> validado por handshake stdio. **Pero ese directorio es hermano del repo y está fuera de git**
> (no trackeado en ninguna rama), así que hoy el MCP *no es parte del proyecto*: un clon no lo
> tendría y el `.mcp.json` apuntaría a una ruta inexistente. Este paso lo reutiliza como borrador
> —no se reescribe desde cero— y lo convierte en asset versionado.

- Mover a `redteam/` dentro del repo:
  - `redteam/attack_toolkit.py` (desde `vicoguard-redteam/attack_toolkit.py`, sin cambios de lógica).
  - `redteam/mcp_redteam_server.py` (desde el prototipo actual; ajustar el `import attack_toolkit`
    — ya resuelve `sys.path` relativo a su propio directorio, así que sigue funcionando).
  - `redteam/__init__.py` vacío.
  - **No** copiar `__pycache__/`. Añadir `redteam/__pycache__/` a `.gitignore` si hace falta.

### 2. Reenvío autenticado (única lógica nueva)
En `redteam/mcp_redteam_server.py`, añadir un helper propio de forwarding autenticado en vez de
usar `tk.forward_events` para el path con sesión:
- `_vicoguard_session(base_url)`: crea `requests.Session`, intenta `POST /api/v1/auth/login`
  con `VICOGUARD_DEMO_EMAIL`/`VICOGUARD_DEMO_PASSWORD`; si falla con 401, `POST /api/v1/auth/register`
  (que crea cuenta + inicia sesión); devuelve la sesión con la cookie ya puesta. Cachear a nivel
  de módulo para no re-loguear en cada llamada.
- `_authenticated_forward(base_url, events, api_key)`: usa esa sesión para
  `POST /api/v1/telemetry/ingest` con `{"api_key", "events"}` y devuelve el resumen de
  `correlation` que responde el endpoint.
- En `_run_mode`, cuando `args.forward and not args.dry_run and events`, llamar a
  `_authenticated_forward` en lugar de `tk.forward_events`. El CLI (`attack_toolkit.main`)
  mantiene su `forward_events` sin cambios.
- Las 7 tools ya definidas (`synthetic_drill`, `bruteforce_drill`, `sqli_drill`, `portscan_drill`,
  `dirfuzz_drill`, `flood_drill`, `forward_telemetry`) no cambian de firma.

### 3. Configuración MCP
- Registrar `vicoguard-redteam` en `.claude/.mcp.json` (junto a `wasp-governor`), apuntando al
  python del venv del repo y a `redteam/mcp_redteam_server.py`. Seguir la convención de ruta
  absoluta del `wasp-governor` existente.
- Nota (fuera de alcance, documentar): la entrada `wasp-governor` conserva rutas Windows de
  Daniel (`E:\...`) que no corren en este entorno; dejar constancia pero no tocarla en este PR.

### 4. Dependencias y entorno
- `requirements.txt`: confirmar `mcp[cli]==1.12.2` (ya está) y añadir `requests` (el toolkit y el
  forwarding lo usan; hoy no está listado).
- Documentar en `redteam/README.md`: crear venv, `pip install -r requirements.txt`, variables de
  entorno (`VICOGUARD_URL` default `http://localhost:8000`, `VICOGUARD_DEMO_EMAIL`,
  `VICOGUARD_DEMO_PASSWORD`, `VG_API_KEY` default `vg_demo`), y cómo lanzar la API defensiva
  (`uvicorn api.main:app --port 8000` desde `src/`).

### 5. Tests
- `tests/test_redteam_mcp.py` (patrón pytest existente en `tests/`):
  - Registro de las 7 tools (`asyncio.run(mcp.list_tools())`).
  - `synthetic_drill` produce eventos con el shape correcto (`type/source_ip/status_code/path/timestamp`)
    y mezcla amenazas + ruido.
  - Modos con `dry_run=True` no tocan la red y generan eventos.
  - **Seguridad**: un target externo sin `force=True` es rechazado por `attack_toolkit.guard_target`
    (target privado permitido, público bloqueado con `SystemExit`).

## Archivos

- **Nuevos**: `redteam/attack_toolkit.py`, `redteam/mcp_redteam_server.py`, `redteam/__init__.py`,
  `redteam/README.md`, `tests/test_redteam_mcp.py`.
- **Modificados**: `.claude/.mcp.json` (registrar el server), `requirements.txt` (añadir `requests`).
- **Reutilizados sin tocar**: `src/api/main.py` (endpoints `auth/*` y `telemetry/ingest`),
  patrón `FastMCP` de `centinela/guards/governance_guard/mcp_governor_server.py`.

## Qué subir para probar la funcionalidad (inventario)

Tomando `attack_toolkit.py` como **core**, esto es todo lo que debe estar presente para que el loop
sea testeable. Se organiza por origen y por nivel de prueba.

### A. Red team — archivos a commitear en la rama (nuevos)
- `redteam/attack_toolkit.py` — **el core** (ya existe como borrador fuera de git).
- `redteam/mcp_redteam_server.py` — wrapper MCP + reenvío autenticado.
- `redteam/__init__.py`, `redteam/README.md`.
- `tests/test_redteam_mcp.py`.
- Modificar: `.claude/.mcp.json` (registro), `requirements.txt` raíz (añadir `requests`).

### B. Defensivo — YA está en `main`, no se re-sube (viene gratis al ramificar off main)
El endpoint `/api/v1/telemetry/ingest` depende de una cadena que ya vive en `main`:
- `src/api/main.py` (endpoints `auth/register`, `auth/login`, `telemetry/ingest`),
  `src/api/auth.py`, `src/api/tenancy.py`.
- `src/scanner/services/ai_engine.py` (`correlate_server_logs` → LLM, **sin fallback**),
  `cognitive_brain.py` (`ThreatType`/`ThreatSeverity`/`brain`), `notifications.py` (Telegram),
  `security_scanner.py`.
- `src/requirements.txt` (openai, fastapi, uvicorn, requests, python-dotenv, beautifulsoup4).
> Conclusión: **no hay que "subir" código defensivo nuevo**. Ramificar off `main` ya lo trae. Lo que
> falta para *probar* no es código, es **configuración de runtime** (abajo).

### C. Runtime — NO se commitea (secretos), pero es imprescindible para el test real
Copiar `.env.example` → `.env` y rellenar según el nivel de prueba:
- `GEMINI_API_KEY` (gratis en Google AI Studio) **o** `OPENAI_API_KEY` — **requerido para que
  `correlate_server_logs` produzca `real_threats`**; sin clave el endpoint responde 200 pero con
  correlación `UNKNOWN` y **sin alerta**.
- `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` — requeridos para que la alerta se **entregue**.
- `VICOGUARD_DEMO_EMAIL` / `VICOGUARD_DEMO_PASSWORD` — nuevas, para el login del MCP.
- Deps instaladas: venv con `requirements.txt` (MCP) **y** `src/requirements.txt` (server defensivo).

### D. Niveles de prueba (qué se necesita en cada uno)
| Nivel | Qué prueba | Necesita | Alerta Telegram |
|------|-----------|----------|-----------------|
| **1 — solo ataque** | registro de tools, shape de eventos, guard de seguridad, `dry_run`/`synthetic` | solo A + SDK `mcp` | no aplica |
| **2 — loop/auth** | login demo + `telemetry/ingest` responde 200, enrutado por tenant | A + B corriendo (`uvicorn`), sin claves LLM | no (real_threats vacío) |
| **3 — demo completa ("beat")** | correlación real + alerta | A + B + C completo (LLM + Telegram) | **sí** |

## Verificación (end-to-end)

1. **Unit**: `pytest tests/test_redteam_mcp.py -v` (tools registradas, shape de eventos, guard de
   seguridad, dry-run).
2. **Handshake MCP** (sin red defensiva): cliente stdio (`mcp.client.stdio.stdio_client`) lanza
   `redteam/mcp_redteam_server.py`, lista las 7 tools y llama `synthetic_drill(count=2)` → devuelve
   eventos estructurados. (Este patrón ya se validó con el prototipo.)
3. **Loop completo**:
   - Levantar la API defensiva: desde `src/`, `uvicorn api.main:app --port 8000`.
   - Configurar `VICOGUARD_DEMO_EMAIL`/`VICOGUARD_DEMO_PASSWORD` (y `TELEGRAM_BOT_TOKEN` si se
     quiere ver la alerta real).
   - Invocar `synthetic_drill(forward="http://localhost:8000")` desde el MCP → esperado: login/registro
     automático, `POST /telemetry/ingest` responde **200** con `correlation.overall_status` y
     `real_threats`, y (con token) llega la alerta de Telegram.
4. **Regresión**: `pytest tests/ -q` completo en verde.

## Notas abiertas

- El prototipo actual y el `.venv` que se crearon quedaron en la rama `wasp` sin commitear; al
  arrancar en `feature/mcp-redteam` (off main) esos archivos se re-crean en la ubicación nueva
  (`redteam/`). Limpiar el working tree de `wasp` para no dejar residuos.
- `.mcp.json` con ruta absoluta no es portable entre máquinas; documentar que hay que ajustar la
  ruta del python del venv por entorno (misma limitación que el `wasp-governor` actual).
