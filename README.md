# 🛡️ VicoGuard AI — Hackathon FLIT 2026

> **Agente Autónomo de Ciberseguridad para Pymes**
> Escaneo + Monitoreo de Servidores + Correlación IA + Auto-Remediación por Telegram

---

## Demo rápida (MVP)

### 1. Requisitos

```bash
pip install -r requirements.txt
cp .env.example .env   # si aún no tienes .env
```

Edita `.env` y pon valores reales (sin esto, Telegram/OpenAI no funcionan; el scanner sí):

| Variable | Obligatorio para | Notas |
|----------|------------------|--------|
| `OPENAI_API_KEY` | Análisis IA (GPT) | Sin key → fallback heurístico |
| `TELEGRAM_BOT_TOKEN` | Alertas Telegram | Placeholder `123456…` = desactivado |
| `TELEGRAM_CHAT_ID` | Alertas Telegram | Chat/grupo destino |
| `API_HOST` / `API_PORT` | Servidor | Default `0.0.0.0` / `8000` |

### 2. Arrancar API + UI

```bash
cd src
uvicorn api.main:app --reload --port 8000
```

| URL | Qué es |
|-----|--------|
| http://localhost:8000/ui/login | Iniciar sesión |
| http://localhost:8000/ui/signup | Crear cuenta |
| http://localhost:8000/ui/app | Centro de Seguridad (escaneo + hallazgos + memoria) |
| http://localhost:8000/docs | Swagger OpenAPI |
| http://localhost:8000/demo/vulnerable | Target demo (secretos fake + sin headers) |
| http://localhost:8000/api/v1/health | Health check |

> Pantallas antiguas de `ui_stitch` siguen accesibles en `/ui/legacy/<pantalla>`.

### 3. Flujo de pitch (2 minutos)

1. Abre **/ui/signup** y crea una cuenta (o inicia sesión en **/ui/login**).
2. En el Centro de Seguridad pulsa **"Usar target de demo"** → **"Escanear ahora"**.
3. (Opcional) marca *Notificar por Telegram* si ya tienes token real.
4. Observa el **agente en vivo**, el **score**, los **hallazgos** y la **memoria canónica**.
5. Vuelve a escanear la misma URL → verás `BRAIN: canonical hit … (merged evidence #2)`.

El target demo expone anon key / password / API key **falsos**, omite headers de seguridad
y sirve un **Supabase mock con RLS deshabilitado** (`/demo/supabase`, datos falsos) → el
scanner reporta **10 hallazgos, 2 CRITICAL de RLS** (tablas `users` y `customers`), score
heurístico **~5** sin OpenAI. Todo auto-contenido: no necesita ningún Supabase externo.

Scan async por API (recomendado para auto-escanear el mismo servidor):

```bash
curl -X POST http://localhost:8000/api/v1/scan/start \
  -H "Content-Type: application/json" \
  -d "{\"repo_url\":\"http://127.0.0.1:8000/demo/vulnerable\",\"notify\":false}"
```

Luego poll: `GET /api/v1/scan/{scan_id}` o abre `/ui/live`.

> **Momento "cerebro" del pitch:** escanea `/demo/vulnerable` **dos veces**. En el 1er
> scan la terminal live muestra `BRAIN: nueva entidad canónica VG-VULN-…`; en el 2º
> muestra `BRAIN: canonical hit VG-VULN-… (merged evidence #2)`. VicoGuard **no** duplica
> la vulnerabilidad: apila evidencia sobre el mismo nodo canónico
> (Canonical Node Memory — ver [.agents/15_CANONICAL_NODE_MEMORY.md](.agents/15_CANONICAL_NODE_MEMORY.md)).
> Inspecciona el grafo: `GET /api/v1/brain/entities` y `GET /api/v1/brain/entity/{canonical_id}`.

> Usa siempre `/api/v1/scan/start` (async + thread pool) para escanear `/demo/vulnerable` en el mismo proceso. El endpoint sync `/scan/repository` puede hacer timeout al pedirse a sí mismo.

### 4. Telegram en vivo (botones inline)

Con `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` reales en `.env`, escanea con `notify:true` y
la alerta suena. Para que los botones **Aplicar Parche / Ignorar** respondan en vivo, Telegram
necesita un webhook público:

```bash
# 1) Levanta la API   → cd src && uvicorn api.main:app --port 8000
# 2) Túnel público    → ngrok http 8000     (copia la URL https://XXXX.ngrok-free.app)
# 3) Registra webhook → python scripts/setup_telegram_webhook.py set https://XXXX.ngrok-free.app
# 4) Verifica         → python scripts/setup_telegram_webhook.py info
# 5) Limpieza         → python scripts/setup_telegram_webhook.py delete
```

El script no imprime el token y aborta si sigue siendo placeholder.

---

## Cuentas y aislamiento multi-tenant

Plataforma con **cuentas de usuario reales** y **aislamiento físico por cuenta**:

- **Auth:** registro/login con hashing **PBKDF2-HMAC-SHA256** (stdlib, sin bcrypt nativo)
  y **sesiones en cookie HTTP-only + SameSite** (token aleatorio guardado hasheado en BD,
  revocable). Endpoints de datos protegidos con dependencia `require_user`.
- **Multi-tenant:** cada usuario tiene su **propia base de datos** (`src/data/tenants/<user_id>.db`)
  con su cerebro, memoria canónica y scans. La BD global (`vicoguard_app.db`) guarda **solo**
  `users` y `sessions`. No hay filtrado por `WHERE user_id`: los datos de un usuario **no existen**
  en la BD de otro → imposible mezclar información entre clientes de seguridad.
- **Front-end nuevo** (`web/`): diseño sobrio tipo SaaS de seguridad (near-black, un acento,
  bordes hairline). Páginas: `login`, `signup`, `app` (Centro de Seguridad).

| Endpoint | Descripción |
|----------|-------------|
| `POST /api/v1/auth/register` | Crea cuenta + inicia sesión (setea cookie) |
| `POST /api/v1/auth/login` | Inicia sesión |
| `POST /api/v1/auth/logout` | Cierra sesión (revoca) |
| `GET /api/v1/auth/me` | Usuario actual |

Config prod: `VG_COOKIE_SECURE=1` (cookies solo por HTTPS). Datos de tenants ignorados por git.

---

## Quick Start (documentación del equipo)

1. Lee el **[9_ENV_SETUP_CHECKLIST.md](9_ENV_SETUP_CHECKLIST.md)** y configura las variables de entorno
2. Instala dependencias: `pip install -r requirements.txt`
3. Prueba el bot de Telegram: `python scripts/test_telegram.py` (requiere token real)
4. Levanta el servidor: `cd src && uvicorn api.main:app --reload --port 8000`

---

## Estructura del Proyecto

### Documentación (leer en este orden)
| # | Archivo | Para quién | Contenido |
|---|---------|-----------|-----------|
| 1 | [1_PRODUCT_PITCH.md](1_PRODUCT_PITCH.md) | Todos | Problema, solución 360°, modelo de negocio, coreografía del pitch |
| 2 | [6_TEAM_ROLES.md](6_TEAM_ROLES.md) | Todos | Roles, habilidades y reglas de oro del equipo |
| 3 | [3_HACKATHON_ROADMAP.md](3_HACKATHON_ROADMAP.md) | Todos | Plan hora por hora (12h) con tareas por persona |
| 4 | [2_TECHNICAL_ARCHITECTURE.md](2_TECHNICAL_ARCHITECTURE.md) | Devs | Stack, módulos, triggers, diagrama de flujo |
| 5 | [7_AI_SYSTEM_PROMPTS.md](7_AI_SYSTEM_PROMPTS.md) | Alberto | 3 System Prompts del LLM listos para copiar/pegar |
| 6 | [9_ENV_SETUP_CHECKLIST.md](9_ENV_SETUP_CHECKLIST.md) | Luis | Variables de entorno y checklist de setup |
| 7 | [5_STITCH_COMPONENTS.md](5_STITCH_COMPONENTS.md) | Daniel | Índice de las 11 pantallas HTML exportadas |
| 8 | [8_PITCH_SCRIPT_AND_QA.md](8_PITCH_SCRIPT_AND_QA.md) | Mariana | Guion del pitch + preguntas difíciles del jurado |
| 9 | [10_DEMO_MOCK_DATA.md](10_DEMO_MOCK_DATA.md) | Todos | Datos mock de emergencia para la demo |
| 10 | [4_DESIGN_AND_UI.md](4_DESIGN_AND_UI.md) | Daniel | Filosofía visual y prompts de Stitch |
| 11 | [11_MEGA_STITCH_PROMPTS.md](11_MEGA_STITCH_PROMPTS.md) | Daniel | 4 Mega Prompts para generar pantallas adicionales |

### Front-end (diseño profesional nuevo)
```
web/
├── login.html            # /ui/login
├── signup.html           # /ui/signup
├── app.html              # /ui/app  (Centro de Seguridad)
└── assets/
    ├── styles.css        # Design system (near-black + acento contenido)
    └── app.js            # Lógica del dashboard (auth-aware, cookies)
```
> `ui_stitch/` se conserva como legacy en `/ui/legacy/<pantalla>`.

### Código
```
src/
├── api/
│   ├── main.py                 # FastAPI — REST + auth + UI + /demo/vulnerable
│   ├── auth.py                 # Cuentas + sesiones (PBKDF2 + cookies)
│   └── tenancy.py              # Aislamiento por usuario (BD por tenant)
├── scanner/services/
│   ├── security_scanner.py     # Motor de escaneo
│   ├── ai_engine.py            # Motor de IA
│   ├── cognitive_brain.py      # Memoria episódica / causal cache (fingerprint)
│   ├── canonical_memory.py     # Canonical Node Memory — dedup por identidad semántica
│   └── notifications.py        # Telegram + dispatcher
└── scripts/
    ├── setup_telegram_webhook.py
    ├── test_telegram.py
    └── mock_server_logs.py
```
