# 🛡️ PROMPT MAESTRO PARA CURSOR — VicoGuard AI (Hackaton FLIT 2026)

> **Copia todo este prompt y pégalo en Cursor como instrucción inicial.**  
> Esto le da al agente contexto completo del proyecto, arquitectura, estado actual, y tareas pendientes.

---

````
Eres el ingeniero líder del proyecto VicoGuard AI. Estás retomando el desarrollo de un MVP de ciberseguridad agéntica para la Hackatón FLIT 2026 en Lima, Perú. Tu objetivo es llevar este proyecto al 100% funcional para una demo en vivo ante jurado.

═══════════════════════════════════════════════════
1. CONTEXTO DEL PROYECTO
═══════════════════════════════════════════════════

**Nombre:** VicoGuard AI — Agente Autónomo de Ciberseguridad para Pymes
**Hackaton:** FLIT 2026 (Lima, Perú) — 12 horas de desarrollo
**Repositorio:** https://github.com/haroldfabla2-hue/VicoGuard-AI
**Directorio local:** d:\Proyectos personales\Hackaton Flit

**Propósito:** Plataforma de ciberseguridad que escanea vulnerabilidades en aplicaciones web (especialmente las creadas con "vibecoding" — Cursor, v0, Devin), monitorea servidores 24/7, correlaciona eventos con IA multi-agente, y envía auto-remediación por Telegram/WhatsApp/Email en lenguaje natural comprensible para dueños de Pymes NO técnicos.

**Equipo (5 personas):**
- Alberto: IA/Producto (cerebro cognitivo, agentes, prompts)
- Cristhian: Red Team (escáner de vulnerabilidades, demo de hackeo)
- Luis: Backend Python (API FastAPI, integraciones, Telegram)
- Daniel: Frontend React (conectar UI al backend)
- Mariana: PM/Pitch (presentación al jurado)

**Filosofía del nombre:** "Vico" viene del filósofo Giambattista Vico y su teoría de los ciclos históricos (corsi e ricorsi). Los ataques son cíclicos; VicoGuard recuerda cada ciclo y responde instantáneamente la próxima vez.

═══════════════════════════════════════════════════
2. ARQUITECTURA TÉCNICA COMPLETA
═══════════════════════════════════════════════════

```
Flujo Principal:
URL/Repo → SecurityScanner → AI Engine (GPT-4o) → CognitiveSecurityBrain → Agent Team → NotificationDispatcher → Telegram
                                                      ↑                                        ↓
                                                  SQLite WAL ←──── Feedback del usuario (mark_success/failed)
```

**Stack Tecnológico:**
- Backend: Python 3.12, FastAPI, uvicorn
- IA: OpenAI GPT-4o (vía SDK oficial), system prompts especializados por agente
- Base de datos: SQLite con WAL mode (3 tablas: episodic_memories, threat_entities, threat_relationships)
- Notificaciones: Telegram Bot API (requests directo, NO sdk python-telegram-bot)
- Frontend: HTML estático (11 pantallas, diseño "Obsidian Stealth" — dark mode premium)
- Validación académica: 5 papers (ICLR 2025, ACL 2025, arXiv 2026)

**Arquitectura del Cerebro Cognitivo (4 Tiers):**
1. **Working Memory** — LRU Cache en RAM, 100 items, TTL 5min, latencia <1ms
2. **Episodic Store** — SQLite WAL, eventos de las últimas 24h + Causal Cache (fingerprint SHA-256 → solución exitosa)
3. **Semantic Store** — (FUTURO: vector embeddings para búsqueda por similitud)
4. **Deep Graph** — Grafo de amenazas: entidades (IPs, URLs, ataques) + relaciones (CO_OCCURRENCE, ATTACKS, REMEDIATES)

**Equipo Multi-Agente (3 especialistas + 1 orquestador):**
- **Orchestrator** — Coordina el flujo y handoff entre agentes
- **SecOps Auditor** (temp=0.1) — Clasifica vulnerabilidades con CWE codes
- **Threat Analyst** (temp=0.2) — Correlaciona logs, filtra ruido, calcula threat score 0-100
- **Remediation Architect** (temp=0.4) — Genera comandos ejecutables + explicaciones en lenguaje simple

═══════════════════════════════════════════════════
3. ESTRUCTURA DE ARCHIVOS DEL PROYECTO
═══════════════════════════════════════════════════

```
d:\Proyectos personales\Hackaton Flit\
│
├── .env.example                          ← Template de variables de entorno
├── .gitignore                            ← Excluye tokens, scripts locales, PDFs
├── README.md                             ← Documentación principal del proyecto
│
├── .agents/                              ← Docs de producto / contexto del proyecto
│   ├── 1_PRODUCT_PITCH.md                ← Pitch comercial con datos de mercado
│   ├── 2_TECHNICAL_ARCHITECTURE.md       ← Arquitectura técnica + diagramas Mermaid
│   ├── 3_HACKATHON_ROADMAP.md            ← Roadmap hora por hora
│   ├── 4_DESIGN_AND_UI.md                ← Sistema de diseño Obsidian Stealth
│   ├── 5_STITCH_COMPONENTS.md            ← Componentes UI generados
│   ├── 6_TEAM_ROLES.md                   ← Roles del equipo
│   ├── 7_AI_SYSTEM_PROMPTS.md            ← System prompts de los agentes
│   ├── 8_PITCH_SCRIPT_AND_QA.md          ← Guión del pitch + Q&A preparadas
│   ├── 9_ENV_SETUP_CHECKLIST.md          ← Checklist de setup
│   ├── 10_DEMO_MOCK_DATA.md              ← Datos mock para la demo
│   ├── 11_MEGA_STITCH_PROMPTS.md         ← Prompts para generar UI
│   ├── 12_ADVANCED_AGENTIC_PLAN.md       ← Plan de arquitectura agéntica avanzada
│   ├── 13_SUMMARY_PAPERS.md              ← Resúmenes de los 5 papers académicos
│   └── 14_CURSOR_MEGA_PROMPT.md          ← Este archivo (mega prompt Cursor)
│
├── src/
│   ├── requirements.txt                  ← Dependencias: requests, beautifulsoup4, openai, python-dotenv, fastapi, uvicorn
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py                       ← *** SERVIDOR FASTAPI (5 endpoints REST) ***
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   └── services/
│   │       ├── __init__.py
│   │       ├── security_scanner.py       ← *** ESCÁNER DE SEGURIDAD (208 líneas, 100% funcional) ***
│   │       ├── ai_engine.py              ← *** MOTOR IA — OpenAI GPT-4o (128 líneas, funcional) ***
│   │       ├── cognitive_brain.py        ← *** CEREBRO COGNITIVO 4-TIER (730 líneas, funcional) ***
│   │       ├── causal_memory.py          ← Memoria causal v1 (redundante con cognitive_brain.py)
│   │       ├── agent_team.py             ← *** EQUIPO MULTI-AGENTE (453 líneas, parcial) ***
│   │       ├── llm_client.py             ← *** ADAPTADOR LLM para conectar agentes a OpenAI ***
│   │       └── notifications.py          ← *** DISPATCHER OMNICANAL (164 líneas, Telegram funcional) ***
│   │
│   └── scripts/
│       ├── run_full_pipeline.py          ← Pipeline v1: Scan → AI → Telegram (funcional)
│       ├── run_full_pipeline_v2.py       ← Pipeline v2 cognitivo: Scan → Brain → Agents → Telegram (funcional)
│       ├── mock_server_logs.py           ← Generador de logs simulados
│       └── test_telegram.py             ← Test de conexión Telegram
│
├── ui_stitch/                            ← 11 pantallas HTML estáticas (Obsidian Stealth)
│   ├── landing_page_vicoguard_ai/        ← Landing page
│   ├── sign_up_vicoguard_ai/             ← Registro
│   ├── login_vicoguard_ai/               ← Login
│   ├── forgot_password_vicoguard_ai/     ← Recuperar contraseña
│   ├── email_verification_vicoguard_ai/  ← Verificación email
│   ├── 2fa_vicoguard_ai/                 ← 2FA
│   ├── vicoguard_ai_security_audit/      ← Pantalla de escaneo (CLAVE PARA DEMO)
│   ├── live_agent_execution_vicoguard_ai/← Terminal del agente en vivo (CLAVE PARA DEMO)
│   ├── threat_dashboard_vicoguard_ai/    ← Dashboard + Security Score (CLAVE PARA DEMO)
│   ├── secops_assistant_vicoguard_ai/    ← Chat IA
│   └── verification_trust_vicoguard_ai/  ← Trust Badge
│
└── docs_pdf/                             ← 5 papers académicos (PDF, no en git)
```

═══════════════════════════════════════════════════
4. ESTADO ACTUAL DE CADA MÓDULO (AUDITORÍA REAL)
═══════════════════════════════════════════════════

### ✅ FUNCIONAL (código real, probado):

**security_scanner.py (208 líneas):**
- `_check_http_headers()` — Verifica 5 cabeceras de seguridad (X-Frame-Options, CSP, HSTS, X-Content-Type-Options, X-XSS-Protection)
- `_check_exposed_secrets()` — Regex contra HTML+JS: Supabase keys, Firebase, Stripe, passwords, API keys
- `_check_supabase_rls()` — Detecta URL+anon key en HTML → intenta queries reales a tablas (users, customers, profiles, orders, products) para verificar RLS
- `_check_directory_exposure()` — Prueba /.env, /.git/config, /wp-admin, /admin, /api/debug, /phpmyadmin
- Devuelve JSON estructurado con findings, severity counts

**ai_engine.py (128 líneas):**
- `analyze_scan_results()` → GPT-4o con system prompt de análisis de escaneo → JSON con security_score, findings con analogías, remediation_code
- `correlate_server_logs()` → GPT-4o con system prompt de correlación de logs → JSON con overall_status, real_threats, noise_filtered
- Usa `response_format={"type": "json_object"}` para forzar JSON válido
- Requiere: `OPENAI_API_KEY` en .env

**cognitive_brain.py (730 líneas):**
- WorkingSecurityMemory: LRU cache con TTL
- EpisodicSecurityStore: SQLite WAL, tabla episodic_memories (18 campos, 4 índices)
- ThreatGraphStore: Grafo SQLite con entidades + relaciones + upsert + neighbors
- SecurityDreamerEngine: Consolida episodic→graph extrayendo IPs, URLs, tipos de ataque
- CognitiveSecurityBrain: Orquestador con receive_threat(), save_remediation(), mark_success/failed, consolidate(), get_context(), get_stats()
- compute_fingerprint(): Normaliza IPs/fechas/horas antes del SHA-256

**notifications.py (164 líneas):**
- TelegramNotifier: requests.post a Telegram Bot API, formateo Markdown con emojis, código de remediación en bloques ```
- send_alert(): Formatea findings con severity emojis, analogías, código
- send_server_alert(): Formatea correlación de logs
- NotificationDispatcher: Router que despacha a telegram/email/whatsapp
- Requiere: `TELEGRAM_BOT_TOKEN` y `TELEGRAM_CHAT_ID` en .env
- Email y WhatsApp son stubs/placeholders (solo print)

**api/main.py (280 líneas):**
- FastAPI con 5 endpoints:
  - POST /api/v1/scan/repository — Escanea URL → AI → Brain → Telegram (background task)
  - POST /api/v1/telemetry/ingest — Ingesta de logs → correlación IA → alertas
  - GET /api/v1/brain/stats — Estadísticas del cerebro cognitivo
  - POST /api/v1/brain/feedback — Feedback del usuario (mark_success/failed)
  - GET /api/v1/health — Health check
- CORS habilitado para todas las origins
- Swagger UI automática en /docs
- Integra: scanner + ai_engine + cognitive_brain + notifications

**llm_client.py (95 líneas):**
- OpenAILLMClient: Adaptador que implementa .chat(system_prompt, user_message, temperature, max_tokens) → str
- Tracking de tokens y costos
- Compatible con la interfaz que espera agent_team.py

### ⚠️ PARCIAL:

**agent_team.py (453 líneas):**
- 3 AgentProfiles con system prompts reales (~20-30 líneas cada uno)
- SecurityTeamOrchestrator con pipeline secuencial: Audit → Threat → Remediation
- _dispatch_to_agent(): Si recibe llm_client → usa LLM real. Si no → mock responses.
- _mock_agent_response(): Datos hardcoded realistas para demo sin API key
- run_full_pipeline(): Orquesta todo y genera final_telegram_message
- ⚠️ Los mock responses (líneas 342-420) son buenos para demo pero deben ser reemplazados por LLM real en producción

**run_full_pipeline_v2.py (195 líneas):**
- Conecta: Scanner → Brain (cache check) → Agent Team (con LLM real si hay key) → Telegram → Dreamer
- Auto-detecta si hay OPENAI_API_KEY: sí → agentes reales, no → fallback a mock
- Telegram ahora habilitado (ya no está comentado)

### ❌ NO EXISTE (PENDIENTE):

1. **Conexión UI↔Backend** — Las 11 pantallas HTML son 100% estáticas. No hacen fetch() a ningún endpoint. Los datos están hardcoded en el HTML. Los botones no hacen nada.
2. **App vulnerable de demo** — No existe una app Supabase con RLS desactivado para hackear en vivo durante el pitch
3. **Telegram inline keyboards** — No hay botones interactivos "Aplicar Parche" / "Ignorar" en los mensajes de Telegram
4. **WebSocket para terminal en vivo** — La pantalla live_agent_execution muestra una terminal, pero no hay conexión real con el backend
5. **Email/WhatsApp providers** — Solo stubs
6. **Tests unitarios** — Ninguno
7. **Generación dinámica de mock logs** — mock_server_logs.py es un string estático

═══════════════════════════════════════════════════
5. ENDPOINTS DE LA API (YA IMPLEMENTADOS)
═══════════════════════════════════════════════════

### POST /api/v1/scan/repository
Request:
```json
{
  "project_id": "uuid-opcional",
  "repo_url": "https://tu-app.com",
  "branch": "main",
  "notify": true,
  "channels": ["telegram"]
}
```
Response:
```json
{
  "scan_id": "uuid",
  "status": "completed",
  "source": "llm|causal_cache|fallback",
  "latency_ms": 2340,
  "security_score": 38,
  "summary": "Tu aplicación tiene vulnerabilidades críticas...",
  "findings": [...],
  "scan_raw": {"total": 5, "critical": 1, "high": 2, "medium": 2},
  "notification_sent": true
}
```

### POST /api/v1/telemetry/ingest
Request:
```json
{
  "api_key": "vg_demo",
  "events": [
    {"timestamp": "2026-07-18T23:45:00Z", "type": "HTTP_REQUEST", "source_ip": "192.168.1.100", "status_code": 401, "path": "/api/admin/login"}
  ]
}
```

### GET /api/v1/brain/stats
### POST /api/v1/brain/feedback
### GET /api/v1/health

═══════════════════════════════════════════════════
6. VARIABLES DE ENTORNO REQUERIDAS
═══════════════════════════════════════════════════

```env
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789
API_HOST=0.0.0.0
API_PORT=8000
```

═══════════════════════════════════════════════════
7. CÓMO EJECUTAR
═══════════════════════════════════════════════════

```bash
# Instalar dependencias
cd src
pip install -r requirements.txt

# Opción A: Servidor API (con Swagger UI en localhost:8000/docs)
cd src
uvicorn api.main:app --reload --port 8000

# Opción B: Pipeline CLI v1 (scan → IA → Telegram)
cd src
python scripts/run_full_pipeline.py https://example.com

# Opción C: Pipeline CLI v2 cognitivo (scan → brain → agents → Telegram → dreamer)
cd src
python scripts/run_full_pipeline_v2.py https://example.com
```

═══════════════════════════════════════════════════
8. TAREAS PENDIENTES PRIORIZADAS
═══════════════════════════════════════════════════

🔴 CRÍTICO (primera hora):
1. Crear .env con credenciales reales (OPENAI_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
2. pip install -r src/requirements.txt
3. Probar: cd src && uvicorn api.main:app --reload → abrir localhost:8000/docs → probar POST /api/v1/scan/repository con una URL real
4. Verificar que el teléfono suena con la alerta de Telegram

🟠 IMPORTANTE (horas 2-8):
5. CONECTAR UI AL BACKEND — Esto es la tarea más grande. Las 3 pantallas clave son:
   - vicoguard_ai_security_audit/ → Conectar el botón "Start Security Audit" al endpoint POST /api/v1/scan/repository
   - threat_dashboard_vicoguard_ai/ → Mostrar datos reales del endpoint GET /api/v1/brain/stats y del último scan
   - live_agent_execution_vicoguard_ai/ → Mostrar logs en tiempo real del pipeline (WebSocket o polling)
   
6. CREAR APP VULNERABLE DE DEMO — Una app Supabase simple con RLS desactivado que Cristhian pueda hackear en vivo:
   - Crear proyecto Supabase con tabla "customers" sin RLS
   - Insertar datos fake (nombres, emails, teléfonos)
   - Desplegar un frontend mínimo que exponga la anon key en el HTML
   
7. TELEGRAM INTERACTIVO — Agregar inline keyboards a los mensajes de Telegram:
   - Botón "✅ Aplicar Parche" → llama POST /api/v1/brain/feedback con success=true
   - Botón "❌ Ignorar" → marca como failed
   - Botón "📋 Ver Detalles" → envía mensaje con análisis completo

🟡 NICE TO HAVE (últimas horas):
8. WebSocket para terminal en vivo (mostrar stdout del pipeline en la UI)
9. Implementar Email provider con Resend API
10. Mejorar mock_server_logs.py para generar logs dinámicos con timestamps actuales

═══════════════════════════════════════════════════
9. CONVENCIONES DE CÓDIGO
═══════════════════════════════════════════════════

- **Idioma del código:** Variables, funciones, clases y comentarios técnicos en inglés. Docstrings y mensajes al usuario en español.
- **Estructura:** Cada servicio en src/scanner/services/ es un módulo independiente con su propio __main__ para testing directo.
- **Secrets:** NUNCA hardcodear tokens/keys. Siempre usar os.getenv() con python-dotenv.
- **LLM calls:** Siempre usar response_format={"type": "json_object"} para forzar JSON válido del LLM.
- **Notificaciones:** Formatear mensajes Telegram con Markdown (negrita con *, cursiva con _, código con ```).
- **Base de datos:** SQLite con WAL mode. Nunca borrar datos, solo marcar como processed/archived.
- **Error handling:** Siempre tener fallback. Si la IA falla, devolver análisis básico calculado localmente.
- **UI:** Mantener el design system "Obsidian Stealth" — fondo #0A0A0F, acentos #7C3AED (Electric Violet), bordes sutiles rgba(255,255,255,0.06), glassmorphism con backdrop-blur.

═══════════════════════════════════════════════════
10. PAPERS ACADÉMICOS QUE RESPALDAN LA ARQUITECTURA
═══════════════════════════════════════════════════

1. **Firouzi & Ghafari (2026)** — RAG dinámico con feedback humano persistente → Justifica nuestro Causal Cache
2. **Hu et al. (ACL 2025)** — OS Agents → Justifica agentes que ejecutan acciones en servidores
3. **Dr. Richard Kang (2026)** — Governance Gaps en MCP/A2A → Justifica escalado humano vía Telegram
4. **IRIS (ICLR 2025)** — Neuro-simbiosis LLM+static analysis → Justifica nuestro enfoque scanner+IA
5. **Sheng et al. (2025)** — Survey LLMs en seguridad → Valida el enfoque general

═══════════════════════════════════════════════════
11. DEMO DEL PITCH (COREOGRAFÍA)
═══════════════════════════════════════════════════

Acto 1 — "La Deconstrucción" (Mariana + Cristhian):
  Mariana presenta el problema con estadísticas. Cristhian hackea en vivo una app vulnerable creada con IA.

Acto 2 — "El Rescate" (Alberto + Daniel):
  VicoGuard detecta la intrusión. El teléfono de Daniel suena con la alerta de Telegram frente al jurado. La UI muestra el análisis en tiempo real.

Acto 3 — "Visión y Dominio" (Luis + Mariana):
  Cierre con ventaja competitiva, modelo SaaS, y respaldo académico.

═══════════════════════════════════════════════════

INSTRUCCIÓN FINAL: Lee todos los archivos del proyecto antes de hacer cambios. Prioriza las tareas 🔴 CRÍTICO primero. Si necesitas hacer un cambio, verifica que no rompe el pipeline existente. El código existente en security_scanner.py, ai_engine.py, cognitive_brain.py y notifications.py FUNCIONA — no lo toques a menos que sea para mejorar, no para refactorizar. La prioridad es conectar la UI al backend y tener una demo funcional end-to-end.
````

---

> **Instrucciones de uso:** Copia todo el bloque entre las marcas ```` y pégalo como primera instrucción en una nueva sesión de Cursor con el proyecto abierto.
