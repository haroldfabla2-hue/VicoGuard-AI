# 🛡️ VicoGuard AI & WASP Sentinel — Suite de Ciberseguridad Agéntica Unificada

> **FLIT Hackathon 2026 (Arequipa)**  
> La fusión definitiva del ecosistema de seguridad de Silhouette: un nodo centinela local (WASP) con ledger criptográfico y gobernanza de agentes, conectado a un panel de control empresarial y cerebro cognitivo multi-tenant (VicoGuard AI).

---

## 💡 ¿Qué es?

Esta suite unifica dos capas de ciberseguridad agéntica complementarias:

1. **WASP Core (Capa Local / Sentinel):**
   * **Auditoría Estática:** Escanea repositorios locales usando Semgrep y Gitleaks integrados.
   * **Gobernanza MCP (Model Context Protocol):** Un servidor de políticas que intercepta comandos de terminal (ej. de Claude Code o Cursor) para bloquear acciones de riesgo (como `git push --force` o leaks de credenciales) usando un contrato de capacidades (`capability_contract.yaml`).
   * **Ledger Inmutable:** Registra todas las amenazas y decisiones de gobernanza en una cadena de hashes criptográfica (Hash-Chain SHA-256) a prueba de alteraciones.
   * **Bot de Control:** Permite consultar y gestionar el centinela local por Telegram (/status, /alertas, /explicar).

2. **VicoGuard AI Core (Capa Central / Hub Multi-Tenant):**
   * **Servidor API FastAPI:** Orquesta el escaneo remoto de URLs, telemetría y logs de servidores.
   * **Aislamiento Físico Multi-Tenant:** Registro y sesión con PBKDF2-HMAC-SHA256, asignando a cada usuario su propia base de datos física SQLite (`src/data/tenants/<user_id>.db`) para evitar cualquier filtrado cruzado de datos.
   * **Cerebro Cognitivo de 4 Capas:**
     * *Working Memory:* LRU cache en memoria (<1ms).
     * *Episodic Memory:* Causal cache (normaliza huellas digitales SHA-256 para resolver amenazas conocidas en 0ms y con 0 tokens).
     * *Canonical Node Memory:* Resuelve identidades semánticas fusionando hallazgos duplicados bajo una misma entidad en un grafo de amenazas.
   * **Panel de Control UI Premium:** Interfaz oscura ("Obsidian Stealth") con gráficos de score de seguridad y terminal del agente en tiempo real.

3. **WASP Network (Capa Colaborativa):**
   * Servidor de agregación en red para publicar de forma opt-in y anónima las métricas e incidentes de múltiples centinelas locales del equipo en un dashboard global.

---

## 🚀 Setup Rápido

1. **Clonar e instalar dependencias:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # En Windows
   pip install -r src/requirements.txt
   pip install -r requirements.txt      # dependencias del nodo wasp
   ```

2. **Configurar Variables de Entorno:**
   Copia el archivo `.env.example` a `.env` y rellena las claves:
   ```bash
   cp .env.example .env
   ```

3. **Verificar Bot de Telegram:**
   ```bash
   python src/scripts/test_telegram.py
   ```

---

## 🖥️ Ejecución y Pruebas

### 🔵 Capa 1: Servidor API & Web UI (VicoGuard)

Levanta el servidor central en el puerto 8000:
```bash
cd src
uvicorn api.main:app --reload --port 8000
```

* **Swagger Docs:** `http://localhost:8000/docs`
* **Centro de Seguridad (App):** `http://localhost:8000/ui/login`
* **Target Demo Vulnerable:** `http://localhost:8000/demo/vulnerable` (omite headers de seguridad, expone tokens falsos y simula un Supabase sin RLS)

#### Flujo del Pitch (VicoGuard):
1. Regístrate en `/ui/signup`.
2. En el panel, pulsa **"Usar target de demo"** y ejecuta **"Escanear ahora"**.
3. Se detectarán 10 hallazgos (incluyendo el Supabase RLS deshabilitado mock). El score caerá a ~5/100 y recibirás la alerta formateada en tu Telegram.
4. Escanea la misma URL de nuevo. El sistema aplicará **Canonical Node Memory** y no duplicará la amenaza; en su lugar, fusionará la evidencia en el mismo nodo del grafo.

---

### 🟡 Capa 2: Centinela Local & Ledger Criptográfico (WASP)

Corre un escaneo local del repositorio desde la consola:
```bash
python -m centinela.main scan tests/fixtures/vuln_sample_repo
```

Esto ejecutará Semgrep + Gitleaks sobre la app de prueba vulnerable, deduplicará el ruido y escribirá el resultado en el Ledger criptográfico (`centinela.ledger`).

* **Verificar el estado del Ledger:**
  El bot de Telegram del centinela (inicializado con `python -m centinela.telegram_bot.bot`) permite interactuar con el ledger local:
  * `/status` — Muestra el estado del centinela y si el Ledger es íntegro y válido.
  * `/alertas` — Lista las últimas vulnerabilidades registradas.
  * `/explicar <id>` — Usa IA para generar una explicación simple y un plan de remediación del hallazgo.

---

### 🟢 Capa 3: Red Global (WASP Network)

Levanta el panel en red (opcional) para agregar múltiples nodos:
```bash
python -m wasp_network.server
```
Abre `http://localhost:8080` en tu navegador para ver la red de centinelas activos y las amenazas anonimizadas del grupo.

---

## 📁 Estructura del Proyecto Unificado

```
├── .agents/                    # Dossiers de producto, pitch y documentación académica
├── .claude/                    # Configuraciones de MCP para integración con Claude Code
├── bin/                        # Binarios de escaneo descargables (Semgrep, Gitleaks)
├── centinela/                  # Capa Local (Guards, Ledger inmutable, Command Interpreter, Bot)
│   ├── attack/                 # Simulador y demo de contención de ataques
│   ├── guards/                 # Wrappers de Semgrep, Gitleaks, y Governance Guard
│   ├── interpreter/            # Consultas al Ledger con IA
│   ├── ledger/                 # Hash-chain criptográfica
│   └── telegram_bot/           # Bot local de interacción
├── config/                     # Configuraciones de nodos
├── src/                        # Capa Central (FastAPI, Cognitive Brain, Tenancy, Scanners)
│   ├── api/                    # Servidor API REST, Autenticación y Tenancy aislado
│   ├── scanner/services/       # Scanner remoto, AI Engine, Causal Memory, Notificaciones
│   └── scripts/                # Scripts utilitarios y pipelines de ejecución
├── ui_stitch/                  # Mockups estáticos legacy en alta fidelidad
├── wasp_network/               # Capa Colaborativa (Agregador de red, Web Dashboard)
├── web/                        # Frontend dinámico profesional (auth-aware, multi-tenant)
└── requirements.txt            # Dependencias del nodo local wasp
```
