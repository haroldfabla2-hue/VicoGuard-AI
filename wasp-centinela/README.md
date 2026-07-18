# WASP Centinela

Nodo local de seguridad para vibe coders — la mitad "Capa 1 / local" del sistema descrito en el material de producto (**WASP Centinela** local + **VicoGuard Hub** en la nube, ver `../src/`). Construido para **FLIT Hackathon 2026** (Arequipa, 18 jul) y **Hack-Nation**.

## Qué es

Un nodo Centinela escanea un repo (Semgrep + Gitleaks), correlaciona y prioriza los hallazgos con GLM-4.5, avisa por Telegram en un solo mensaje claro, y gobierna las acciones de la propia sesión de Claude Code (bloqueando cosas como `git push --force`) — todo con un registro de auditoría encadenado (hash-chain SHA-256) que no se puede editar después sin que se note.

`centinela/orchestrator/unify.py` es el punto de entrada que une este nodo con **VicoGuard Hub** (`../src/api/main.py`): recibe una URL y un repo, corre el escaneo DAST del Hub (con consentimiento informado explícito) + el escaneo SAST de este nodo + una demo de ataque local, y genera un informe único con todo hasheado en el mismo ledger. Ver `centinela/main.py unify --help`.

## Setup rápido

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
cp .env.example .env   # completar TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID y ANTHROPIC_API_KEY (key de Z.ai/GLM, pese al nombre)
```

Gitleaks (`bin/gitleaks.exe`) no viene versionado — descargarlo de https://github.com/gitleaks/gitleaks/releases y colocarlo en `bin/`.

### Guardia de gobernanza (hook de Claude Code)

`centinela/guards/governance_guard/` expone un hook `PreToolUse` real que bloquea comandos prohibidos por `capability_contract.yaml` durante una sesión de Claude Code. La config de ejemplo (`.claude/settings.json`/`.mcp.json`) no se versiona porque usa rutas absolutas de una máquina específica — para activarlo en la tuya, creá tu propio `.claude/settings.json` apuntando `command`/`args` a tu propio `.venv\Scripts\python.exe` y a `centinela/guards/governance_guard/audit_hook.py` con ruta absoluta.

## Estructura

```
centinela/
  guards/            # SAST (Semgrep+Gitleaks) + gobernanza MCP
  attack/            # simulador de ataque, SOLO localhost (regla de seguridad no negociable)
  interpreter/        # GLM-4.5 vía endpoint del Coding Plan de Z.ai, con fallback heurístico
  ledger/              # hash-chain SHA-256, a prueba de manipulación
  adapters/             # normaliza hallazgos DAST de VicoGuard Hub al schema de este ledger
  orchestrator/          # unify.py (entrypoint), consent.py, notify.py, report.py, cronos.py
  telegram_bot/           # bot reactivo (/status /alertas /explicar)
wasp_network/         # dashboard de red opt-in entre nodos (stretch)
tests/fixtures/       # repo de prueba deliberadamente vulnerable, para demos y tests
capability_contract.yaml   # reglas de gobernanza (qué puede/no puede hacer el agente de código)
```

## Estado

Sistema unificado verificado de punta a punta con datos reales: escaneo DAST+SAST combinado, ataque simulado local, informe generado, y cadena de hashes íntegra (`hash_chain.verify_chain() == True`). Suite de tests: 58/58.
