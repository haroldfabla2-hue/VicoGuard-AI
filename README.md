# WASP

Copiloto de seguridad para vibe coders + red de nodos opt-in entre equipos del hackathon.

Este repo es el sitio oficial de trabajo del proyecto para **FLIT Hackathon 2026** (Arequipa, 18 jul) y **Hack-Nation**. Todo el código que se entrega al evento vive acá — no en la carpeta de investigación/dossiers que lo rodea.

## Qué es

Un nodo Centinela escanea un repo (Semgrep + Gitleaks), correlaciona y prioriza los hallazgos con un LLM, avisa por Telegram en un solo mensaje claro, y gobierna las acciones de la propia sesión de Claude Code (bloqueando cosas como `git push --force`) — todo con un registro de auditoría encadenado (hash-chain SHA-256) que no se puede editar después sin que se note. Si el tiempo alcanza, cada nodo puede sumarse de forma opt-in a una Red WASP: un panel en vivo que muestra los hallazgos anonimizados de todos los equipos que instalaron el mismo Centinela durante el evento.

Plan completo de construcción: `C:\Users\marro\.claude\plans\detallame-paso-a-paso-atomic-valley.md`.
Propuesta original con sustento académico: `..\PROPUESTA_WASP.md`.

## Setup rápido

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
cp .env.example .env   # completar TELEGRAM_BOT_TOKEN y ANTHROPIC_API_KEY
```

## Estructura

```
centinela/           # Capa 1 — nodo local (guardias, intérprete, ledger, bot)
wasp_network/         # Capa 2 — agregación entre nodos (stretch)
tests/fixtures/       # repo de prueba deliberadamente vulnerable, para demos y tests
capability_contract.yaml   # reglas de gobernanza (qué puede/no puede hacer el agente de código)
```

## Estado

Ver el plan de construcción para el detalle fase por fase, checkpoints de verificación, y la regla de corte si el tiempo aprieta el día del evento.
