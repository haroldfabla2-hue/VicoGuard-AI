"""
VicoGuard AI — GLM Team Client (Z.ai Coding Plan)
====================================================
Reconecta el SecurityTeamOrchestrator (equipo de 3 agentes: SecOps Auditor,
Threat Analyst, Remediation Architect — ver agent_team.py) a un LLM real,
usando el endpoint OpenAI-compatible del Coding Plan de Z.ai (modelo GLM-4.5)
en lugar de OpenAI/Gemini, porque hoy VicoGuard-AI no tiene una key real de
OPENAI_API_KEY/GEMINI_API_KEY configurada.

No reescribe agent_team.py ni llm_client.py (salvo el parametro opcional
base_url agregado a OpenAILLMClient) — solo los conecta con la config
correcta.

Uso:
    from scanner.services.glm_team_client import run_team_analysis
    result = run_team_analysis(scan_results, api_key="...")
"""
import os
import logging
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from scanner.services.agent_team import SecurityTeamOrchestrator
from scanner.services.llm_client import OpenAILLMClient

logger = logging.getLogger("vicoguard.glm_team")

GLM_BASE_URL = "https://api.z.ai/api/coding/paas/v4"
GLM_MODEL = "glm-4.5"

# The GLM Coding Plan key lives in the sibling `wasp/` project's .env (single
# source of truth -- confirmed live and working there), not in VicoGuard-AI's
# own .env. When this module runs inside the real `uvicorn api.main:app`
# server process, os.getenv("ANTHROPIC_API_KEY") is empty because nothing
# loads wasp/.env into this process -- confirmed live (build_glm_team_orchestrator
# raised "No se encontro API key" in ~1s, not the ~140s a real GLM call takes).
# load_dotenv() with override=False only fills env vars that are NOT already
# set, so this never clobbers a real OPENAI_API_KEY/GEMINI_API_KEY/
# ANTHROPIC_API_KEY the operator may have configured directly for VicoGuard-AI.
_WASP_ENV_PATH = Path(__file__).resolve().parents[4] / "wasp" / ".env"
if _WASP_ENV_PATH.exists():
    load_dotenv(_WASP_ENV_PATH, override=False)


def build_glm_team_orchestrator(api_key: Optional[str] = None) -> SecurityTeamOrchestrator:
    """
    Construye un SecurityTeamOrchestrator real, con su llm_client apuntado
    al endpoint GLM Coding Plan de Z.ai.

    La api_key se resuelve en este orden:
      1. Parametro api_key explicito.
      2. Variable de entorno GLM_CODING_API_KEY.
      3. Variable de entorno ANTHROPIC_API_KEY (fallback — nombre historico
         que trae la misma key desde wasp/.env sin tener que duplicarla).

    Levanta RuntimeError con mensaje claro si no hay key disponible o si el
    cliente LLM no pudo inicializarse (ej: paquete openai no instalado).
    """
    resolved_key = api_key or os.getenv("GLM_CODING_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not resolved_key:
        raise RuntimeError(
            "No se encontro API key para GLM Coding Plan (Z.ai). "
            "Definir GLM_CODING_API_KEY (o ANTHROPIC_API_KEY como fallback) "
            "en el entorno, o pasarla explicitamente a "
            "build_glm_team_orchestrator(api_key=...) / run_team_analysis(api_key=...)."
        )

    try:
        llm_client = OpenAILLMClient(
            model=GLM_MODEL,
            api_key=resolved_key,
            base_url=GLM_BASE_URL,
        )
    except Exception as exc:
        raise RuntimeError(
            f"No se pudo inicializar el cliente LLM para GLM Coding Plan (Z.ai): {exc}"
        ) from exc

    return SecurityTeamOrchestrator(llm_client=llm_client)


def run_team_analysis(scan_results: dict, api_key: Optional[str] = None) -> dict:
    """
    Construye el orchestrator con build_glm_team_orchestrator() y corre el
    pipeline real de 3 agentes (run_full_pipeline) sobre scan_results (la
    forma real que devuelve SecurityScanner.run_full_scan()).

    Devuelve el resultado tal cual lo da el orchestrator, sin transformarlo
    (el adaptador de schema es responsabilidad de otra pieza, en wasp).

    Levanta RuntimeError con mensaje claro si falta la api_key, si el
    cliente LLM no pudo construirse, o si el pipeline explota antes de
    devolver un resultado (errores de red durante cada llamada a un agente
    individual quedan reflejados dentro del resultado por agent_team.py,
    que no interrumpe el pipeline por diseno).
    """
    if not scan_results:
        raise ValueError("scan_results no puede estar vacio.")

    orchestrator = build_glm_team_orchestrator(api_key=api_key)

    try:
        return orchestrator.run_full_pipeline(scan_results=scan_results, server_logs="")
    except Exception as exc:
        raise RuntimeError(
            f"Fallo el pipeline del equipo de agentes GLM (Z.ai Coding Plan): {exc}"
        ) from exc
