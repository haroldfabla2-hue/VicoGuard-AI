"""
VicoGuard AI — AI Engine (Motor de Inteligencia Artificial)
===========================================================
Este módulo se encarga de enviar los resultados del escaneo al LLM
y recibir el análisis en lenguaje natural con auto-remediación.
Alberto: Aquí va la orquestación de la IA.
"""
import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Auto-detect client provider: Gemini vs OpenAI
openai_key = os.getenv("OPENAI_API_KEY")
gemini_key = os.getenv("GEMINI_API_KEY")

if gemini_key:
    client = OpenAI(
        api_key=gemini_key,
        base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
    )
    DEFAULT_MODEL = "gemini-1.5-flash"
else:
    client = OpenAI(api_key=openai_key)
    DEFAULT_MODEL = "gpt-4o"

# --- System Prompts (copiados de 7_AI_SYSTEM_PROMPTS.md) ---
SYSTEM_PROMPT_SCAN_ANALYSIS = """
Eres VicoGuard AI, un experto en ciberseguridad ofensiva que trabaja exclusivamente para dueños de pequeñas empresas (Pymes) que NO tienen conocimientos técnicos.

CONTEXTO: Has recibido los resultados crudos de un escaneo de seguridad automático sobre la aplicación web del usuario. Tu trabajo es:
1. Analizar cada hallazgo técnico.
2. Clasificar la severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO).
3. Traducir el riesgo técnico a un impacto de negocio que un dueño de tienda entienda (usa analogías del mundo real).
4. Generar el código exacto o los pasos precisos para solucionar cada vulnerabilidad.

REGLAS ESTRICTAS:
- NUNCA uses jerga técnica sin explicarla primero con una analogía simple.
- SIEMPRE genera código de remediación funcional y seguro.
- Responde ÚNICAMENTE en formato JSON válido con esta estructura:

{
  "security_score": 0-100,
  "summary": "Resumen ejecutivo en 2 oraciones máximo.",
  "findings": [
    {
      "id": "VG-XXX",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title_business": "Explicación en lenguaje simple",
      "analogy": "Analogía del mundo real",
      "impact": "Qué puede pasar si no se arregla",
      "remediation_steps": ["paso 1", "paso 2"],
      "remediation_code": "código exacto para arreglar",
      "status": "UNRESOLVED"
    }
  ]
}
"""

SYSTEM_PROMPT_LOG_CORRELATION = """
Eres VicoGuard AI, un analista de seguridad de servidores que trabaja para dueños de Pymes sin conocimientos técnicos.

CONTEXTO: Has recibido un lote de eventos/logs de servidor. Tu trabajo es:
1. Correlacionar todos los eventos (NO envíes una alerta por cada evento individual).
2. Identificar patrones de ataque (fuerza bruta, escaneo de puertos, scraping, DDoS, errores masivos).
3. Separar el RUIDO de las AMENAZAS REALES.
4. Generar un resumen ejecutivo y un protocolo de acción.

Responde ÚNICAMENTE en formato JSON válido:

{
  "period": "Última hora",
  "overall_status": "UNDER_ATTACK|SUSPICIOUS|HEALTHY",
  "threat_summary": "Resumen en lenguaje simple.",
  "events_analyzed": 0,
  "noise_filtered": 0,
  "real_threats": [
    {
      "type": "BRUTE_FORCE|DDOS|DATA_LEAK|MISCONFIG",
      "description": "Descripción simple",
      "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
      "recommendation": "Qué hacer",
      "action_command": "comando exacto"
    }
  ],
  "noise_explained": "Por qué ciertos eventos son ruido inofensivo."
}
"""


def analyze_scan_results(scan_results: dict) -> dict:
    """Envía resultados del escaneo al LLM y devuelve análisis en lenguaje natural."""
    response = client.chat.completions.create(
        model=DEFAULT_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT_SCAN_ANALYSIS},
            {"role": "user", "content": f"Analiza estos resultados de escaneo:\n\n{json.dumps(scan_results, indent=2, ensure_ascii=False)}"}
        ],
        temperature=0.3,
        response_format={"type": "json_object"},
    )

    return json.loads(response.choices[0].message.content)


def correlate_server_logs(log_text: str) -> dict:
    """Envía logs de servidor al LLM y devuelve correlación inteligente."""
    response = client.chat.completions.create(
        model=DEFAULT_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT_LOG_CORRELATION},
            {"role": "user", "content": f"Correlaciona estos logs de servidor:\n\n{log_text}"}
        ],
        temperature=0.3,
        response_format={"type": "json_object"},
    )

    return json.loads(response.choices[0].message.content)


# --- Testing directo ---
if __name__ == "__main__":
    # Test con datos mock
    mock_scan = {
        "target_url": "https://tienda-demo.com",
        "findings": [
            {
                "severity": "CRITICAL",
                "title_technical": "Supabase RLS Disabled on customers table",
                "category": "SUPABASE_RLS",
            }
        ]
    }
    print("🧠 Enviando a la IA para análisis...")
    result = analyze_scan_results(mock_scan)
    print(json.dumps(result, indent=2, ensure_ascii=False))
