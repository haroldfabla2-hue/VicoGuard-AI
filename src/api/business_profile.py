"""
VicoGuard AI — Business Profile & Intelligent Onboarding
========================================================
Cuestionario inteligente PRE-ESCANEO que captura el contexto de negocio del
cliente para que el scanner, la IA y el grafo tengan más señal.

El perfil se usa para:
  1. Dar contexto a la IA (prioriza/explica hallazgos según el negocio).
  2. Re-ponderar la severidad de los hallazgos (un secreto expuesto en una
     fintech con tarjetas != una cabecera faltante en un blog personal).
  3. Enriquecer el grafo con un nodo de negocio (el cerebro aprende el contexto).

El diseño es adaptativo: cada pregunta puede depender de respuestas previas
(p.ej. si maneja pagos -> PCI; si el stack es Supabase -> foco en RLS).
La capa "hiper-inteligente" (síntesis del perfil de riesgo + preguntas de
seguimiento) usa el LLM si hay OPENAI_API_KEY; si no, cae a heurística rica.
"""

import os
import json
from typing import Dict, List, Any, Optional


# ══════════════════════════════════════════════════════════════
# Esquema del cuestionario (renderizado como wizard adaptativo)
# ══════════════════════════════════════════════════════════════
# type: single | multi | text | scale
# depends: {field, in:[...]}  -> la pregunta solo aplica si se cumple
QUESTION_SCHEMA: List[Dict[str, Any]] = [
    {
        "id": "sector", "type": "single", "required": True,
        "label": "¿En qué sector opera tu aplicación?",
        "help": "Define el modelo de amenazas y las obligaciones de cumplimiento.",
        "options": [
            {"v": "ecommerce", "l": "E-commerce / Tienda online"},
            {"v": "fintech", "l": "Fintech / Pagos / Banca"},
            {"v": "health", "l": "Salud / Datos médicos"},
            {"v": "saas", "l": "SaaS / Software B2B"},
            {"v": "education", "l": "Educación"},
            {"v": "marketplace", "l": "Marketplace / Plataforma"},
            {"v": "logistics", "l": "Logística / Delivery"},
            {"v": "media", "l": "Medios / Contenido"},
            {"v": "gov", "l": "Gobierno / Sector público"},
            {"v": "personal", "l": "Proyecto personal / Portafolio"},
            {"v": "other", "l": "Otro"},
        ],
    },
    {
        "id": "description", "type": "text", "required": True,
        "label": "En una o dos frases, ¿qué hace tu aplicación?",
        "help": "La IA usa esto para entender tus 'joyas de la corona' y priorizar.",
        "placeholder": "Ej: Vendemos ropa online y guardamos pedidos y datos de clientes en Supabase.",
    },
    {
        "id": "data", "type": "multi", "required": True,
        "label": "¿Qué datos maneja tu aplicación?",
        "help": "Determina la gravedad real de una fuga.",
        "options": [
            {"v": "payments", "l": "Pagos / Tarjetas"},
            {"v": "pii", "l": "Datos personales (nombre, email, teléfono)"},
            {"v": "gov_id", "l": "Documentos de identidad (DNI, pasaporte)"},
            {"v": "health", "l": "Datos de salud"},
            {"v": "credentials", "l": "Credenciales / Contraseñas de usuarios"},
            {"v": "location", "l": "Ubicación / Geodatos"},
            {"v": "none", "l": "Ninguno sensible / público"},
        ],
    },
    {
        "id": "stack", "type": "multi", "required": True,
        "label": "¿Con qué tecnología está construida?",
        "help": "Enfoca el escaneo (p.ej. Supabase -> RLS).",
        "options": [
            {"v": "supabase", "l": "Supabase"},
            {"v": "firebase", "l": "Firebase"},
            {"v": "custom_api", "l": "Backend propio / API"},
            {"v": "wordpress", "l": "WordPress"},
            {"v": "nocode", "l": "No-code (Bubble, Webflow, etc.)"},
            {"v": "static", "l": "Sitio estático"},
            {"v": "unknown", "l": "No estoy seguro"},
        ],
    },
    {
        "id": "surface", "type": "multi", "required": False,
        "label": "¿Qué expone públicamente tu aplicación?",
        "options": [
            {"v": "login", "l": "Inicio de sesión de usuarios"},
            {"v": "payments_flow", "l": "Flujo de pago"},
            {"v": "admin", "l": "Panel de administración"},
            {"v": "api", "l": "API pública"},
            {"v": "uploads", "l": "Subida de archivos"},
        ],
    },
    {
        "id": "users", "type": "single", "required": False,
        "label": "¿Cuántos usuarios/clientes tiene aproximadamente?",
        "options": [
            {"v": "pre", "l": "Aún sin lanzar"},
            {"v": "small", "l": "< 1.000"},
            {"v": "medium", "l": "1.000 – 50.000"},
            {"v": "large", "l": "> 50.000"},
        ],
    },
    {
        "id": "compliance", "type": "multi", "required": False,
        "label": "¿Tienes obligaciones de cumplimiento?",
        "help": "Aparece según los datos que manejas.",
        "options": [
            {"v": "pci", "l": "PCI-DSS (tarjetas)"},
            {"v": "gdpr", "l": "GDPR / Ley de datos personales"},
            {"v": "hipaa", "l": "Salud (HIPAA-equivalente)"},
            {"v": "none", "l": "Ninguna / No estoy seguro"},
        ],
        "depends": {"field": "data", "in": ["payments", "pii", "gov_id", "health"]},
    },
    {
        "id": "concern", "type": "single", "required": False,
        "label": "¿Cuál es tu mayor preocupación de seguridad?",
        "options": [
            {"v": "leak", "l": "Fuga de datos de clientes"},
            {"v": "ato", "l": "Robo de cuentas / accesos"},
            {"v": "downtime", "l": "Caída del servicio"},
            {"v": "defacement", "l": "Que alteren mi sitio"},
            {"v": "unknown", "l": "No lo tengo claro"},
        ],
    },
]

# Sectores donde una exposición de datos es especialmente crítica.
_HIGH_STAKES_SECTORS = {"fintech", "health", "gov", "ecommerce", "marketplace"}
# Datos cuya exposición es intolerable.
_CROWN_DATA = {"payments", "gov_id", "health", "credentials"}
# Categorías del scanner que son "exposición de datos".
_EXPOSURE_CATEGORIES = {"SUPABASE_RLS", "EXPOSED_SECRETS", "EXPOSED_SECRETS_JS", "DIRECTORY_EXPOSURE"}

_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def visible_questions(answers: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Filtra el esquema según dependencias (para wizards server-driven)."""
    out = []
    for q in QUESTION_SCHEMA:
        dep = q.get("depends")
        if dep:
            have = answers.get(dep["field"])
            have = have if isinstance(have, list) else [have]
            if not any(v in dep["in"] for v in have):
                continue
        out.append(q)
    return out


def _bump(sev: str, steps: int = 1) -> str:
    sev = (sev or "MEDIUM").upper()
    if sev not in _SEV_ORDER:
        return sev
    return _SEV_ORDER[min(len(_SEV_ORDER) - 1, _SEV_ORDER.index(sev) + steps)]


def _soften(sev: str, steps: int = 1) -> str:
    sev = (sev or "MEDIUM").upper()
    if sev not in _SEV_ORDER:
        return sev
    return _SEV_ORDER[max(0, _SEV_ORDER.index(sev) - steps)]


def reweight_findings(findings: List[Dict], profile: Dict) -> List[Dict]:
    """Ajusta la severidad de cada hallazgo según el contexto de negocio.

    Escala hacia arriba las exposiciones de datos en negocios de alto riesgo;
    suaviza el ruido en proyectos personales sin datos sensibles.
    """
    if not profile:
        return findings
    sector = profile.get("sector")
    data = set(profile.get("data", []) or [])
    high_stakes = sector in _HIGH_STAKES_SECTORS or bool(data & _CROWN_DATA)
    benign = sector == "personal" and (not data or data == {"none"})

    for f in findings:
        cat = str(f.get("category", "")).upper()
        sev = str(f.get("severity", "MEDIUM")).upper()
        base = sev
        if cat in _EXPOSURE_CATEGORIES and high_stakes:
            sev = _bump(sev, 1)
            if data & _CROWN_DATA and cat in ("SUPABASE_RLS", "EXPOSED_SECRETS", "EXPOSED_SECRETS_JS"):
                sev = "CRITICAL"
        elif benign and cat == "HTTP_HEADERS":
            sev = _soften(sev, 1)
        if sev != base:
            f["severity"] = sev
            f["severity_original"] = base
            f["severity_reason"] = _reweight_reason(cat, profile, sev, base)
    return findings


def _reweight_reason(cat: str, profile: Dict, sev: str, base: str) -> str:
    sector = profile.get("sector", "tu negocio")
    if sev in ("CRITICAL", "HIGH") and base != sev:
        return (f"Elevado a {sev}: tu negocio ({sector}) maneja datos sensibles, "
                f"una exposición aquí tiene impacto directo.")
    if base != sev:
        return f"Ajustado a {sev} para tu contexto ({sector})."
    return ""


def recompute_counts(findings: List[Dict]) -> Dict[str, int]:
    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"),
        "high": sum(1 for f in findings if str(f.get("severity", "")).upper() == "HIGH"),
        "medium": sum(1 for f in findings if str(f.get("severity", "")).upper() == "MEDIUM"),
    }


def to_scan_context(profile: Dict) -> str:
    """Texto compacto de contexto de negocio para el prompt del LLM."""
    if not profile:
        return ""
    sec = profile.get("sector", "n/a")
    desc = profile.get("description", "")
    data = ", ".join(profile.get("data", []) or []) or "n/a"
    stack = ", ".join(profile.get("stack", []) or []) or "n/a"
    comp = ", ".join(profile.get("compliance", []) or []) or "ninguna declarada"
    concern = profile.get("concern", "n/a")
    return (f"Sector: {sec}. Descripción: {desc}. Datos que maneja: {data}. "
            f"Stack: {stack}. Cumplimiento: {comp}. Mayor preocupación: {concern}.")


def heuristic_risk_summary(profile: Dict) -> Dict[str, Any]:
    """Perfil de riesgo sin LLM (fallback determinista pero rico)."""
    sector = profile.get("sector", "other")
    data = set(profile.get("data", []) or [])
    crown = sorted(data & _CROWN_DATA)
    threat = []
    if data & {"payments"}:
        threat.append("Robo de datos de pago (PCI)")
    if data & {"pii", "gov_id"}:
        threat.append("Fuga de datos personales")
    if "credentials" in data:
        threat.append("Robo de cuentas (credential stuffing)")
    if not threat:
        threat.append("Defacement / abuso de recursos")
    posture = "alto" if (sector in _HIGH_STAKES_SECTORS or crown) else "medio" if data else "bajo"
    return {
        "generated_by": "heuristic",
        "risk_posture": posture,
        "crown_jewels": crown or (["contenido público"] if sector == "personal" else ["datos de clientes"]),
        "top_threats": threat[:3],
        "focus": _focus_for_stack(profile.get("stack", [])),
        "narrative": (f"Como negocio de tipo '{sector}', tu superficie crítica gira en torno a "
                      f"{', '.join(crown) if crown else 'tus datos de clientes'}. "
                      f"VicoGuard priorizará exposiciones de datos y accesos."),
    }


def _focus_for_stack(stack: List[str]) -> List[str]:
    f = []
    if "supabase" in stack:
        f.append("Row Level Security (RLS) en Supabase")
    if "firebase" in stack:
        f.append("Reglas de seguridad de Firebase")
    if "wordpress" in stack:
        f.append("Plugins/paneles expuestos")
    if "custom_api" in stack:
        f.append("Autenticación y secretos del backend")
    return f or ["Cabeceras de seguridad y secretos en el frontend"]


def ai_risk_summary(profile: Dict) -> Dict[str, Any]:
    """Síntesis del perfil de riesgo con LLM (si hay OPENAI_API_KEY)."""
    key = os.getenv("OPENAI_API_KEY", "")
    if not key or key.startswith("sk-xxx"):
        return heuristic_risk_summary(profile)
    try:
        from openai import OpenAI
        client = OpenAI()
        sys_prompt = (
            "Eres un consultor de ciberseguridad para Pymes. Dado el perfil de negocio, "
            "devuelve SOLO JSON con esta forma: {\"risk_posture\":\"bajo|medio|alto\","
            "\"crown_jewels\":[..],\"top_threats\":[..3],\"focus\":[..],\"narrative\":\"..\","
            "\"followup_questions\":[..2]}. Español, claro para no técnicos.")
        resp = client.chat.completions.create(
            model="gpt-4o", temperature=0.3, response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": json.dumps(profile, ensure_ascii=False)},
            ],
        )
        out = json.loads(resp.choices[0].message.content)
        out["generated_by"] = "gpt-4o"
        return out
    except Exception as e:
        out = heuristic_risk_summary(profile)
        out["ai_error"] = str(e)
        return out
