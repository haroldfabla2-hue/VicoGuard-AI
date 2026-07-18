"""
VicoGuard AI — API Server (FastAPI)
====================================
Servidor REST multi-tenant: escaneo, IA, cerebro cognitivo y notificaciones,
con cuentas de usuario reales y AISLAMIENTO por usuario (cada cuenta tiene su
propia base de datos; ver api/tenancy.py). Nada de datos compartidos entre
usuarios ni entre clientes de seguridad.

Uso:
    cd src
    uvicorn api.main:app --reload --port 8000

Auth:
    POST /api/v1/auth/register  → crea cuenta + inicia sesión (cookie)
    POST /api/v1/auth/login     → inicia sesión (cookie HTTP-only)
    POST /api/v1/auth/logout    → cierra sesión
    GET  /api/v1/auth/me        → usuario actual

Datos (requieren sesión, operan solo sobre los datos del usuario):
    POST /api/v1/scan/repository | /api/v1/scan/start
    GET  /api/v1/scan/{scan_id} | /api/v1/scan/latest
    POST /api/v1/telemetry/ingest
    GET  /api/v1/brain/stats | /api/v1/brain/entities | /api/v1/brain/entity/{id}
    POST /api/v1/brain/feedback
    POST /api/v1/telegram/webhook   (callback público del bot)
    GET  /api/v1/health
"""
import os
import sys
import json
import time
import uuid
import secrets
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Response, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Paths
SRC_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = SRC_DIR.parent
UI_DIR = PROJECT_ROOT / "ui_stitch"
WEB_DIR = PROJECT_ROOT / "web"

sys.path.insert(0, str(SRC_DIR))

# Cargar .env desde la raíz del proyecto (no solo desde cwd)
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv()  # fallback cwd

from scanner.services.security_scanner import SecurityScanner
from scanner.services.ai_engine import analyze_scan_results, correlate_server_logs
from scanner.services.notifications import NotificationDispatcher
from scanner.services.glm_team_client import run_team_analysis
from scanner.services.cognitive_brain import (
    CognitiveSecurityBrain,
    ThreatSeverity,
    ThreatType,
)
from api.auth import AuthService, AuthError, User, SESSION_COOKIE
from api.tenancy import TenancyManager, UserContext
import api.business_profile as business_profile

# ============================================================
# App Setup
# ============================================================

# Swagger/OpenAPI deshabilitado por defecto (endurecimiento prod). Habilitar con
# VG_ENABLE_DOCS=1 en desarrollo.
_ENABLE_DOCS = os.getenv("VG_ENABLE_DOCS", "0") == "1"

app = FastAPI(
    title="VicoGuard AI",
    description="Agente Autónomo de Ciberseguridad para Pymes — API REST",
    version="2.0.0-hackathon",
    docs_url="/docs" if _ENABLE_DOCS else None,
    redoc_url="/redoc" if _ENABLE_DOCS else None,
    openapi_url="/openapi.json" if _ENABLE_DOCS else None,
)

# Cookies de sesión: same-origin (la UI se sirve desde este mismo host).
# Se permiten orígenes localhost con credenciales para desarrollo.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Cabeceras de seguridad en TODA respuesta (el propio scanner las exige)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Nota: ocultar `Server: uvicorn` se hace en el proxy (Caddy `header -Server`)
    # o corriendo uvicorn con --no-server-header; setearlo aquí duplicaría la cabecera.
    # HSTS solo cuando la petición llegó por HTTPS (directa o detrás del proxy)
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if proto == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # CSP: self + Google Fonts (usadas por la UI). 'unsafe-inline' necesario por los
    # <script>/<style> inline de las páginas de auth y del dashboard.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'"
    )
    return response

# Servicios globales (NO contienen datos de usuarios de seguridad)
dispatcher = NotificationDispatcher()
auth_service = AuthService(db_path=str(SRC_DIR / "vicoguard_app.db"))
tenants = TenancyManager(base_dir=str(SRC_DIR / "data" / "tenants"))

# Cookie Secure solo en producción (HTTPS). En localhost debe ir en False.
COOKIE_SECURE = os.getenv("VG_COOKIE_SECURE", "0") == "1"

# Registro efímero para enrutar callbacks de Telegram al usuario correcto.
# token corto -> {"user_id", "record_id", "scan_id"}
feedback_tokens: dict = {}

# Thread pool para que las llamadas HTTP del scanner puedan golpear esta misma
# API (p.ej. /demo/vulnerable) sin bloquear el worker único de uvicorn.
_scan_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vg-scan")


# ============================================================
# Modelos Pydantic
# ============================================================

class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = ""
    company: Optional[str] = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class ScanRequest(BaseModel):
    """Solicitud de escaneo de repositorio/URL."""
    project_id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_url: str = Field(..., description="URL del sitio web o repositorio a escanear")
    branch: Optional[str] = "main"
    notify: Optional[bool] = True
    channels: Optional[list] = ["telegram"]
    use_agent_team: Optional[bool] = False
    """Si True, usa el equipo de 3 agentes (SecOps Auditor, Threat Analyst,
    Remediation Architect -- ver scanner/services/agent_team.py) via el
    endpoint GLM Coding Plan de Z.ai, en vez de la llamada única a
    analyze_scan_results(). Default False porque el equipo completo tarda
    ~140s (confirmado en verificación real) contra unos pocos segundos de
    la llamada única -- dejalo en True solo cuando el pitch necesita
    mostrar los 3 roles actuando, no como comportamiento por defecto."""


class TelemetryRequest(BaseModel):
    """Solicitud de ingesta de telemetría de servidor."""
    api_key: Optional[str] = "vg_demo"
    events: list = Field(..., description="Lista de eventos/logs del servidor")


class FeedbackRequest(BaseModel):
    """Feedback del usuario sobre una remediación."""
    threat_fingerprint: str
    success: bool
    notes: Optional[str] = ""


class SettingsRequest(BaseModel):
    """Solicitud de actualización de configuraciones del usuario."""
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    alert_level: Optional[str] = "ALL"  # ALL | CRITICAL_ONLY | HIGH_AND_CRITICAL
    remediation_tone: Optional[str] = "concise"  # concise | technical | explanatory


class BusinessProfileRequest(BaseModel):
    """Respuestas del cuestionario inteligente pre-escaneo."""
    sector: str
    description: str
    data: list = Field(default_factory=list)
    stack: list = Field(default_factory=list)
    surface: Optional[list] = Field(default_factory=list)
    users: Optional[str] = "pre"
    compliance: Optional[list] = Field(default_factory=list)
    concern: Optional[str] = "leak"


class PlanRequest(BaseModel):
    """Actualización simulada del plan SaaS."""
    plan: str


class RemediationSendRequest(BaseModel):
    """Enviar remediación(es) del último scan al Telegram del usuario."""
    scan_id: Optional[str] = None
    finding_index: Optional[int] = None  # None + all=False -> primer hallazgo
    send_all: Optional[bool] = False


# ============================================================
# Autenticación — dependencias
# ============================================================

def get_current_user(request: Request) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE)
    return auth_service.user_for_token(token)


def require_user(request: Request) -> User:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sesión requerida. Inicia sesión.")
    return user


def _set_session_cookie(response: Response, token: str, request: Request = None):
    # Secure automático cuando la petición llegó por HTTPS (directa o vía proxy).
    secure = COOKIE_SECURE
    if request is not None:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto == "https":
            secure = True
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=7 * 24 * 3600,
        path="/",
    )


def _user_public(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "company": user.company,
        "created_at": user.created_at,
    }


# ============================================================
# Helpers — Scan pipeline con eventos en vivo (por usuario)
# ============================================================

def _append_event(ctx: UserContext, scan_id: str, level: str, message: str, agent: str = "SYSTEM"):
    """Agrega un evento al stream del scan (aislado por usuario)."""
    job = ctx.scan_jobs.get(scan_id)
    if not job:
        return
    job["events"].append({
        "ts": datetime.utcnow().strftime("%H:%M:%S"),
        "level": level,  # INFO | WARN | ALERT | OK | REASONING
        "agent": agent,
        "message": message,
    })
    job["updated_at"] = datetime.utcnow().isoformat()


def _classify_scan(scan_results: dict) -> tuple:
    """Clasifica hallazgos del scanner a ThreatType / ThreatSeverity del cerebro."""
    if scan_results.get("critical_count", 0) > 0:
        severity = ThreatSeverity.CRITICAL
    elif scan_results.get("high_count", 0) > 0:
        severity = ThreatSeverity.HIGH
    elif scan_results.get("medium_count", 0) > 0:
        severity = ThreatSeverity.MEDIUM
    elif scan_results.get("total_findings", 0) > 0:
        severity = ThreatSeverity.LOW
    else:
        severity = ThreatSeverity.NONE

    cats = " ".join(
        str(f.get("category", "")) for f in scan_results.get("findings", [])
    ).upper()
    if "SECRET" in cats or "EXPOSED" in cats:
        threat_type = ThreatType.SECRET_EXPOSED
    elif "RLS" in cats or "SUPABASE" in cats:
        threat_type = ThreatType.RLS_DISABLED
    elif scan_results.get("total_findings", 0) > 0:
        threat_type = ThreatType.RECONNAISSANCE
    else:
        threat_type = ThreatType.UNKNOWN
    return threat_type, severity


def _resolve_brain_record_id(ctx: UserContext, payload: str) -> Optional[str]:
    """Resuelve id de memoria episódica desde record_id o fingerprint (del usuario)."""
    if not payload:
        return None
    import sqlite3
    with sqlite3.connect(ctx.brain.db_path) as conn:
        row = conn.execute(
            """
            SELECT id FROM episodic_memories
            WHERE id = ? OR threat_fingerprint = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (payload, payload),
        ).fetchone()
    return row[0] if row else None


def _register_feedback_token(user_id: str, record_id: str, scan_id: str) -> str:
    """Crea un token corto para enrutar el callback de Telegram al usuario correcto."""
    token = secrets.token_urlsafe(9)
    feedback_tokens[token] = {"user_id": user_id, "record_id": record_id, "scan_id": scan_id}
    # Poda simple para no crecer sin límite en la demo.
    if len(feedback_tokens) > 500:
        for k in list(feedback_tokens.keys())[:100]:
            feedback_tokens.pop(k, None)
    return token


def _new_job(scan_id: str, target_url: str, status: str = "running") -> dict:
    now = datetime.utcnow().isoformat()
    return {
        "scan_id": scan_id, "status": status, "target_url": target_url,
        "events": [], "result": None, "created_at": now, "updated_at": now,
    }


def _run_scan_pipeline(ctx: UserContext, scan_id: str, request: ScanRequest) -> dict:
    """Pipeline completo: Scanner → Brain → Canonical → IA → Telegram (por usuario)."""
    start_time = time.time()
    job = ctx.scan_jobs.setdefault(scan_id, _new_job(scan_id, request.repo_url))
    job["status"] = "running"

    try:
        _append_event(ctx, scan_id, "INFO", f"TARGET: {request.repo_url}", "ORCHESTRATOR")
        _append_event(ctx, scan_id, "INFO", "Inicializando reconocimiento...", "ORCHESTRATOR")

        # PASO 1: Escaneo
        _append_event(ctx, scan_id, "INFO", "Mapeando superficie pública...", "SECOPS")
        scanner = SecurityScanner(request.repo_url)
        scan_results = scanner.run_full_scan()

        total = scan_results.get("total_findings", 0)
        critical = scan_results.get("critical_count", 0)
        high = scan_results.get("high_count", 0)
        _append_event(
            ctx, scan_id, "WARN" if critical or high else "OK",
            f"Hallazgos: {total} total · {critical} críticos · {high} altos", "SECOPS",
        )
        for finding in scan_results.get("findings", [])[:5]:
            sev = finding.get("severity", "INFO")
            title = (
                finding.get("title_technical") or finding.get("title_business")
                or finding.get("title") or finding.get("type") or "finding"
            )
            level = "ALERT" if sev == "CRITICAL" else "WARN" if sev == "HIGH" else "INFO"
            _append_event(ctx, scan_id, level, f"[{sev}] {title}", "SECOPS")

        # PASO 1b: Re-ponderación basada en el Perfil de Negocio del usuario
        biz_profile = ctx.get_business_profile()
        if biz_profile and scan_results.get("findings"):
            scan_results["findings"] = business_profile.reweight_findings(scan_results["findings"], biz_profile)
            counts = business_profile.recompute_counts(scan_results["findings"])
            scan_results["critical_count"] = counts["critical"]
            scan_results["high_count"] = counts["high"]
            scan_results["medium_count"] = counts["medium"]
            scan_results["total_findings"] = counts["total"]
            _append_event(ctx, scan_id, "INFO", f"Ponderado con contexto de negocio ({biz_profile.get('sector', 'general')})", "SECOPS")

        # PASO 2: Cerebro cognitivo (cache causal)

        scan_fingerprint = None
        brain_record = None
        brain_record_id = None
        cached_hit = False
        if scan_results.get("findings"):
            threat_type, severity = _classify_scan(scan_results)
            detail = json.dumps(scan_results["findings"][0], sort_keys=True, ensure_ascii=False)
            scan_fingerprint = CognitiveSecurityBrain.compute_fingerprint(threat_type.value, detail)
            brain_result = ctx.brain.receive_threat(
                threat_type=threat_type, detail=detail, severity=severity,
                target_url=request.repo_url,
                context={"scan_id": scan_id, "total_findings": scan_results["total_findings"]},
            )
            brain_record = brain_result.get("record")
            if brain_record is not None:
                brain_record_id = getattr(brain_record, "id", None)
                scan_fingerprint = getattr(brain_record, "threat_fingerprint", scan_fingerprint)
            if brain_result.get("source") == "cache":
                cached_hit = True
                _append_event(ctx, scan_id, "OK", "Cache causal HIT — respuesta instantánea", "BRAIN")
            else:
                _append_event(ctx, scan_id, "INFO", "Cache miss — requiere análisis", "BRAIN")

        # PASO 2b: Canonical Node Memory — entity resolution / dedup no redundante.
        canonical_summary = None
        if scan_results.get("findings"):
            try:
                canonical_summary = ctx.canonical.ingest_scan(scan_results, scan_id=scan_id)
                for ev_msg in canonical_summary["events"]:
                    lvl = "OK" if "canonical hit" in ev_msg else "INFO"
                    _append_event(ctx, scan_id, lvl, ev_msg, "BRAIN")
                _append_event(
                    ctx, scan_id, "INFO",
                    f"Memoria canónica: {canonical_summary['new']} nuevas · "
                    f"{canonical_summary['merges']} merges · {canonical_summary['variants']} variantes",
                    "BRAIN",
                )
            except Exception as e:
                _append_event(ctx, scan_id, "WARN", f"Canonical memory error: {e}", "BRAIN")

        # PASO 3: Análisis IA
        ai_analysis = None
        source = "fallback"
        if cached_hit and brain_record is not None:
            try:
                ai_analysis = json.loads(brain_record.remediation_explanation or "{}")
                if not isinstance(ai_analysis, dict) or "security_score" not in ai_analysis:
                    raise ValueError("cache payload incomplete")
            except (json.JSONDecodeError, ValueError, TypeError):
                ai_analysis = {
                    "security_score": max(0, 100 - (scan_results["critical_count"] * 25)
                                          - (scan_results["high_count"] * 15)),
                    "summary": brain_record.remediation_explanation
                    or "Remediación recuperada del cache causal.",
                    "findings": scan_results["findings"],
                    "remediation_command": brain_record.remediation_command,
                }
            source = "causal_cache"
        elif request.use_agent_team:
            _append_event(scan_id, "REASONING", "Convocando equipo de 3 agentes (Auditor/Analista/Arquitecto)...", "THREAT")
            try:
                team_result = run_team_analysis(scan_results)
                score = max(
                    0,
                    100
                    - (scan_results["critical_count"] * 25)
                    - (scan_results["high_count"] * 15),
                )
                protocols = (team_result.get("remediation") or {}).get("protocols") or []
                ai_analysis = {
                    "security_score": score,
                    "summary": team_result.get("final_telegram_message")
                    or f"Equipo de agentes ({', '.join(team_result.get('agents_used', []))}) completó el análisis.",
                    "findings": scan_results["findings"],
                    "remediation_command": (protocols[0].get("plain_language") if protocols else None)
                    or "# Ver hallazgos en /ui/dashboard",
                    "agent_team_result": team_result,
                }
                source = "agent_team"
                _append_event(
                    scan_id, "OK",
                    f"Equipo completó en {team_result.get('total_pipeline_seconds', '?')}s "
                    f"(roles: {', '.join(team_result.get('agents_used', []))})",
                    "THREAT",
                )
            except Exception as e:
                ai_analysis = {
                    "security_score": max(
                        0,
                        100
                        - (scan_results["critical_count"] * 25)
                        - (scan_results["high_count"] * 15),
                    ),
                    "summary": (
                        f"Escaneo completado. Se encontraron "
                        f"{scan_results['total_findings']} hallazgos."
                    ),
                    "findings": scan_results["findings"],
                    "ai_error": str(e),
                }
                source = "fallback"
        else:
            _append_event(ctx, scan_id, "REASONING", "Correlacionando hallazgos con GPT-4o...", "THREAT")
            try:
                ai_analysis = analyze_scan_results(scan_results)
                source = "llm"
                _append_event(ctx, scan_id, "OK", "Análisis IA completado", "THREAT")
            except Exception as e:
                ai_analysis = {
                    "security_score": max(0, 100 - (scan_results["critical_count"] * 25)
                                          - (scan_results["high_count"] * 15)),
                    "summary": (f"Escaneo completado. Se encontraron "
                                f"{scan_results['total_findings']} hallazgos."),
                    "findings": scan_results["findings"],
                    "ai_error": str(e),
                }
                source = "fallback"
                _append_event(ctx, scan_id, "WARN", f"IA fallback: {e}", "THREAT")

        score = ai_analysis.get("security_score", 0)
        _append_event(
            ctx, scan_id, "ALERT" if score < 50 else "OK",
            f"Security Score: {score}/100 — {ai_analysis.get('summary', '')[:120]}", "REMEDIATION",
        )

        # PASO 4: Persistir remediación en memoria episódica
        if brain_record is not None and source in ("llm", "fallback") and not cached_hit:
            try:
                brain_record_id = ctx.brain.save_remediation(
                    brain_record,
                    command=ai_analysis.get("remediation_command", "# Ver hallazgos en el dashboard"),
                    explanation=json.dumps(ai_analysis, ensure_ascii=False)[:4000],
                    model="gpt-4o" if source == "llm" else "heuristic-fallback",
                    tokens=0,
                )
                _append_event(ctx, scan_id, "INFO", "Amenaza registrada en memoria episódica", "BRAIN")
            except Exception as e:
                _append_event(ctx, scan_id, "WARN", f"Brain save error: {e}", "BRAIN")

        # PASO 5: Notificación
        notification_sent = False
        feedback_token = _register_feedback_token(
            ctx.user_id, brain_record_id or scan_fingerprint or "", scan_id
        )
        if request.notify and ai_analysis:
            _append_event(ctx, scan_id, "INFO", "Despachando alerta a Telegram...", "ORCHESTRATOR")
            try:
                ai_analysis["scan_id"] = scan_id
                bot_token = ctx.get_setting("telegram_bot_token")
                chat_id = ctx.get_setting("telegram_chat_id")
                results = dispatcher.dispatch(
                    ai_analysis, channels=request.channels or ["telegram"],
                    threat_fingerprint=feedback_token, scan_id=feedback_token,
                    bot_token=bot_token, chat_id=chat_id,
                )
                notification_sent = True
                _append_event(ctx, scan_id, "OK", "Alerta enviada a Telegram", "ORCHESTRATOR")
                print(f"[Telegram] dispatch result: {results}")
            except Exception as e:
                _append_event(ctx, scan_id, "WARN", f"Telegram error: {e}", "ORCHESTRATOR")

        latency_ms = int((time.time() - start_time) * 1000)
        result = {
            "scan_id": scan_id, "project_id": request.project_id, "status": "completed",
            "source": source, "latency_ms": latency_ms, "target_url": request.repo_url,
            "security_score": ai_analysis.get("security_score", "N/A"),
            "summary": ai_analysis.get("summary", ""),
            "findings": ai_analysis.get("findings", scan_results.get("findings", [])),
            "scan_raw": {
                "total": scan_results["total_findings"], "critical": scan_results["critical_count"],
                "high": scan_results["high_count"], "medium": scan_results["medium_count"],
            },
            "notification_sent": notification_sent,
            "threat_fingerprint": scan_fingerprint,
            "brain_record_id": brain_record_id,
            "canonical": {
                "new": canonical_summary["new"], "merges": canonical_summary["merges"],
                "variants": canonical_summary["variants"],
                "canonical_ids": canonical_summary["canonical_ids"],
            } if canonical_summary else None,
        }

        job["status"] = "completed"
        job["result"] = result
        job["updated_at"] = datetime.utcnow().isoformat()
        ctx.latest_scan = result
        try:
            score_val = result["security_score"] if isinstance(result.get("security_score"), int) else 50
            ctx.save_scan_history(scan_id, request.repo_url, score_val, len(result.get("findings", [])))
        except Exception as e:
            print(f"[!] Error guardando historial de scan: {e}")
        _append_event(ctx, scan_id, "OK", f"Pipeline completado en {latency_ms}ms", "ORCHESTRATOR")
        return result


    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
        job["updated_at"] = datetime.utcnow().isoformat()
        _append_event(ctx, scan_id, "ALERT", f"Error fatal: {e}", "ORCHESTRATOR")
        raise


def _run_scan_pipeline_safe(user_id: str, scan_id: str, request: ScanRequest):
    """Wrapper para el thread pool (resuelve el contexto del usuario)."""
    try:
        ctx = tenants.get(user_id)
        _run_scan_pipeline(ctx, scan_id, request)
    except Exception as e:
        print(f"[!] Scan {scan_id} (user {user_id[:8]}) failed: {e}")


# ============================================================
# Endpoints — Auth
# ============================================================

@app.post("/api/v1/auth/register")
async def register(req: RegisterRequest, request: Request, response: Response):
    try:
        user = auth_service.register(req.email, req.password, req.full_name or "", req.company or "")
    except AuthError as e:
        raise HTTPException(status_code=400, detail=e.message)
    token = auth_service.create_session(user.id, request.headers.get("user-agent", ""))
    _set_session_cookie(response, token, request)
    tenants.get(user.id)  # provisiona la BD aislada del usuario
    return {"status": "ok", "user": _user_public(user)}


@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    try:
        user = auth_service.authenticate(req.email, req.password)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    token = auth_service.create_session(user.id, request.headers.get("user-agent", ""))
    _set_session_cookie(response, token, request)
    return {"status": "ok", "user": _user_public(user)}


@app.post("/api/v1/auth/logout")
async def logout(request: Request, response: Response):
    auth_service.destroy_session(request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@app.get("/api/v1/auth/me")
async def me(user: User = Depends(require_user)):
    return {"status": "ok", "user": _user_public(user)}


# ============================================================
# Endpoints — Health
# ============================================================

@app.get("/api/v1/health")
async def health_check(request: Request):
    openai_ok = bool(os.getenv("OPENAI_API_KEY") and not os.getenv("OPENAI_API_KEY", "").startswith("sk-xxx"))
    telegram_ok = bool(os.getenv("TELEGRAM_BOT_TOKEN")
                       and not os.getenv("TELEGRAM_BOT_TOKEN", "").startswith("123456"))
    user = get_current_user(request)
    return {
        "status": "healthy",
        "service": "VicoGuard AI",
        "version": "2.0.0-hackathon",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {"openai_configured": openai_ok, "telegram_configured": telegram_ok},
        "authenticated": bool(user),
    }


# ============================================================
# Endpoints — Scan (requieren sesión, aislados por usuario)
# ============================================================

@app.post("/api/v1/scan/repository")
async def scan_repository(request: ScanRequest, user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    scan_id = str(uuid.uuid4())
    ctx.scan_jobs[scan_id] = _new_job(scan_id, request.repo_url)
    try:
        return _run_scan_pipeline(ctx, scan_id, request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en escaneo: {str(e)}")


@app.post("/api/v1/scan/start")
async def start_scan_async(request: ScanRequest, user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    scan_id = str(uuid.uuid4())
    ctx.scan_jobs[scan_id] = _new_job(scan_id, request.repo_url, status="queued")
    _append_event(ctx, scan_id, "INFO", "Scan encolado — iniciando pipeline...", "ORCHESTRATOR")
    loop = asyncio.get_running_loop()
    loop.run_in_executor(_scan_executor, _run_scan_pipeline_safe, user.id, scan_id, request)
    return {
        "scan_id": scan_id, "status": "queued", "target_url": request.repo_url,
        "poll_url": f"/api/v1/scan/{scan_id}",
    }


@app.get("/api/v1/scan/latest")
async def get_latest_scan(user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    if not ctx.latest_scan:
        return {"status": "empty", "message": "No hay escaneos aún.", "result": None}
    return {"status": "ok", "result": ctx.latest_scan}


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str, user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    job = ctx.scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return job


# ============================================================
# Endpoints — Telemetría
# ============================================================

@app.post("/api/v1/telemetry/ingest")
async def ingest_telemetry(request: TelemetryRequest, background_tasks: BackgroundTasks,
                           user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    start_time = time.time()
    if not request.events:
        return {"status": "ok", "processed_events": 0, "message": "No hay eventos."}

    log_text = "\n".join(
        f"[{e.get('timestamp', 'N/A')}] {e.get('type', 'UNKNOWN')} | "
        f"src={e.get('source_ip', '?')} | status={e.get('status_code', '?')} | "
        f"path={e.get('path', '?')}" for e in request.events
    )
    try:
        correlation = correlate_server_logs(log_text)
    except Exception as e:
        correlation = {
            "overall_status": "UNKNOWN", "threat_summary": f"Error al correlacionar: {str(e)}",
            "events_analyzed": len(request.events), "noise_filtered": 0, "real_threats": [],
        }

    for event in request.events:
        try:
            ctx.brain.receive_threat(
                threat_type=ThreatType.BRUTE_FORCE
                if str(event.get("type", "")).upper() in ("LOGIN_FAIL", "BRUTE_FORCE")
                else ThreatType.RECONNAISSANCE,
                detail=(f"{event.get('type', 'TELEMETRY')} src={event.get('source_ip', '?')} "
                        f"path={event.get('path', '/')} status={event.get('status_code', '?')}"),
                severity=ThreatSeverity.HIGH
                if int(event.get("status_code", 0) or 0) >= 401 else ThreatSeverity.MEDIUM,
                source_ip=event.get("source_ip"), target_url=event.get("path"),
            )
        except Exception as e:
            print(f"[!] brain.receive_threat telemetry error: {e}")

    if correlation.get("real_threats"):
        bot_token = ctx.get_setting("telegram_bot_token")
        chat_id = ctx.get_setting("telegram_chat_id")
        background_tasks.add_task(_send_server_notification, correlation, bot_token, chat_id)

    return {
        "status": "processed", "processed_events": len(request.events),
        "latency_ms": int((time.time() - start_time) * 1000), "correlation": correlation,
    }


# ============================================================
# Endpoints — Brain / Memoria canónica (aislados por usuario)
# ============================================================

@app.get("/api/v1/brain/stats")
async def get_brain_stats(user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    return {
        "status": "ok",
        "brain": ctx.brain.get_stats(),
        "canonical": ctx.canonical.get_stats(),
        "timestamp": datetime.utcnow().isoformat(),
        "latest_scan": {
            "security_score": ctx.latest_scan.get("security_score"),
            "target_url": ctx.latest_scan.get("target_url"),
            "scan_raw": ctx.latest_scan.get("scan_raw"),
        } if ctx.latest_scan else None,
    }


@app.get("/api/v1/brain/entities")
async def list_canonical_entities(entity_type: Optional[str] = None, limit: int = 50,
                                  user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    return {
        "status": "ok",
        "entities": ctx.canonical.list_entities(limit=limit, entity_type=entity_type),
        "dedup": ctx.canonical.get_stats(),
    }


@app.get("/api/v1/brain/entity/{canonical_id}")
async def get_canonical_entity(canonical_id: str, user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    entity = ctx.canonical.get_entity(canonical_id)
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entidad canónica no encontrada: {canonical_id}")
    return {"status": "ok", "entity": entity}


@app.post("/api/v1/brain/feedback")
async def submit_feedback(request: FeedbackRequest, user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    record_id = _resolve_brain_record_id(ctx, request.threat_fingerprint)
    if not record_id:
        raise HTTPException(status_code=404, detail="Registro de amenaza no encontrado")
    if request.success:
        ctx.brain.mark_success(record_id)
    else:
        ctx.brain.mark_failed(record_id)
    return {
        "status": "ok", "record_id": record_id,
        "marked_as": "success" if request.success else "failed",
        "message": "Gracias. El cerebro de VicoGuard aprendió de tu feedback.",
    }


@app.get("/api/v1/settings")
async def get_settings(user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    bot_token = ctx.get_setting("telegram_bot_token", "")
    chat_id = ctx.get_setting("telegram_chat_id", "")
    
    masked_token = ""
    if bot_token:
        if len(bot_token) > 10:
            masked_token = bot_token[:6] + "..." + bot_token[-4:]
        else:
            masked_token = "Configurado"
            
    return {
        "status": "ok",
        "telegram_bot_token": masked_token,
        "telegram_chat_id": chat_id,
    }


@app.post("/api/v1/settings")
async def update_settings(request: SettingsRequest, user: User = Depends(require_user)):
    ctx = tenants.get(user.id)
    if request.telegram_bot_token is not None:
        token = request.telegram_bot_token.strip()
        if token == "__clear__":
            ctx.set_setting("telegram_bot_token", "")  # borrar credencial
        elif token and not token.endswith("..."):
            ctx.set_setting("telegram_bot_token", token)  # cifrado en reposo
        # (token vacío o enmascarado sin cambios -> no se toca)
    if request.telegram_chat_id is not None:
        chat_id = request.telegram_chat_id.strip()
        ctx.set_setting("telegram_chat_id", chat_id)
    return {"status": "ok", "message": "Configuración guardada exitosamente."}


@app.post("/api/v1/settings/test")
async def test_telegram(user: User = Depends(require_user)):
    """Envía un mensaje de prueba al Telegram del usuario para validar su config."""
    ctx = tenants.get(user.id)
    bot_token = ctx.get_setting("telegram_bot_token")
    chat_id = ctx.get_setting("telegram_chat_id")
    if not bot_token or not chat_id:
        raise HTTPException(status_code=400, detail="Configura tu bot token y chat ID primero.")
    res = dispatcher.telegram._send_message(
        "✅ *VicoGuard AI* — conexión verificada.\nAquí recibirás tus alertas de seguridad "
        "y remediaciones. _Powered by VicoGuard AI 🛡️_",
        bot_token=bot_token, chat_id=chat_id,
    )
    if not res.get("ok"):
        raise HTTPException(status_code=400,
                            detail=f"Telegram rechazó el mensaje: {res.get('description') or res.get('error')}")
    return {"status": "ok", "message": "Mensaje de prueba enviado a tu Telegram."}


# ============================================================
# Endpoints — Cuestionario Inteligente & Perfil de Negocio
# ============================================================

@app.get("/api/v1/business-profile/schema")
async def get_business_profile_schema(user: User = Depends(require_user)):
    """Devuelve las preguntas del cuestionario (esquema adaptativo)."""
    ctx = tenants.get(user.id)
    profile = ctx.get_business_profile() or {}
    questions = business_profile.visible_questions(profile)
    return {
        "status": "ok",
        "questions": questions,
        "raw_schema": business_profile.QUESTION_SCHEMA
    }


@app.get("/api/v1/business-profile")
async def get_business_profile(user: User = Depends(require_user)):
    """Obtiene el perfil de negocio guardado y la síntesis de riesgo."""
    ctx = tenants.get(user.id)
    profile = ctx.get_business_profile()
    if not profile:
        return {"status": "empty", "profile": None, "risk_summary": None}
    summary = business_profile.ai_risk_summary(profile)
    return {
        "status": "ok",
        "profile": profile,
        "risk_summary": summary
    }


@app.post("/api/v1/business-profile")
async def save_business_profile(request: BusinessProfileRequest, user: User = Depends(require_user)):
    """Guarda las respuestas del cuestionario y sintetiza el modelo de riesgo."""
    ctx = tenants.get(user.id)
    profile_data = request.dict()
    ctx.set_business_profile(profile_data)
    
    # Sintetizar modelo de riesgo (con OpenAI o heurística)
    summary = business_profile.ai_risk_summary(profile_data)

    # Ingestar nodo de negocio en el Grafo Canónico (Memoria de Entidad Canónica)
    try:
        ctx.canonical.resolve_identity(
            entity_type=business_profile.EntityType.SERVICE if hasattr(business_profile, 'EntityType') else "Service",
            normalized_key=f"business:{user.id}",
            attributes={
                "name": f"Negocio ({request.sector})",
                "sector": request.sector,
                "data_handled": request.data,
                "stack": request.stack,
                "risk_posture": summary.get("risk_posture", "medio")
            },
            evidence_summary=f"Perfil de negocio configurado: {request.description[:100]}"
        )
    except Exception as e:
        print(f"[!] Error al ingestar nodo de negocio en grafo: {e}")

    return {
        "status": "ok",
        "message": "Perfil de negocio guardado exitosamente.",
        "profile": profile_data,
        "risk_summary": summary
    }


# ============================================================
# Endpoints — Monitoreo Post-Escaneo e Historial
# ============================================================

@app.get("/api/v1/scans/history")
async def get_scan_history_endpoint(user: User = Depends(require_user)):
    """Obtiene la tendencia de puntuación e historial de escaneos."""
    ctx = tenants.get(user.id)
    history = ctx.get_scan_history(limit=20)
    avg_score = int(sum(h["score"] for h in history) / len(history)) if history else 0
    return {
        "status": "ok",
        "total_scans": len(history),
        "avg_score": avg_score,
        "history": history
    }


# ============================================================
# Endpoints — Planes y Uso SaaS
# ============================================================

@app.get("/api/v1/billing/plan")
async def get_plan_endpoint(user: User = Depends(require_user)):
    """Obtiene el plan SaaS actual del usuario y su cuota de uso."""
    ctx = tenants.get(user.id)
    return {"status": "ok", **ctx.get_plan()}


@app.post("/api/v1/billing/plan")
async def update_plan_endpoint(req: PlanRequest, user: User = Depends(require_user)):
    """Actualiza el plan SaaS del usuario (simulación B2B)."""
    ctx = tenants.get(user.id)
    ctx.set_plan(req.plan)
    return {"status": "ok", "message": f"Plan actualizado a {req.plan}.", **ctx.get_plan()}



# ============================================================
# Endpoints — Topología del scan (grafo canónico)
# ============================================================

@app.get("/api/v1/brain/graph")
async def get_brain_graph(user: User = Depends(require_user)):
    """Grafo de topología: qué se escaneó y cómo se relaciona (aislado por usuario)."""
    ctx = tenants.get(user.id)
    graph = ctx.canonical.get_graph()
    return {"status": "ok", **graph, "dedup": ctx.canonical.get_stats()}


# ============================================================
# Endpoints — Envío de remediación (dashboard -> Telegram)
# ============================================================

def _remediation_of(finding: dict) -> str:
    return (finding.get("remediation_code")
            or "\n".join(finding.get("remediation_steps", []) or [])
            or "Revisa el hallazgo en el panel de VicoGuard.")


@app.post("/api/v1/remediation/send")
async def send_remediation(req: RemediationSendRequest, user: User = Depends(require_user)):
    """Envía la remediación de un hallazgo (o todas) al Telegram del usuario."""
    ctx = tenants.get(user.id)
    bot_token = ctx.get_setting("telegram_bot_token")
    chat_id = ctx.get_setting("telegram_chat_id")
    if not bot_token or not chat_id:
        raise HTTPException(status_code=400,
                            detail="Configura tu Telegram en Ajustes antes de enviar remediaciones.")

    result = None
    if req.scan_id:
        result = (ctx.scan_jobs.get(req.scan_id) or {}).get("result")
    if not result:
        result = ctx.latest_scan
    if not result:
        raise HTTPException(status_code=404, detail="No hay un escaneo del cual enviar remediación.")

    findings = result.get("findings", []) or []
    if not findings:
        raise HTTPException(status_code=404, detail="El escaneo no tiene hallazgos.")

    target = result.get("target_url", "")
    if req.send_all:
        lines = [f"🛠️ *Plan de remediación — VicoGuard AI*", f"Target: `{target}`", ""]
        for f in findings[:10]:
            sev = f.get("severity", "?")
            title = f.get("title_business") or f.get("title_technical") or "Hallazgo"
            lines.append(f"*[{sev}]* {title}")
            code = _remediation_of(f)
            lines.append(f"```\n{code[:500]}\n```")
        lines.append("\n_Powered by VicoGuard AI 🛡️_")
        message = "\n".join(lines)
        sent_count = min(len(findings), 10)
    else:
        idx = req.finding_index if req.finding_index is not None else 0
        if idx < 0 or idx >= len(findings):
            raise HTTPException(status_code=400, detail="Índice de hallazgo inválido.")
        f = findings[idx]
        sev = f.get("severity", "?")
        title = f.get("title_business") or f.get("title_technical") or "Hallazgo"
        message = (f"🛠️ *Remediación — VicoGuard AI*\nTarget: `{target}`\n\n"
                   f"*[{sev}]* {title}\n")
        if f.get("analogy"):
            message += f"💡 _{f['analogy']}_\n"
        message += f"\n*Solución:*\n```\n{_remediation_of(f)[:900]}\n```\n\n_Powered by VicoGuard AI 🛡️_"
        sent_count = 1

    res = dispatcher.telegram._send_message(message, bot_token=bot_token, chat_id=chat_id)
    if not res.get("ok"):
        raise HTTPException(status_code=400,
                            detail=f"Telegram rechazó el mensaje: {res.get('description') or res.get('error')}")
    return {"status": "ok", "sent": sent_count, "message": "Remediación enviada a tu Telegram."}


# ============================================================
# Reporte — generador HTML self-contained (imprimible a PDF)
# ============================================================

def _report_escape(s) -> str:
    s = "" if s is None else str(s)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _build_report_html(user: User, result: dict, brain_stats: dict, canonical_stats: dict) -> str:
    """Genera un reporte ejecutivo de seguridad (HTML self-contained, print->PDF)."""
    try:
        score = int(result.get("security_score", 0))
    except (TypeError, ValueError):
        score = 0
    raw = result.get("scan_raw", {}) or {}
    findings = result.get("findings", []) or []
    company = _report_escape(user.company or user.full_name or user.email)
    target = _report_escape(result.get("target_url", ""))
    summary = _report_escape(result.get("summary", ""))
    gen = datetime.now().strftime("%d/%m/%Y %H:%M")
    accent = "#46D3A0" if score >= 80 else "#F4C24E" if score >= 50 else "#FF6B6B"
    risk = "Riesgo bajo" if score >= 80 else "Riesgo medio" if score >= 50 else "Riesgo crítico"
    circ = 327
    dash = circ - (score / 100) * circ

    sev_colors = {"CRITICAL": "#FF6B6B", "HIGH": "#FF9145", "MEDIUM": "#F4C24E", "LOW": "#7FB0FF"}
    rows = []
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        color = sev_colors.get(sev, "#94A3B8")
        title = _report_escape(f.get("title_business") or f.get("title_technical") or "Hallazgo")
        code = _report_escape(_remediation_of(f))
        analogy = _report_escape(f.get("analogy") or "")
        rows.append(f"""
        <tr>
          <td><span class="sev" style="color:{color};border-color:{color}">{sev}</span></td>
          <td>
            <div class="ftitle">{title}</div>
            {f'<div class="fanalogy">💡 {analogy}</div>' if analogy else ''}
            <pre>{code}</pre>
          </td>
        </tr>""")
    rows_html = "".join(rows) or '<tr><td colspan="2" class="empty">Sin hallazgos.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Reporte de Seguridad · {company} · VicoGuard AI</title>
<style>
  :root {{ --ink:#0f141b; --mut:#5b6472; --line:#e4e7ec; --accent:{accent}; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; color:var(--ink);
          background:#f6f7f9; margin:0; line-height:1.55; }}
  .sheet {{ max-width:820px; margin:24px auto; background:#fff; border:1px solid var(--line);
            border-radius:14px; overflow:hidden; }}
  .top {{ display:flex; justify-content:space-between; align-items:center; padding:22px 32px;
          border-bottom:1px solid var(--line); }}
  .brand {{ display:flex; align-items:center; gap:10px; font-weight:800; letter-spacing:-.02em; }}
  .brand .m {{ width:28px; height:28px; border-radius:7px; background:linear-gradient(155deg,#6EA0FF,#3A6DEB);
               color:#08122b; display:grid; place-items:center; font-weight:800; }}
  .brand small {{ color:var(--mut); font-weight:500; }}
  .toolbar {{ text-align:right; }}
  .btn {{ font:inherit; font-size:13px; padding:8px 14px; border:1px solid var(--line); background:#fff;
          border-radius:8px; cursor:pointer; }}
  .btn.primary {{ background:#111827; color:#fff; border-color:#111827; }}
  .hero {{ display:flex; gap:28px; align-items:center; padding:28px 32px; border-bottom:1px solid var(--line); }}
  .ring {{ position:relative; width:120px; height:120px; flex:none; }}
  .ring svg {{ transform:rotate(-90deg); }}
  .ring .n {{ position:absolute; inset:0; display:grid; place-items:center; font-size:34px; font-weight:800;
              color:var(--accent); }}
  .meta h1 {{ margin:0 0 4px; font-size:22px; letter-spacing:-.02em; }}
  .meta .risk {{ display:inline-block; font-size:12px; font-weight:700; color:var(--accent);
                 border:1px solid var(--accent); border-radius:999px; padding:2px 10px; }}
  .meta .kv {{ color:var(--mut); font-size:13px; margin-top:8px; }}
  .kv b {{ color:var(--ink); font-weight:600; }}
  .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:0; border-bottom:1px solid var(--line); }}
  .cell {{ padding:18px 20px; border-right:1px solid var(--line); }}
  .cell:last-child {{ border-right:none; }}
  .cell .l {{ font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--mut); font-weight:700; }}
  .cell .v {{ font-size:26px; font-weight:800; margin-top:4px; }}
  section {{ padding:24px 32px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.06em; color:var(--mut); margin:0 0 14px; }}
  .summary {{ font-size:15px; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:14px 0; border-top:1px solid var(--line); vertical-align:top; }}
  td:first-child {{ width:96px; }}
  .sev {{ font-size:11px; font-weight:800; border:1px solid; border-radius:999px; padding:2px 9px; }}
  .ftitle {{ font-weight:650; }}
  .fanalogy {{ color:var(--mut); font-size:13px; margin-top:3px; }}
  pre {{ background:#0b0e13; color:#bfe3d3; border-radius:8px; padding:11px 13px; overflow-x:auto;
         font-family:"SF Mono",Consolas,monospace; font-size:12px; margin:10px 0 0; white-space:pre-wrap; }}
  .foot {{ padding:18px 32px; color:var(--mut); font-size:12px; border-top:1px solid var(--line);
           display:flex; justify-content:space-between; }}
  .empty {{ color:var(--mut); }}
  @media print {{ body {{ background:#fff; }} .sheet {{ border:none; margin:0; max-width:none; }}
                  .toolbar {{ display:none; }} }}
</style></head>
<body>
  <div class="sheet">
    <div class="top">
      <div class="brand"><span class="m">V</span><div>VicoGuard AI<br/><small>Reporte de seguridad</small></div></div>
      <div class="toolbar"><button class="btn primary" onclick="window.print()">Imprimir / Guardar PDF</button></div>
    </div>
    <div class="hero">
      <div class="ring">
        <svg width="120" height="120" viewBox="0 0 118 118">
          <circle cx="59" cy="59" r="52" fill="none" stroke="#e9edf1" stroke-width="10"/>
          <circle cx="59" cy="59" r="52" fill="none" stroke="{accent}" stroke-width="10"
                  stroke-linecap="round" stroke-dasharray="{circ}" stroke-dashoffset="{dash:.0f}"/>
        </svg>
        <div class="n">{score}</div>
      </div>
      <div class="meta">
        <h1>{company}</h1>
        <span class="risk">{risk} · {score}/100</span>
        <div class="kv"><b>Objetivo:</b> {target}</div>
        <div class="kv"><b>Generado:</b> {gen} &nbsp;·&nbsp; <b>Análisis:</b> {_report_escape(result.get('source','')) or 'n/a'}</div>
      </div>
    </div>
    <div class="grid">
      <div class="cell"><div class="l">Críticos</div><div class="v" style="color:#FF6B6B">{raw.get('critical',0)}</div></div>
      <div class="cell"><div class="l">Altos</div><div class="v" style="color:#FF9145">{raw.get('high',0)}</div></div>
      <div class="cell"><div class="l">Medios</div><div class="v" style="color:#F4C24E">{raw.get('medium',0)}</div></div>
      <div class="cell"><div class="l">Total</div><div class="v">{raw.get('total',0)}</div></div>
    </div>
    <section>
      <h2>Resumen ejecutivo</h2>
      <p class="summary">{summary or 'Escaneo completado.'}</p>
    </section>
    <section>
      <h2>Hallazgos y remediación</h2>
      <table><tbody>{rows_html}</tbody></table>
    </section>
    <section>
      <h2>Memoria del agente (no redundante)</h2>
      <p class="summary">VicoGuard registró estos hallazgos como
        <b>{canonical_stats.get('unique_entities',0)} entidades canónicas únicas</b>
        con <b>{canonical_stats.get('evidences',0)} evidencias</b> y
        <b>{canonical_stats.get('redundant_nodes_avoided',0)} duplicados evitados</b>.
        El cerebro cognitivo acumula <b>{brain_stats.get('total_memories',0)} memorias</b> de amenazas.</p>
    </section>
    <div class="foot">
      <span>Confidencial · generado para {company}</span>
      <span>VicoGuard AI · Hackatón FLIT 2026</span>
    </div>
  </div>
</body></html>"""


@app.get("/api/v1/scan/{scan_id}/report", response_class=HTMLResponse)
async def scan_report(scan_id: str, request: Request):
    """Reporte ejecutivo imprimible (HTML self-contained) de un scan del usuario."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/ui/login")
    ctx = tenants.get(user.id)
    result = (ctx.scan_jobs.get(scan_id) or {}).get("result")
    if not result and ctx.latest_scan.get("scan_id") == scan_id:
        result = ctx.latest_scan
    if not result:
        raise HTTPException(status_code=404, detail="Scan no encontrado.")
    html = _build_report_html(user, result, ctx.brain.get_stats(), ctx.canonical.get_stats())
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store"})


@app.get("/api/v1/report/latest", response_class=HTMLResponse)
async def latest_report(request: Request):
    """Reporte del último scan del usuario."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/ui/login")
    ctx = tenants.get(user.id)
    if not ctx.latest_scan:
        raise HTTPException(status_code=404, detail="Aún no hay escaneos.")
    html = _build_report_html(user, ctx.latest_scan, ctx.brain.get_stats(), ctx.canonical.get_stats())
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store"})


# ============================================================
# Endpoint — Telegram webhook (callback público del bot)
# ============================================================

@app.post("/api/v1/telegram/webhook")
async def telegram_webhook(request: Request):
    """Callbacks de botones inline. El token corto enruta al usuario dueño del scan."""
    body = await request.json()
    callback = body.get("callback_query")
    if not callback:
        return {"ok": True}

    data = callback.get("data", "")
    callback_id = callback.get("id")
    parts = data.split(":", 2)
    if len(parts) < 3 or parts[0] != "vg":
        return {"ok": True}

    action, token = parts[1], parts[2]
    ref = feedback_tokens.get(token)
    answer_text = "OK"
    bot_token = None  # se resuelve al del tenant dueño del scan

    if ref:
        ctx = tenants.get(ref["user_id"])
        bot_token = ctx.get_setting("telegram_bot_token")  # bot del usuario
        chat_id = ctx.get_setting("telegram_chat_id")
        if action == "success":
            rid = _resolve_brain_record_id(ctx, ref["record_id"]) or ref["record_id"]
            ctx.brain.mark_success(rid)
            answer_text = "Parche marcado como aplicado. VicoGuard aprendio."
            dispatcher.telegram._send_message(
                "*Feedback recibido*\nRemediacion marcada como exitosa. "
                "La proxima vez responderemos en <1s desde el Causal Cache.",
                bot_token=bot_token, chat_id=chat_id)
        elif action == "failed":
            rid = _resolve_brain_record_id(ctx, ref["record_id"]) or ref["record_id"]
            ctx.brain.mark_failed(rid)
            answer_text = "Marcado como fallido. Generaremos otra solucion."
            dispatcher.telegram._send_message(
                "*Remediacion fallida*\nEl cerebro invalido este parche. "
                "Ejecuta un nuevo scan para regenerar la solucion.",
                bot_token=bot_token, chat_id=chat_id)
        elif action == "details":
            job = ctx.scan_jobs.get(ref["scan_id"]) or {}
            result = job.get("result")
            if result:
                findings_text = "\n".join(
                    f"• *{f.get('severity', '?')}:* {f.get('title_business', f.get('title', 'N/A'))}"
                    for f in result.get("findings", [])[:5])
                dispatcher.telegram._send_message(
                    f"*Detalles del Scan*\nScore: {result.get('security_score')}/100\n"
                    f"Target: `{result.get('target_url')}`\n\n{findings_text}\n\n"
                    f"_{result.get('summary', '')}_",
                    bot_token=bot_token, chat_id=chat_id)
                answer_text = "Detalles enviados"
            else:
                answer_text = "Scan no encontrado"
    else:
        answer_text = "Sesion expirada"

    try:
        dispatcher.telegram.answer_callback(callback_id, answer_text, bot_token=bot_token)
    except Exception as e:
        print(f"[Telegram webhook] answer error: {e}")
    return {"ok": True, "action": action}


# ============================================================
# Background Tasks
# ============================================================

def _send_server_notification(correlation: dict, bot_token: str = None, chat_id: str = None):
    try:
        dispatcher.telegram.send_server_alert(correlation, bot_token=bot_token, chat_id=chat_id)
    except Exception as e:
        print(f"[!] Error enviando alerta de servidor: {e}")


# ============================================================
# Front-end (web/ — diseño profesional) + compat ui_stitch
# ============================================================

# Páginas nuevas (autenticadas / auth) servidas desde web/
WEB_PAGES = {
    "login": "login.html",
    "signup": "signup.html",
    "app": "app.html",
    "dashboard": "app.html",
    "audit": "app.html",
    "account": "account.html",
}

# Alias legacy de ui_stitch (se mantienen accesibles con /ui/legacy/...)
UI_ROUTES = {
    "live": "live_agent_execution_vicoguard_ai",
    "landing": "landing_page_vicoguard_ai",
    "chat": "secops_assistant_vicoguard_ai",
    "trust": "verification_trust_vicoguard_ai",
}


@app.get("/")
async def root_redirect(request: Request):
    """Entrada: al dashboard si hay sesión, si no al login."""
    return RedirectResponse(url="/ui/app" if get_current_user(request) else "/ui/login")


@app.get("/ui")
@app.get("/ui/")
async def ui_index(request: Request):
    return RedirectResponse(url="/ui/app" if get_current_user(request) else "/ui/login")


@app.get("/ui/assets/{filename}")
async def serve_web_asset(filename: str):
    """Sirve CSS/JS del front-end nuevo."""
    if not (filename.endswith(".css") or filename.endswith(".js")):
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    path = WEB_DIR / "assets" / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    media = "text/css" if filename.endswith(".css") else "application/javascript"
    return FileResponse(path, media_type=media)


@app.get("/ui/js/{filename}")
async def serve_ui_js(filename: str):
    """Compat: cliente JS legacy de ui_stitch."""
    js_path = UI_DIR / "js" / filename
    if not js_path.exists() or not filename.endswith(".js"):
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    return FileResponse(js_path, media_type="application/javascript")


@app.get("/ui/legacy/{screen}")
async def serve_ui_legacy(screen: str):
    """Pantallas antiguas de ui_stitch (por si se necesitan)."""
    folder = UI_ROUTES.get(screen, screen)
    html_path = UI_DIR / folder / "code.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail=f"Pantalla no encontrada: {screen}")
    return FileResponse(html_path, media_type="text/html")


@app.get("/ui/{screen}")
async def serve_ui_screen(screen: str, request: Request):
    """Sirve el front-end nuevo. Las páginas de app exigen sesión (redirige a login)."""
    if screen in WEB_PAGES:
        # Gating server-side para páginas autenticadas.
        if screen in ("app", "dashboard", "audit", "account") and not get_current_user(request):
            return RedirectResponse(url="/ui/login")
        page = WEB_DIR / WEB_PAGES[screen]
        if page.exists():
            return FileResponse(page, media_type="text/html")
    # Fallback a ui_stitch legacy
    folder = UI_ROUTES.get(screen, screen)
    html_path = UI_DIR / folder / "code.html"
    if html_path.exists():
        return FileResponse(html_path, media_type="text/html")
    raise HTTPException(status_code=404, detail=f"Pantalla no encontrada: {screen}")


# ============================================================
# Demo target (intentionally vulnerable — fake secrets only)
# ============================================================

DEMO_VULNERABLE_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Acme Pyme — Portal Demo (Vulnerable)</title>
  <style>
    body { font-family: Georgia, serif; max-width: 640px; margin: 48px auto; padding: 0 16px;
           background: #f7f3ee; color: #1a1a1a; }
    h1 { font-size: 1.75rem; margin-bottom: 0.25rem; }
    .tag { color: #b45309; font-size: 0.85rem; letter-spacing: 0.04em; text-transform: uppercase; }
    p { line-height: 1.55; color: #333; }
    code { background: #efe8df; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
  </style>
</head>
<body>
  <p class="tag">Demo interna · no usar en producción</p>
  <h1>Portal clientes Acme Pyme</h1>
  <p>Esta página es un <strong>target de demo</strong> para VicoGuard AI.
     Contiene secretos falsos y carece de cabeceras de seguridad a propósito.</p>
  <p>Login: <code>cliente@acme-demo.local</code> / <code>demo-password-not-real</code></p>

  <!-- Intentionally exposed fake Supabase config for scanner demos -->
  <script>
    // FAKE credentials — not real keys. For hackathon scanner demo only.
    // Long eyJ* token (no dots) so regex eyJ[A-Za-z0-9_-]{50,} matches.
    window.APP_CONFIG = {
      supabaseUrl: "https://xyzabcdefghijklmnopq.supabase.co",
      supabaseAnonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9FAKEdemoAnonKeyNotRealXXXXXXXXXXXXXXXabcdefghij",
      apiKey: "vg_demo_frontend_key_not_real_12345"
    };
    const SUPABASE_URL = "https://xyzabcdefghijklmnopq.supabase.co";
    const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9FAKEdemoAnonKeyNotRealXXXXXXXXXXXXXXXabcdefghij";
    // Explicit REST base -> points the scanner at the SELF-CONTAINED mock Supabase
    // (RLS disabled) served by this same API, so the RLS finding fires without any
    // external project. Relative path resolves against this origin on any port.
    const SUPABASE_REST_BASE = "/demo/supabase";
    // password hardcoded on purpose for demo detection
    const adminPassword = "SuperSecretDemo123!";
  </script>
</body>
</html>
"""


@app.get("/demo/vulnerable", response_class=HTMLResponse)
async def demo_vulnerable_page():
    """Página estática intencionalmente vulnerable (secretos fake + sin headers)."""
    return HTMLResponse(
        content=DEMO_VULNERABLE_HTML,
        headers={"Cache-Control": "no-store"},  # sin headers de seguridad a propósito
    )


# Self-contained mock of a Supabase project with RLS DISABLED. Returns rows to any
# caller (no auth), so the scanner's RLS check reports a real CRITICAL finding
# without needing an external Supabase project. Demo data only — fully fake.
_DEMO_SUPABASE_TABLES = {
    "customers": [
        {"id": 1, "nombre": "Ana Torres", "email": "ana@acme-demo.local",
         "telefono": "+51 999 000 111", "tarjeta_last4": "4242"},
        {"id": 2, "nombre": "Luis Vega", "email": "luis@acme-demo.local",
         "telefono": "+51 988 222 333", "tarjeta_last4": "1111"},
    ],
    "users": [
        {"id": 1, "email": "admin@acme-demo.local", "role": "admin"},
    ],
}


@app.get("/demo/supabase/rest/v1/{table}")
async def demo_supabase_rest(table: str):
    """Mock Supabase REST (RLS off) para el target de demo — datos 100% falsos."""
    return JSONResponse(content=_DEMO_SUPABASE_TABLES.get(table, []))


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():
    auth_service.purge_expired_sessions()
    port = os.getenv("API_PORT", 8000)
    print("=" * 60)
    print("VicoGuard AI -- API Server v2.0.0 (multi-tenant)")
    print("=" * 60)
    print(f"App:   http://localhost:{port}/ui/login")
    print(f"Docs:  http://localhost:{port}/docs")
    print(f"Demo:  http://localhost:{port}/demo/vulnerable")
    print(f"OpenAI:   {'OK' if os.getenv('OPENAI_API_KEY') and not os.getenv('OPENAI_API_KEY','').startswith('sk-xxx') else 'missing/placeholder'}")
    print(f"Telegram: {'OK' if os.getenv('TELEGRAM_BOT_TOKEN') and not os.getenv('TELEGRAM_BOT_TOKEN','').startswith('123456') else 'missing/placeholder'}")
    print("=" * 60)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        reload=True,
    )
