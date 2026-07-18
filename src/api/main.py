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

# ============================================================
# App Setup
# ============================================================

app = FastAPI(
    title="VicoGuard AI",
    description="Agente Autónomo de Ciberseguridad para Pymes — API REST",
    version="2.0.0-hackathon",
    docs_url="/docs",
    redoc_url="/redoc",
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


def _set_session_cookie(response: Response, token: str):
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
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
                results = dispatcher.dispatch(
                    ai_analysis, channels=request.channels or ["telegram"],
                    threat_fingerprint=feedback_token, scan_id=feedback_token,
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
    _set_session_cookie(response, token)
    tenants.get(user.id)  # provisiona la BD aislada del usuario
    return {"status": "ok", "user": _user_public(user)}


@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, request: Request, response: Response):
    try:
        user = auth_service.authenticate(req.email, req.password)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    token = auth_service.create_session(user.id, request.headers.get("user-agent", ""))
    _set_session_cookie(response, token)
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
        background_tasks.add_task(_send_server_notification, correlation)

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

    if ref:
        ctx = tenants.get(ref["user_id"])
        if action == "success":
            rid = _resolve_brain_record_id(ctx, ref["record_id"]) or ref["record_id"]
            ctx.brain.mark_success(rid)
            answer_text = "Parche marcado como aplicado. VicoGuard aprendio."
            dispatcher.telegram._send_message(
                "*Feedback recibido*\nRemediacion marcada como exitosa. "
                "La proxima vez responderemos en <1s desde el Causal Cache.")
        elif action == "failed":
            rid = _resolve_brain_record_id(ctx, ref["record_id"]) or ref["record_id"]
            ctx.brain.mark_failed(rid)
            answer_text = "Marcado como fallido. Generaremos otra solucion."
            dispatcher.telegram._send_message(
                "*Remediacion fallida*\nEl cerebro invalido este parche. "
                "Ejecuta un nuevo scan para regenerar la solucion.")
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
                    f"_{result.get('summary', '')}_")
                answer_text = "Detalles enviados"
            else:
                answer_text = "Scan no encontrado"
    else:
        answer_text = "Sesion expirada"

    try:
        dispatcher.telegram.answer_callback(callback_id, answer_text)
    except Exception as e:
        print(f"[Telegram webhook] answer error: {e}")
    return {"ok": True, "action": action}


# ============================================================
# Background Tasks
# ============================================================

def _send_server_notification(correlation: dict):
    try:
        dispatcher.telegram.send_server_alert(correlation)
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
        if screen in ("app", "dashboard", "audit") and not get_current_user(request):
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
