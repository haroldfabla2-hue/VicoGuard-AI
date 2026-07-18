"""
VicoGuard AI — API Server (FastAPI)
====================================
Servidor REST que expone los endpoints documentados en 2_TECHNICAL_ARCHITECTURE.md.
Conecta el frontend con el backend de escaneo, IA y notificaciones.

Uso:
    cd src
    uvicorn api.main:app --reload --port 8000

Endpoints:
    POST /api/v1/scan/repository    → Escanea una URL y devuelve análisis IA (sync)
    POST /api/v1/scan/start         → Inicia escaneo async con eventos en vivo
    GET  /api/v1/scan/{scan_id}     → Estado + eventos + resultado de un scan
    GET  /api/v1/scan/latest        → Último escaneo completado
    POST /api/v1/telemetry/ingest   → Recibe logs de servidor y los correlaciona
    GET  /api/v1/brain/stats        → Estadísticas del cerebro cognitivo
    POST /api/v1/brain/feedback     → Marca remediación como exitosa/fallida
    POST /api/v1/telegram/webhook   → Callbacks de botones inline de Telegram
    GET  /api/v1/health             → Health check
    GET  /ui/...                    → Pantallas HTML (Obsidian Stealth)
"""
import os
import sys
import json
import time
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Paths
SRC_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = SRC_DIR.parent
UI_DIR = PROJECT_ROOT / "ui_stitch"

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
from scanner.services.canonical_memory import CanonicalMemory

# ============================================================
# App Setup
# ============================================================

app = FastAPI(
    title="VicoGuard AI",
    description="🛡️ Agente Autónomo de Ciberseguridad para Pymes — API REST",
    version="1.0.0-hackathon",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instancias globales
brain = CognitiveSecurityBrain(db_path=str(SRC_DIR / "vicoguard_brain.db"))
dispatcher = NotificationDispatcher()
# Canonical Node Memory — dedup por identidad semántica (complementa el causal cache)
canonical = CanonicalMemory(db_path=str(SRC_DIR / "vicoguard_brain.db"))

# Store en memoria para demo (scan jobs + último resultado)
scan_jobs: dict = {}
latest_scan: dict = {}

# Thread pool so scanner HTTP calls can hit this same API (e.g. /demo/vulnerable)
# without deadlocking the single uvicorn worker.
_scan_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vg-scan")


# ============================================================
# Modelos Pydantic
# ============================================================

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
# Helpers — Scan pipeline con eventos en vivo
# ============================================================

def _append_event(scan_id: str, level: str, message: str, agent: str = "SYSTEM"):
    """Agrega un evento al stream del scan para la UI en vivo."""
    job = scan_jobs.get(scan_id)
    if not job:
        return
    event = {
        "ts": datetime.utcnow().strftime("%H:%M:%S"),
        "level": level,  # INFO | WARN | ALERT | OK | REASONING
        "agent": agent,
        "message": message,
    }
    job["events"].append(event)
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


def _resolve_brain_record_id(payload: str) -> Optional[str]:
    """Resuelve id de memoria episódica desde record_id o fingerprint."""
    if not payload:
        return None
    import sqlite3
    with sqlite3.connect(brain.db_path) as conn:
        row = conn.execute(
            """
            SELECT id FROM episodic_memories
            WHERE id = ? OR threat_fingerprint = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (payload, payload),
        ).fetchone()
    return row[0] if row else None


def _run_scan_pipeline(scan_id: str, request: ScanRequest) -> dict:
    """
    Pipeline completo: Scanner → AI → Brain → Telegram.
    Emite eventos al job store para la terminal en vivo.
    """
    start_time = time.time()
    job = scan_jobs.setdefault(scan_id, {
        "scan_id": scan_id,
        "status": "running",
        "target_url": request.repo_url,
        "events": [],
        "result": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    })
    job["status"] = "running"

    try:
        _append_event(scan_id, "INFO", f"TARGET: {request.repo_url}", "ORCHESTRATOR")
        _append_event(scan_id, "INFO", "Inicializando reconocimiento...", "ORCHESTRATOR")

        # PASO 1: Escaneo
        _append_event(scan_id, "INFO", "Mapeando superficie pública...", "SECOPS")
        scanner = SecurityScanner(request.repo_url)
        scan_results = scanner.run_full_scan()

        total = scan_results.get("total_findings", 0)
        critical = scan_results.get("critical_count", 0)
        high = scan_results.get("high_count", 0)
        _append_event(
            scan_id, "WARN" if critical or high else "OK",
            f"Hallazgos: {total} total · {critical} críticos · {high} altos",
            "SECOPS",
        )

        for finding in scan_results.get("findings", [])[:5]:
            sev = finding.get("severity", "INFO")
            title = (
                finding.get("title_technical")
                or finding.get("title_business")
                or finding.get("title")
                or finding.get("type")
                or "finding"
            )
            level = "ALERT" if sev == "CRITICAL" else "WARN" if sev == "HIGH" else "INFO"
            _append_event(scan_id, level, f"[{sev}] {title}", "SECOPS")

        # PASO 2: Cerebro cognitivo (cache causal)
        scan_fingerprint = None
        brain_record = None
        brain_record_id = None
        cached_hit = False
        if scan_results.get("findings"):
            threat_type, severity = _classify_scan(scan_results)
            detail = json.dumps(scan_results["findings"][0], sort_keys=True, ensure_ascii=False)
            scan_fingerprint = CognitiveSecurityBrain.compute_fingerprint(
                threat_type.value, detail
            )
            brain_result = brain.receive_threat(
                threat_type=threat_type,
                detail=detail,
                severity=severity,
                target_url=request.repo_url,
                context={
                    "scan_id": scan_id,
                    "total_findings": scan_results["total_findings"],
                },
            )
            brain_record = brain_result.get("record")
            if brain_record is not None:
                brain_record_id = getattr(brain_record, "id", None)
                scan_fingerprint = getattr(brain_record, "threat_fingerprint", scan_fingerprint)
            if brain_result.get("source") == "cache":
                cached_hit = True
                _append_event(scan_id, "OK", "Cache causal HIT — respuesta instantánea", "BRAIN")
            else:
                _append_event(scan_id, "INFO", "Cache miss — requiere análisis", "BRAIN")

        # PASO 2b: Canonical Node Memory — entity resolution / dedup no redundante.
        # Cada finding pasa por MERGE | VARIANT | NEW antes de considerarse "nuevo".
        # Re-escanear la misma URL apila evidencia en el nodo canónico, no duplica.
        canonical_summary = None
        if scan_results.get("findings"):
            try:
                canonical_summary = canonical.ingest_scan(scan_results, scan_id=scan_id)
                for ev_msg in canonical_summary["events"]:
                    lvl = "OK" if "canonical hit" in ev_msg else "INFO"
                    _append_event(scan_id, lvl, ev_msg, "BRAIN")
                _append_event(
                    scan_id, "INFO",
                    f"Memoria canónica: {canonical_summary['new']} nuevas · "
                    f"{canonical_summary['merges']} merges · {canonical_summary['variants']} variantes",
                    "BRAIN",
                )
            except Exception as e:
                _append_event(scan_id, "WARN", f"Canonical memory error: {e}", "BRAIN")

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
                    "security_score": max(
                        0,
                        100
                        - (scan_results["critical_count"] * 25)
                        - (scan_results["high_count"] * 15),
                    ),
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
            _append_event(scan_id, "REASONING", "Correlacionando hallazgos con GPT-4o...", "THREAT")
            try:
                ai_analysis = analyze_scan_results(scan_results)
                source = "llm"
                _append_event(scan_id, "OK", "Análisis IA completado", "THREAT")
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
                _append_event(scan_id, "WARN", f"IA fallback: {e}", "THREAT")

        score = ai_analysis.get("security_score", 0)
        _append_event(
            scan_id, "ALERT" if score < 50 else "OK",
            f"Security Score: {score}/100 — {ai_analysis.get('summary', '')[:120]}",
            "REMEDIATION",
        )

        # PASO 4: Persistir remediación en memoria episódica
        if brain_record is not None and source in ("llm", "fallback") and not cached_hit:
            try:
                brain_record_id = brain.save_remediation(
                    brain_record,
                    command=ai_analysis.get("remediation_command", "# Ver hallazgos en /ui/dashboard"),
                    explanation=json.dumps(ai_analysis, ensure_ascii=False)[:4000],
                    model="gpt-4o" if source == "llm" else "heuristic-fallback",
                    tokens=0,
                )
                _append_event(scan_id, "INFO", "Amenaza registrada en memoria episódica", "BRAIN")
            except Exception as e:
                _append_event(scan_id, "WARN", f"Brain save error: {e}", "BRAIN")

        # PASO 5: Notificación
        notification_sent = False
        feedback_id = brain_record_id or scan_fingerprint or ""
        if request.notify and ai_analysis:
            _append_event(scan_id, "INFO", "Despachando alerta a Telegram...", "ORCHESTRATOR")
            try:
                ai_analysis["scan_id"] = scan_id
                results = dispatcher.dispatch(
                    ai_analysis,
                    channels=request.channels or ["telegram"],
                    threat_fingerprint=feedback_id,
                    scan_id=scan_id,
                )
                notification_sent = True
                _append_event(scan_id, "OK", "Alerta enviada a Telegram", "ORCHESTRATOR")
                ai_analysis["_threat_fingerprint"] = feedback_id
                print(f"[Telegram] dispatch result: {results}")
            except Exception as e:
                _append_event(scan_id, "WARN", f"Telegram error: {e}", "ORCHESTRATOR")

        latency_ms = int((time.time() - start_time) * 1000)

        result = {
            "scan_id": scan_id,
            "project_id": request.project_id,
            "status": "completed",
            "source": source,
            "latency_ms": latency_ms,
            "target_url": request.repo_url,
            "security_score": ai_analysis.get("security_score", "N/A"),
            "summary": ai_analysis.get("summary", ""),
            "findings": ai_analysis.get("findings", scan_results.get("findings", [])),
            "scan_raw": {
                "total": scan_results["total_findings"],
                "critical": scan_results["critical_count"],
                "high": scan_results["high_count"],
                "medium": scan_results["medium_count"],
            },
            "notification_sent": notification_sent,
            "threat_fingerprint": scan_fingerprint,
            "brain_record_id": brain_record_id,
            "canonical": {
                "new": canonical_summary["new"],
                "merges": canonical_summary["merges"],
                "variants": canonical_summary["variants"],
                "canonical_ids": canonical_summary["canonical_ids"],
            } if canonical_summary else None,
        }

        job["status"] = "completed"
        job["result"] = result
        job["updated_at"] = datetime.utcnow().isoformat()

        global latest_scan
        latest_scan = result

        _append_event(scan_id, "OK", f"Pipeline completado en {latency_ms}ms", "ORCHESTRATOR")
        return result

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
        job["updated_at"] = datetime.utcnow().isoformat()
        _append_event(scan_id, "ALERT", f"Error fatal: {e}", "ORCHESTRATOR")
        raise


# ============================================================
# Endpoints
# ============================================================

@app.get("/api/v1/health")
async def health_check():
    """Health check del servidor."""
    openai_ok = bool(os.getenv("OPENAI_API_KEY") and not os.getenv("OPENAI_API_KEY", "").startswith("sk-xxx"))
    telegram_ok = bool(
        os.getenv("TELEGRAM_BOT_TOKEN")
        and not os.getenv("TELEGRAM_BOT_TOKEN", "").startswith("123456")
    )
    return {
        "status": "healthy",
        "service": "VicoGuard AI",
        "version": "1.0.0-hackathon",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "openai_configured": openai_ok,
            "telegram_configured": telegram_ok,
        },
        "brain_stats": brain.get_stats(),
        "has_latest_scan": bool(latest_scan),
    }


@app.post("/api/v1/scan/repository")
async def scan_repository(request: ScanRequest):
    """
    Escanea una URL objetivo y devuelve análisis de seguridad con IA (síncrono).
    Flujo: Scanner → AI Engine → Cognitive Brain → Telegram
    """
    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target_url": request.repo_url,
        "events": [],
        "result": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    try:
        return _run_scan_pipeline(scan_id, request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en escaneo: {str(e)}")


@app.post("/api/v1/scan/start")
async def start_scan_async(request: ScanRequest):
    """
    Inicia un escaneo en un thread pool y devuelve scan_id inmediatamente.
    La UI hace polling a GET /api/v1/scan/{scan_id} para ver eventos en vivo.
    Usa threads (no BackgroundTasks) para poder escanear /demo/vulnerable
    en el mismo proceso sin deadlock del worker.
    """
    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "target_url": request.repo_url,
        "events": [],
        "result": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    _append_event(scan_id, "INFO", "Scan encolado — iniciando pipeline...", "ORCHESTRATOR")
    loop = asyncio.get_running_loop()
    loop.run_in_executor(_scan_executor, _run_scan_pipeline_safe, scan_id, request)
    return {
        "scan_id": scan_id,
        "status": "queued",
        "target_url": request.repo_url,
        "poll_url": f"/api/v1/scan/{scan_id}",
    }


def _run_scan_pipeline_safe(scan_id: str, request: ScanRequest):
    """Wrapper para background task que no propaga excepciones."""
    try:
        _run_scan_pipeline(scan_id, request)
    except Exception as e:
        print(f"[!] Scan {scan_id} failed: {e}")


@app.get("/api/v1/scan/latest")
async def get_latest_scan():
    """Devuelve el último escaneo completado (para dashboard)."""
    if not latest_scan:
        return {
            "status": "empty",
            "message": "No hay escaneos aún. Ejecuta un audit desde la UI.",
            "result": None,
        }
    return {"status": "ok", "result": latest_scan}


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Estado, eventos en vivo y resultado de un scan."""
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan no encontrado")
    return job


@app.post("/api/v1/telemetry/ingest")
async def ingest_telemetry(request: TelemetryRequest, background_tasks: BackgroundTasks):
    """
    Recibe logs del servidor del cliente, los correlaciona con IA,
    y envía alertas si detecta amenazas.
    """
    start_time = time.time()

    if not request.events:
        return {"status": "ok", "processed_events": 0, "message": "No hay eventos."}

    log_text = "\n".join(
        f"[{e.get('timestamp', 'N/A')}] {e.get('type', 'UNKNOWN')} | "
        f"src={e.get('source_ip', '?')} | status={e.get('status_code', '?')} | "
        f"path={e.get('path', '?')}"
        for e in request.events
    )

    try:
        correlation = correlate_server_logs(log_text)
    except Exception as e:
        correlation = {
            "overall_status": "UNKNOWN",
            "threat_summary": f"Error al correlacionar: {str(e)}",
            "events_analyzed": len(request.events),
            "noise_filtered": 0,
            "real_threats": [],
        }

    for event in request.events:
        try:
            brain.receive_threat(
                threat_type=ThreatType.BRUTE_FORCE
                if str(event.get("type", "")).upper() in ("LOGIN_FAIL", "BRUTE_FORCE")
                else ThreatType.RECONNAISSANCE,
                detail=(
                    f"{event.get('type', 'TELEMETRY')} "
                    f"src={event.get('source_ip', '?')} "
                    f"path={event.get('path', '/')} "
                    f"status={event.get('status_code', '?')}"
                ),
                severity=ThreatSeverity.HIGH
                if int(event.get("status_code", 0) or 0) >= 401
                else ThreatSeverity.MEDIUM,
                source_ip=event.get("source_ip"),
                target_url=event.get("path"),
            )
        except Exception as e:
            print(f"[!] brain.receive_threat telemetry error: {e}")

    if correlation.get("real_threats"):
        background_tasks.add_task(_send_server_notification, correlation)

    latency_ms = int((time.time() - start_time) * 1000)

    return {
        "status": "processed",
        "processed_events": len(request.events),
        "latency_ms": latency_ms,
        "correlation": correlation,
    }


@app.get("/api/v1/brain/stats")
async def get_brain_stats():
    """Devuelve estadísticas del cerebro cognitivo + memoria canónica (dedup)."""
    stats = brain.get_stats()
    dedup = canonical.get_stats()
    return {
        "status": "ok",
        "brain": stats,
        "canonical": dedup,
        "timestamp": datetime.utcnow().isoformat(),
        "latest_scan": {
            "security_score": latest_scan.get("security_score"),
            "target_url": latest_scan.get("target_url"),
            "scan_raw": latest_scan.get("scan_raw"),
        } if latest_scan else None,
    }


@app.get("/api/v1/brain/entities")
async def list_canonical_entities(entity_type: Optional[str] = None, limit: int = 50):
    """Lista los nodos canónicos activos (para dashboard / grafo de memoria)."""
    return {
        "status": "ok",
        "entities": canonical.list_entities(limit=limit, entity_type=entity_type),
        "dedup": canonical.get_stats(),
    }


@app.get("/api/v1/brain/entity/{canonical_id}")
async def get_canonical_entity(canonical_id: str):
    """Detalle de un nodo canónico: evidencias, relaciones y revisiones."""
    entity = canonical.get_entity(canonical_id)
    if not entity:
        raise HTTPException(status_code=404, detail=f"Entidad canónica no encontrada: {canonical_id}")
    return {"status": "ok", "entity": entity}


@app.post("/api/v1/brain/feedback")
async def submit_feedback(request: FeedbackRequest):
    """
    El usuario indica si una remediación funcionó o no.
    Esto alimenta la memoria causal para futuras respuestas instantáneas.
    """
    record_id = _resolve_brain_record_id(request.threat_fingerprint)
    if not record_id:
        raise HTTPException(status_code=404, detail="Registro de amenaza no encontrado")

    if request.success:
        brain.mark_success(record_id)
    else:
        brain.mark_failed(record_id)

    return {
        "status": "ok",
        "fingerprint": request.threat_fingerprint,
        "record_id": record_id,
        "marked_as": "success" if request.success else "failed",
        "message": "Gracias. El cerebro de VicoGuard aprendió de tu feedback.",
    }


@app.post("/api/v1/telegram/webhook")
async def telegram_webhook(request: Request):
    """
    Recibe callbacks de botones inline de Telegram
    (Aplicar Parche / Ignorar / Ver Detalles).
    """
    body = await request.json()
    callback = body.get("callback_query")
    if not callback:
        return {"ok": True}

    data = callback.get("data", "")
    callback_id = callback.get("id")
    chat_id = callback.get("message", {}).get("chat", {}).get("id")
    message_id = callback.get("message", {}).get("message_id")

    # Formato: vg:success:<fingerprint> | vg:failed:<fingerprint> | vg:details:<scan_id>
    parts = data.split(":", 2)
    if len(parts) < 3 or parts[0] != "vg":
        return {"ok": True}

    action, payload = parts[1], parts[2]
    answer_text = "OK"

    if action == "success":
        record_id = _resolve_brain_record_id(payload) or payload
        brain.mark_success(record_id)
        answer_text = "Parche marcado como aplicado. VicoGuard aprendio."
        if chat_id:
            dispatcher.telegram._send_message(
                "*Feedback recibido*\nRemediacion marcada como exitosa. "
                "La proxima vez responderemos en <1s desde el Causal Cache."
            )
    elif action == "failed":
        record_id = _resolve_brain_record_id(payload) or payload
        brain.mark_failed(record_id)
        answer_text = "Marcado como fallido. Generaremos otra solucion."
        if chat_id:
            dispatcher.telegram._send_message(
                "*Remediacion fallida*\nEl cerebro invalido este parche. "
                "Ejecuta un nuevo scan para regenerar la solucion."
            )
    elif action == "details":
        job = scan_jobs.get(payload) or {}
        result = job.get("result") or (latest_scan if latest_scan.get("scan_id") == payload else None)
        if result:
            findings_text = "\n".join(
                f"• *{f.get('severity', '?')}:* {f.get('title_business', f.get('title', 'N/A'))}"
                for f in result.get("findings", [])[:5]
            )
            dispatcher.telegram._send_message(
                f"📋 *Detalles del Scan*\n"
                f"Score: {result.get('security_score')}/100\n"
                f"Target: `{result.get('target_url')}`\n\n"
                f"{findings_text}\n\n"
                f"_{result.get('summary', '')}_"
            )
            answer_text = "📋 Detalles enviados"
        else:
            answer_text = "Scan no encontrado"

    # Answer callback (quita el loading del botón)
    try:
        dispatcher.telegram.answer_callback(callback_id, answer_text)
    except Exception as e:
        print(f"[Telegram webhook] answer error: {e}")

    return {"ok": True, "action": action, "message_id": message_id}


# ============================================================
# Background Tasks
# ============================================================

def _send_server_notification(correlation: dict):
    """Envía alerta de servidor en background."""
    try:
        dispatcher.telegram.send_server_alert(correlation)
    except Exception as e:
        print(f"[!] Error enviando alerta de servidor: {e}")


# ============================================================
# Static UI (Obsidian Stealth)
# ============================================================

UI_ROUTES = {
    "audit": "vicoguard_ai_security_audit",
    "dashboard": "threat_dashboard_vicoguard_ai",
    "live": "live_agent_execution_vicoguard_ai",
    "landing": "landing_page_vicoguard_ai",
    "login": "login_vicoguard_ai",
    "signup": "sign_up_vicoguard_ai",
    "chat": "secops_assistant_vicoguard_ai",
    "trust": "verification_trust_vicoguard_ai",
}


@app.get("/")
async def root_redirect():
    """Redirige a la pantalla de audit (entrada de la demo)."""
    return RedirectResponse(url="/ui/audit")


@app.get("/ui")
@app.get("/ui/")
async def ui_index():
    return RedirectResponse(url="/ui/audit")


@app.get("/ui/js/{filename}")
async def serve_ui_js(filename: str):
    """Sirve JS compartido (cliente API)."""
    js_path = UI_DIR / "js" / filename
    if not js_path.exists() or not filename.endswith(".js"):
        raise HTTPException(status_code=404, detail="Asset no encontrado")
    return FileResponse(js_path, media_type="application/javascript")


@app.get("/ui/{screen}")
async def serve_ui_screen(screen: str):
    """Sirve una pantalla HTML de ui_stitch por alias corto."""
    folder = UI_ROUTES.get(screen, screen)
    html_path = UI_DIR / folder / "code.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail=f"Pantalla no encontrada: {screen}")
    return FileResponse(html_path, media_type="text/html")


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
    """
    Página estática intencionalmente vulnerable (secretos fake + sin headers).
    Escanéala desde /ui/audit con: http://localhost:8000/demo/vulnerable
    """
    return HTMLResponse(
        content=DEMO_VULNERABLE_HTML,
        headers={
            # Explicitly omit security headers so the scanner reports them missing.
            "Cache-Control": "no-store",
        },
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
    rows = _DEMO_SUPABASE_TABLES.get(table, [])
    return JSONResponse(content=rows)


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():
    # Avoid emoji in console — Windows cp1252 crashes on Unicode shield/icons
    print("=" * 60)
    print("VicoGuard AI -- API Server v1.0.0")
    print("=" * 60)
    print(f"Brain stats: {brain.get_stats()}")
    print(f"Docs:  http://localhost:{os.getenv('API_PORT', 8000)}/docs")
    print(f"UI:    http://localhost:{os.getenv('API_PORT', 8000)}/ui/audit")
    print(f"Demo:  http://localhost:{os.getenv('API_PORT', 8000)}/demo/vulnerable")
    print(f"OpenAI: {'OK' if os.getenv('OPENAI_API_KEY') else 'missing'}")
    print(f"Telegram: {'OK' if os.getenv('TELEGRAM_BOT_TOKEN') else 'missing'}")
    print("=" * 60)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        reload=True,
    )
