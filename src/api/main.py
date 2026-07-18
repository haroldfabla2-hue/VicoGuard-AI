"""
VicoGuard AI — API Server (FastAPI)
====================================
Servidor REST que expone los endpoints documentados en 2_TECHNICAL_ARCHITECTURE.md.
Conecta el frontend con el backend de escaneo, IA y notificaciones.

Uso:
    cd src
    uvicorn api.main:app --reload --port 8000

Endpoints:
    POST /api/v1/scan/repository    → Escanea una URL y devuelve análisis IA
    POST /api/v1/telemetry/ingest   → Recibe logs de servidor y los correlaciona
    GET  /api/v1/brain/stats        → Estadísticas del cerebro cognitivo
    POST /api/v1/brain/feedback     → Marca remediación como exitosa/fallida
    GET  /api/v1/health             → Health check
"""
import os
import sys
import json
import time
import uuid
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from dotenv import load_dotenv

# Agregar el directorio src al path para imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()

from scanner.services.security_scanner import SecurityScanner
from scanner.services.ai_engine import analyze_scan_results, correlate_server_logs
from scanner.services.notifications import NotificationDispatcher
from scanner.services.cognitive_brain import CognitiveSecurityBrain

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

# CORS — permitir que la UI se conecte desde cualquier origen (MVP)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instancias globales
brain = CognitiveSecurityBrain(db_path="vicoguard_brain.db")
dispatcher = NotificationDispatcher()


# ============================================================
# Modelos Pydantic (Request/Response)
# ============================================================

class ScanRequest(BaseModel):
    """Solicitud de escaneo de repositorio/URL."""
    project_id: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_url: str = Field(..., description="URL del sitio web o repositorio a escanear")
    branch: Optional[str] = "main"
    notify: Optional[bool] = True
    channels: Optional[list] = ["telegram"]


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
# Endpoints
# ============================================================

@app.get("/api/v1/health")
async def health_check():
    """Health check del servidor."""
    return {
        "status": "healthy",
        "service": "VicoGuard AI",
        "version": "1.0.0-hackathon",
        "timestamp": datetime.utcnow().isoformat(),
        "brain_stats": brain.get_stats(),
    }


@app.post("/api/v1/scan/repository")
async def scan_repository(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Escanea una URL objetivo y devuelve análisis de seguridad con IA.
    
    Flujo: Scanner → AI Engine → Cognitive Brain → Telegram
    """
    scan_id = str(uuid.uuid4())
    start_time = time.time()

    # PASO 1: Escaneo de seguridad
    try:
        scanner = SecurityScanner(request.repo_url)
        scan_results = scanner.run_full_scan()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en escaneo: {str(e)}")

    # PASO 2: Verificar cache causal (cerebro cognitivo)
    scan_fingerprint = None
    cached_response = None
    if scan_results.get("findings"):
        # Crear representación del hallazgo para fingerprinting
        finding_repr = json.dumps(scan_results["findings"][0], sort_keys=True)
        scan_fingerprint = brain.compute_fingerprint(finding_repr)

        # Buscar en la memoria causal
        cached = brain.recall_by_fingerprint(scan_fingerprint)
        if cached and cached.get("outcome") == "success":
            cached_response = cached

    # PASO 3: Análisis con IA (solo si no hay cache hit)
    ai_analysis = None
    source = "cache"
    if cached_response:
        ai_analysis = json.loads(cached_response.get("remediation_applied", "{}"))
        source = "causal_cache"
        latency_ms = int((time.time() - start_time) * 1000)
    else:
        try:
            ai_analysis = analyze_scan_results(scan_results)
            source = "llm"
        except Exception as e:
            # Fallback: devolver resultados crudos si la IA falla
            ai_analysis = {
                "security_score": max(0, 100 - (scan_results["critical_count"] * 25) - (scan_results["high_count"] * 15)),
                "summary": f"Escaneo completado. Se encontraron {scan_results['total_findings']} hallazgos.",
                "findings": scan_results["findings"],
                "ai_error": str(e),
            }
            source = "fallback"
        latency_ms = int((time.time() - start_time) * 1000)

    # PASO 4: Guardar en el cerebro cognitivo
    if scan_results.get("findings"):
        brain.receive_threat({
            "type": "SCAN_RESULT",
            "target": request.repo_url,
            "findings_count": scan_results["total_findings"],
            "critical_count": scan_results["critical_count"],
            "score": ai_analysis.get("security_score", 0),
        })

        # Guardar remediación para cache futuro
        if scan_fingerprint and source == "llm":
            brain.save_remediation(
                fingerprint=scan_fingerprint,
                remediation=json.dumps(ai_analysis),
            )

    # PASO 5: Notificación (en background para no bloquear la respuesta)
    if request.notify and ai_analysis:
        background_tasks.add_task(
            _send_notification, ai_analysis, request.channels
        )

    return {
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
        "notification_sent": request.notify,
    }


@app.post("/api/v1/telemetry/ingest")
async def ingest_telemetry(request: TelemetryRequest, background_tasks: BackgroundTasks):
    """
    Recibe logs del servidor del cliente, los correlaciona con IA,
    y envía alertas si detecta amenazas.
    """
    start_time = time.time()

    if not request.events:
        return {"status": "ok", "processed_events": 0, "message": "No hay eventos."}

    # Convertir eventos a texto para el LLM
    log_text = "\n".join(
        f"[{e.get('timestamp', 'N/A')}] {e.get('type', 'UNKNOWN')} | "
        f"src={e.get('source_ip', '?')} | status={e.get('status_code', '?')} | "
        f"path={e.get('path', '?')}"
        for e in request.events
    )

    # Correlacionar con IA
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

    # Registrar en cerebro cognitivo
    for event in request.events:
        brain.receive_threat({
            "type": event.get("type", "TELEMETRY_EVENT"),
            "source_ip": event.get("source_ip", "unknown"),
            "path": event.get("path", "/"),
            "status_code": event.get("status_code", 0),
        })

    # Si hay amenazas reales, notificar
    if correlation.get("real_threats"):
        background_tasks.add_task(
            _send_server_notification, correlation
        )

    latency_ms = int((time.time() - start_time) * 1000)

    return {
        "status": "processed",
        "processed_events": len(request.events),
        "latency_ms": latency_ms,
        "correlation": correlation,
    }


@app.get("/api/v1/brain/stats")
async def get_brain_stats():
    """Devuelve estadísticas del cerebro cognitivo."""
    stats = brain.get_stats()
    return {
        "status": "ok",
        "brain": stats,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/api/v1/brain/feedback")
async def submit_feedback(request: FeedbackRequest):
    """
    El usuario indica si una remediación funcionó o no.
    Esto alimenta la memoria causal para futuras respuestas instantáneas.
    """
    if request.success:
        brain.mark_success(request.threat_fingerprint)
    else:
        brain.mark_failed(request.threat_fingerprint)

    return {
        "status": "ok",
        "fingerprint": request.threat_fingerprint,
        "marked_as": "success" if request.success else "failed",
        "message": "Gracias. El cerebro de VicoGuard aprendió de tu feedback.",
    }


# ============================================================
# Background Tasks
# ============================================================

def _send_notification(ai_analysis: dict, channels: list):
    """Envía notificación en background."""
    try:
        dispatcher.dispatch(ai_analysis, channels=channels)
    except Exception as e:
        print(f"[!] Error enviando notificación: {e}")


def _send_server_notification(correlation: dict):
    """Envía alerta de servidor en background."""
    try:
        telegram = dispatcher.telegram
        telegram.send_server_alert(correlation)
    except Exception as e:
        print(f"[!] Error enviando alerta de servidor: {e}")


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event():
    print("=" * 60)
    print("🛡️  VicoGuard AI — API Server v1.0.0")
    print("=" * 60)
    print(f"📊 Brain stats: {brain.get_stats()}")
    print(f"📡 Docs: http://localhost:{os.getenv('API_PORT', 8000)}/docs")
    print("=" * 60)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000)),
        reload=True,
    )
