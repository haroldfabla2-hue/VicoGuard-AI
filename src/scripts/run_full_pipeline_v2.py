"""
VicoGuard AI — Pipeline Cognitivo Completo V2
================================================
Integra el ecosistema completo de Silhouette:
  - CognitiveSecurityBrain (4-tier memory + causal cache)
  - SecurityTeamOrchestrator (multi-agent + handoff)
  - SecurityScanner (escaneo de vulnerabilidades)
  - NotificationDispatcher (Telegram)

Flujo:
  1. Escanea la URL objetivo
  2. Cerebro cognitivo: ¿ya vimos este patrón? → Cache hit (0ms) o LLM (2s)
  3. Si cache miss: Equipo multi-agente analiza y genera remediación
  4. Despacha alerta por Telegram
  5. Espera feedback del usuario → Aprende

Uso:
    python scripts/run_full_pipeline_v2.py https://tu-app.com
"""
import sys
import json
import time

sys.path.insert(0, ".")

from scanner.services.security_scanner import SecurityScanner
from scanner.services.ai_engine import analyze_scan_results
from scanner.services.notifications import NotificationDispatcher
from scanner.services.cognitive_brain import (
    CognitiveSecurityBrain, ThreatType, ThreatSeverity
)
from scanner.services.agent_team import SecurityTeamOrchestrator


def classify_threat(scan_results: dict) -> tuple:
    """Clasifica el tipo y severidad predominante del escaneo."""
    threat_map = {
        "rls_disabled": ThreatType.RLS_DISABLED,
        "secret_exposed": ThreatType.SECRET_EXPOSED,
        "sql_injection": ThreatType.SQL_INJECTION,
        "xss": ThreatType.XSS,
        "brute_force": ThreatType.BRUTE_FORCE,
    }

    findings = scan_results.get("findings", [])
    if not findings:
        return ThreatType.UNKNOWN, ThreatSeverity.LOW

    # Buscar el hallazgo mas critico
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_finding = max(findings, key=lambda f: severity_rank.get(f.get("severity", "low"), 0))

    threat_type = threat_map.get(top_finding.get("type", "").lower(), ThreatType.UNKNOWN)
    severity = ThreatSeverity(top_finding.get("severity", "medium"))

    return threat_type, severity


def run_cognitive_pipeline(target_url: str, db_path: str = "vicoguard_brain.db"):
    """Pipeline cognitivo completo con cerebro de 4 capas."""

    print("=" * 60)
    print("  VICOGUARD AI — Pipeline Cognitivo V2")
    print("  Powered by Silhouette Brain Architecture")
    print("=" * 60)

    # Inicializar componentes
    brain = CognitiveSecurityBrain(db_path)
    team = SecurityTeamOrchestrator(llm_client=None)  # Mock para demo
    dispatcher = NotificationDispatcher()

    pipeline_start = time.time()

    # ━━━ PASO 1: Escaneo ━━━
    print("\n[SCAN] Ejecutando escaneo de seguridad...")
    scanner = SecurityScanner(target_url)
    scan_results = scanner.run_full_scan()
    total = scan_results.get("total_findings", 0)
    print(f"  {total} hallazgos encontrados.")

    # ━━━ PASO 2: Clasificacion ━━━
    threat_type, severity = classify_threat(scan_results)
    detail = json.dumps(scan_results, ensure_ascii=False)[:500]
    print(f"\n[CLASSIFY] Tipo: {threat_type.value}, Severidad: {severity.value}")

    # ━━━ PASO 3: Cerebro Cognitivo ━━━
    print("\n[BRAIN] Consultando memoria cognitiva...")
    brain_result = brain.receive_threat(
        threat_type=threat_type,
        detail=detail,
        severity=severity,
        target_url=target_url
    )

    if brain_result["source"] == "cache":
        # ¡Cache hit! No necesitamos LLM
        print(f"  [CACHE HIT] Patron conocido. Latencia: {brain_result['latency_ms']}ms")
        print(f"  Remediacion cacheada: {brain_result['record'].remediation_command}")
        print(f"  Tokens ahorrados: {brain_result['record'].llm_tokens_used}")

        ai_analysis = {
            "security_score": 100 - ({"critical": 60, "high": 40, "medium": 20, "low": 10}
                                     .get(severity.value, 20)),
            "remediation": brain_result["record"].remediation_explanation,
            "telegram_message": (
                f"*VicoGuard AI — Patron Conocido*\n\n"
                f"Amenaza: *{threat_type.value}*\n"
                f"Comando: `{brain_result['record'].remediation_command}`\n"
                f"Latencia: {brain_result['latency_ms']}ms (sin LLM)"
            ),
            "source": "cognitive_cache"
        }
    else:
        # Cache miss → Equipo multi-agente
        print(f"  [CACHE MISS] Patron nuevo. Activando equipo multi-agente...")
        print(f"\n[AGENTS] Despachando a 3 agentes especializados...")

        agent_result = team.run_full_pipeline(
            scan_results=scan_results,
            server_logs=""
        )

        print(f"  Agentes usados: {agent_result['agents_used']}")
        print(f"  Tiempo total: {agent_result['total_pipeline_seconds']}s")

        # Guardar remediacion en el cerebro
        remediation = agent_result.get("remediation", {})
        protocols = remediation.get("protocols", [])
        command = protocols[0]["technical_command"] if protocols else "# Sin comando"
        explanation = protocols[0]["plain_language"] if protocols else "Analisis pendiente"

        record_id = brain.save_remediation(
            brain_result["record"],
            command=command,
            explanation=explanation,
            model="multi-agent-team",
            tokens=200
        )

        ai_analysis = {
            "security_score": agent_result.get("threat_analysis", {}).get(
                "security_score",
                agent_result.get("audit", {}).get("risk_score", 50)
            ),
            "remediation": remediation,
            "telegram_message": agent_result.get("final_telegram_message", ""),
            "record_id": record_id,
            "source": "multi_agent_team"
        }

    # ━━━ PASO 4: Notificacion ━━━
    print(f"\n[NOTIFY] Despachando alerta...")
    print(f"  Mensaje Telegram:")
    print(f"  {ai_analysis.get('telegram_message', 'N/A')[:200]}")

    # En produccion: dispatcher.dispatch(ai_analysis, channels=["telegram"])

    # ━━━ PASO 5: Consolidar cerebro ━━━
    print(f"\n[DREAM] Ejecutando Dreamer Engine...")
    dream = brain.consolidate()
    print(f"  Consolidados: {dream['consolidated']}, Edges: {dream['edges_added']}")

    # ━━━ RESULTADO ━━━
    elapsed = round(time.time() - pipeline_start, 2)
    stats = brain.get_stats()

    print(f"\n{'=' * 60}")
    print(f"  PIPELINE COMPLETADO en {elapsed}s")
    print(f"{'=' * 60}")
    print(f"  Source:          {ai_analysis.get('source', 'unknown')}")
    print(f"  Security Score:  {ai_analysis.get('security_score', '?')}/100")
    print(f"  Total memorias:  {stats['total_memories']}")
    print(f"  Cache eligible:  {stats['cache_eligible']}")
    print(f"  Grafo entidades: {stats['graph_entities']}")
    print(f"  Grafo edges:     {stats['graph_relationships']}")
    print(f"{'=' * 60}")

    return ai_analysis


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = run_cognitive_pipeline(url)
