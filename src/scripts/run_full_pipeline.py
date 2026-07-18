"""
VicoGuard AI — Pipeline Completo (Orquestador)
================================================
Este script ejecuta el flujo completo del MVP:
1. Escanea la URL objetivo
2. Envía resultados al LLM para análisis
3. Despacha la alerta por Telegram

Uso:
    python scripts/run_full_pipeline.py https://tu-app.com
"""
import sys
import json

sys.path.insert(0, ".")

from scanner.services.security_scanner import SecurityScanner
from scanner.services.ai_engine import analyze_scan_results
from scanner.services.notifications import NotificationDispatcher


def run_pipeline(target_url: str):
    """Ejecuta el pipeline completo: Escaneo → IA → Notificación."""

    print("=" * 60)
    print("🛡️  VicoGuard AI — Pipeline de Seguridad Completo")
    print("=" * 60)

    # PASO 1: Escaneo
    print("\n📡 PASO 1: Ejecutando escaneo de seguridad...")
    scanner = SecurityScanner(target_url)
    scan_results = scanner.run_full_scan()
    print(f"   ✅ Escaneo completado. {scan_results['total_findings']} hallazgos encontrados.")

    # PASO 2: Análisis con IA
    print("\n🧠 PASO 2: Enviando resultados al motor de IA...")
    ai_analysis = analyze_scan_results(scan_results)
    print(f"   ✅ Análisis completado. Security Score: {ai_analysis.get('security_score', '?')}/100")

    # PASO 3: Notificación
    print("\n📱 PASO 3: Despachando alerta por Telegram...")
    dispatcher = NotificationDispatcher()
    notification_results = dispatcher.dispatch(ai_analysis, channels=["telegram"])

    for nr in notification_results:
        channel = nr["channel"]
        ok = nr["result"].get("ok", False)
        status = "✅ Enviado" if ok else "❌ Error"
        print(f"   {status} por {channel}")

    # Resultado final
    print("\n" + "=" * 60)
    print("🏁 Pipeline completado.")
    print(f"   Security Score: {ai_analysis.get('security_score', '?')}/100")
    print(f"   Vulnerabilidades: {scan_results['critical_count']} críticas, {scan_results['high_count']} altas")
    print("=" * 60)

    return ai_analysis


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = run_pipeline(url)
