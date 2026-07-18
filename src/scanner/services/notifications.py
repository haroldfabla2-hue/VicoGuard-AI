"""
VicoGuard AI — Notification Dispatcher (Router de Notificaciones Omnicanal)
============================================================================
Envía alertas al canal preferido del usuario: Telegram, WhatsApp o Email.
Luis: Este es tu módulo principal de integraciones.
"""
import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()


class TelegramNotifier:
    """Envía mensajes formateados por Telegram Bot API."""

    def __init__(self):
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"

    def send_alert(self, ai_analysis: dict) -> dict:
        """Formatea y envía la alerta de vulnerabilidad por Telegram."""
        score = ai_analysis.get("security_score", "?")
        summary = ai_analysis.get("summary", "Sin resumen disponible.")
        findings = ai_analysis.get("findings", [])

        # Determinar emoji del score
        score_emoji = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"

        # Construir mensaje Markdown
        message = f"""🚨 *ALERTA DE SEGURIDAD — VicoGuard AI* 🚨
━━━━━━━━━━━━━━━━━━━━━━━

{score_emoji} *Security Score: {score}/100*

📋 *Resumen:* {summary}
"""
        for f in findings[:3]:  # Máximo 3 hallazgos en el mensaje
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.get("severity"), "⚪")
            message += f"""
{severity_emoji} *{f.get('severity', 'N/A')}:* {f.get('title_business', 'Sin título')}
"""
            if f.get("analogy"):
                message += f"💡 _{f['analogy']}_\n"

            if f.get("remediation_code"):
                message += f"""
🛠️ *Solución:*
```
{f['remediation_code']}
```
"""

        message += "\n✅ _¿Ya aplicaste el parche? Escribe \"Listo\" y reescanearemos tu app._\n\n_Powered by VicoGuard AI 🛡️_"

        return self._send_message(message)

    def send_server_alert(self, correlation: dict) -> dict:
        """Envía alerta de monitoreo de servidor correlacionada."""
        status = correlation.get("overall_status", "UNKNOWN")
        status_emoji = {"UNDER_ATTACK": "🚨", "SUSPICIOUS": "⚠️", "HEALTHY": "✅"}.get(status, "❓")

        message = f"""{status_emoji} *ESTADO DEL SERVIDOR — VicoGuard AI*
━━━━━━━━━━━━━━━━━━━━━━━

📊 *Estado:* {status}
🔍 *Eventos analizados:* {correlation.get('events_analyzed', 0)}
🗑️ *Ruido filtrado:* {correlation.get('noise_filtered', 0)}

📝 *Resumen:* {correlation.get('threat_summary', 'Sin eventos relevantes.')}
"""
        for threat in correlation.get("real_threats", []):
            message += f"""
🔴 *{threat.get('type', 'N/A')}:* {threat.get('description', '')}
💡 *Recomendación:* {threat.get('recommendation', '')}
"""
            if threat.get("action_command"):
                message += f"```\n{threat['action_command']}\n```\n"

        if correlation.get("noise_explained"):
            message += f"\n🤖 *Ruido filtrado:* _{correlation['noise_explained']}_"

        message += "\n\n_Powered by VicoGuard AI 🛡️_"

        return self._send_message(message)

    def _send_message(self, text: str) -> dict:
        """Envía un mensaje de texto por Telegram."""
        url = f"{self.api_url}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }
        response = requests.post(url, json=payload)
        return response.json()


class EmailNotifier:
    """Placeholder para envío de correos (Resend/SendGrid). Activar post-MVP."""

    def send_alert(self, ai_analysis: dict) -> dict:
        # TODO: Implementar con Resend API o SendGrid
        print("[EMAIL] Notificación por email pendiente de implementar.")
        return {"ok": True, "channel": "email", "status": "placeholder"}


class WhatsAppNotifier:
    """Placeholder para envío por WhatsApp (Twilio). Activar post-MVP."""

    def send_alert(self, ai_analysis: dict) -> dict:
        # TODO: Implementar con Twilio WhatsApp API
        print("[WHATSAPP] Notificación por WhatsApp pendiente de implementar.")
        return {"ok": True, "channel": "whatsapp", "status": "placeholder"}


class NotificationDispatcher:
    """Router central que envía alertas al canal que el usuario tenga configurado."""

    def __init__(self):
        self.telegram = TelegramNotifier()
        self.email = EmailNotifier()
        self.whatsapp = WhatsAppNotifier()

    def dispatch(self, ai_analysis: dict, channels: list = None) -> list:
        """Envía la alerta a todos los canales activos del usuario."""
        if channels is None:
            channels = ["telegram"]  # Default para el MVP

        results = []
        for channel in channels:
            if channel == "telegram":
                results.append({"channel": "telegram", "result": self.telegram.send_alert(ai_analysis)})
            elif channel == "email":
                results.append({"channel": "email", "result": self.email.send_alert(ai_analysis)})
            elif channel == "whatsapp":
                results.append({"channel": "whatsapp", "result": self.whatsapp.send_alert(ai_analysis)})

        return results


# --- Testing directo ---
if __name__ == "__main__":
    dispatcher = NotificationDispatcher()

    mock_analysis = {
        "security_score": 38,
        "summary": "Tu aplicación tiene una vulnerabilidad crítica en la base de datos.",
        "findings": [
            {
                "severity": "CRITICAL",
                "title_business": "Tu lista completa de clientes está expuesta a internet",
                "analogy": "Es como dejar los archivos de tus clientes en una mesa en la vereda.",
                "remediation_code": "ALTER TABLE customers ENABLE ROW LEVEL SECURITY;",
            }
        ]
    }

    print("📡 Despachando alerta de prueba...")
    results = dispatcher.dispatch(mock_analysis, channels=["telegram"])
    print(json.dumps(results, indent=2, ensure_ascii=False))
