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

    def send_alert(self, ai_analysis: dict, threat_fingerprint: str = "", scan_id: str = "", bot_token: str = None, chat_id: str = None) -> dict:
        """Formatea y envía la alerta de vulnerabilidad por Telegram con botones inline."""
        score = ai_analysis.get("security_score", "?")
        try:
            score_num = int(score)
        except (TypeError, ValueError):
            score_num = 0
        summary = ai_analysis.get("summary", "Sin resumen disponible.")
        findings = ai_analysis.get("findings", [])
        fingerprint = threat_fingerprint or ai_analysis.get("_threat_fingerprint", "")
        scan_id = scan_id or ai_analysis.get("scan_id", "")

        # Determinar emoji del score
        score_emoji = "🟢" if score_num >= 80 else "🟡" if score_num >= 50 else "🔴"

        # Construir mensaje Markdown
        message = f"""🚨 *ALERTA DE SEGURIDAD — VicoGuard AI* 🚨
━━━━━━━━━━━━━━━━━━━━━━━

{score_emoji} *Security Score: {score}/100*

📋 *Resumen:* {summary}
"""
        for f in findings[:3]:  # Máximo 3 hallazgos en el mensaje
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.get("severity"), "⚪")
            title = f.get("title_business") or f.get("title") or "Sin título"
            message += f"""
{severity_emoji} *{f.get('severity', 'N/A')}:* {title}
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

        message += "\n✅ _Usa los botones abajo para confirmar remediación._\n\n_Powered by VicoGuard AI 🛡️_"

        # Inline keyboard: Aplicar / Ignorar / Ver Detalles
        reply_markup = None
        if fingerprint or scan_id:
            row = []
            if fingerprint:
                row.append({"text": "✅ Aplicar Parche", "callback_data": f"vg:success:{fingerprint[:40]}"})
                row.append({"text": "❌ Ignorar", "callback_data": f"vg:failed:{fingerprint[:40]}"})
            buttons = [row] if row else []
            if scan_id:
                buttons.append([{"text": "📋 Ver Detalles", "callback_data": f"vg:details:{scan_id[:40]}"}])
            if buttons:
                reply_markup = {"inline_keyboard": buttons}

        return self._send_message(message, reply_markup=reply_markup, bot_token=bot_token, chat_id=chat_id)

    def send_server_alert(self, correlation: dict, bot_token: str = None, chat_id: str = None) -> dict:
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

        return self._send_message(message, bot_token=bot_token, chat_id=chat_id)

    def _send_message(self, text: str, reply_markup: dict = None, bot_token: str = None, chat_id: str = None) -> dict:
        """Envía un mensaje de texto por Telegram (opcionalmente con inline keyboard)."""
        token = bot_token or self.bot_token
        target_chat = chat_id or self.chat_id
        if not token or not target_chat:
            print("[Telegram] TOKEN o CHAT_ID no configurados — skip")
            return {"ok": False, "error": "missing_credentials"}

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": target_chat,
            "text": text,
            "parse_mode": "Markdown",
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        response = requests.post(url, json=payload, timeout=15)
        result = response.json()
        if not result.get("ok"):
            # Retry sin Markdown si falla el parseo
            payload.pop("parse_mode", None)
            response = requests.post(url, json=payload, timeout=15)
            result = response.json()
        return result

    def answer_callback(self, callback_query_id: str, text: str, bot_token: str = None) -> dict:
        """Responde a un callback de botón inline (quita el spinner).

        Usa el token del tenant si se provee (bots por-usuario); si no, el global.
        """
        token = bot_token or self.bot_token
        if not token:
            return {"ok": False}
        url = f"https://api.telegram.org/bot{token}/answerCallbackQuery"
        response = requests.post(
            url,
            json={"callback_query_id": callback_query_id, "text": text, "show_alert": False},
            timeout=10,
        )
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

    def dispatch(
        self,
        ai_analysis: dict,
        channels: list = None,
        threat_fingerprint: str = "",
        scan_id: str = "",
        bot_token: str = None,
        chat_id: str = None,
    ) -> list:
        """Envía la alerta a todos los canales activos del usuario."""
        if channels is None:
            channels = ["telegram"]  # Default para el MVP

        results = []
        for channel in channels:
            if channel == "telegram":
                results.append({
                    "channel": "telegram",
                    "result": self.telegram.send_alert(
                        ai_analysis,
                        threat_fingerprint=threat_fingerprint,
                        scan_id=scan_id or ai_analysis.get("scan_id", ""),
                        bot_token=bot_token,
                        chat_id=chat_id,
                    ),
                })
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
