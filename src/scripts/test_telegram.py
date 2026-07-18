"""
VicoGuard AI — Test Telegram Bot
================================
Ejecuta este script para verificar que el bot de Telegram funciona.
Asegúrate de tener las variables TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID en tu .env

Uso:
    python scripts/test_telegram.py
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram_message(text: str, parse_mode: str = "Markdown") -> dict:
    """Envía un mensaje por Telegram. Reutilizable en todo el proyecto."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": parse_mode,
    }
    response = requests.post(url, json=payload)
    return response.json()


def main():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("❌ ERROR: Falta TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID en el archivo .env")
        print("   1. Crea un bot en https://t.me/BotFather")
        print("   2. Envíale /start a tu bot")
        print(f"   3. Visita: https://api.telegram.org/bot<TU_TOKEN>/getUpdates")
        print("   4. Copia el chat_id y agrégalo al .env")
        return

    test_message = """
🛡️ *VicoGuard AI — Test de Conexión*
━━━━━━━━━━━━━━━━━━━━━━━

✅ *¡Conexión exitosa!*
Tu bot de Telegram está configurado correctamente.

📊 Este es un mensaje de prueba.
Cuando el sistema detecte una vulnerabilidad,
recibirás alertas con este formato.

_Powered by VicoGuard AI 🛡️_
"""

    print("📡 Enviando mensaje de prueba a Telegram...")
    result = send_telegram_message(test_message)

    if result.get("ok"):
        print("✅ ¡Mensaje enviado con éxito! Revisa tu Telegram.")
    else:
        print(f"❌ Error al enviar: {result}")


if __name__ == "__main__":
    main()
