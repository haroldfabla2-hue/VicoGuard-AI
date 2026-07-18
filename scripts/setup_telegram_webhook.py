"""
VicoGuard AI — Configurador de Webhook de Telegram
==================================================
Registra (o inspecciona / borra) el webhook del bot para que los botones inline
"Aplicar Parche / Ignorar / Ver Detalles" lleguen a la API en vivo durante la demo.

Requiere `TELEGRAM_BOT_TOKEN` real en `.env` (raíz del proyecto).
NUNCA imprime el token.

Uso típico en la demo (con un túnel público, ej. ngrok):

    1. Levanta la API:      cd src && uvicorn api.main:app --port 8000
    2. Abre un túnel:       ngrok http 8000        (copia la URL https://XXXX.ngrok-free.app)
    3. Registra el webhook: python scripts/setup_telegram_webhook.py set https://XXXX.ngrok-free.app
    4. Verifica:            python scripts/setup_telegram_webhook.py info
    5. (limpieza)           python scripts/setup_telegram_webhook.py delete

También puedes fijar la URL pública con la env var PUBLIC_BASE_URL en vez de pasarla como arg.
"""
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

WEBHOOK_PATH = "/api/v1/telegram/webhook"


def _token() -> str:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token or token.startswith("123456"):
        print("[!] TELEGRAM_BOT_TOKEN no configurado o es placeholder. "
              "Pon el token real en .env antes de registrar el webhook.")
        sys.exit(1)
    return token


def _api(token: str, method: str) -> str:
    return f"https://api.telegram.org/bot{token}/{method}"


def cmd_set(public_base: str):
    token = _token()
    public_base = (public_base or os.getenv("PUBLIC_BASE_URL", "")).rstrip("/")
    if not public_base:
        print("[!] Falta la URL pública. Ej: python scripts/setup_telegram_webhook.py set https://XXXX.ngrok-free.app")
        sys.exit(1)
    webhook_url = f"{public_base}{WEBHOOK_PATH}"
    resp = requests.post(
        _api(token, "setWebhook"),
        json={"url": webhook_url, "allowed_updates": ["callback_query", "message"]},
        timeout=15,
    ).json()
    if resp.get("ok"):
        print(f"[OK] Webhook registrado -> {webhook_url}")
    else:
        print(f"[!] Error al registrar webhook: {resp.get('description')}")
    return resp


def cmd_info():
    token = _token()
    resp = requests.get(_api(token, "getWebhookInfo"), timeout=15).json()
    info = resp.get("result", {})
    print("[i] Webhook actual:")
    print(f"    url:                 {info.get('url') or '(ninguno)'}")
    print(f"    pending_update_count:{info.get('pending_update_count')}")
    if info.get("last_error_message"):
        print(f"    last_error:          {info.get('last_error_message')}")
    return resp


def cmd_delete():
    token = _token()
    resp = requests.post(
        _api(token, "deleteWebhook"), json={"drop_pending_updates": True}, timeout=15
    ).json()
    print("[OK] Webhook eliminado" if resp.get("ok") else f"[!] Error: {resp.get('description')}")
    return resp


def main():
    args = sys.argv[1:]
    action = args[0] if args else "info"
    if action == "set":
        cmd_set(args[1] if len(args) > 1 else "")
    elif action == "info":
        cmd_info()
    elif action == "delete":
        cmd_delete()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
