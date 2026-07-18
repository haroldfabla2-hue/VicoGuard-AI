"""Proactive Telegram notifications for the orchestrator.

Unlike centinela/telegram_bot/bot.py (which is reactive -- it only replies
when someone messages it, via long polling), this module needs to PUSH
messages on its own initiative: when an analysis finishes, or when Cronos
detects something new. Telegram bots cannot open a polling loop and also
push arbitrary messages from another process at the same time, so instead
of reusing the bot, this talks directly to the public Bot API with a plain
HTTP POST to sendMessage.

Credential handling: TELEGRAM_BOT_TOKEN is loaded lazily inside
send_message() (never at import time, so importing this module has no
side effects) and is never logged or printed. The bot.py module already
hit a real incident where httpx logged the full request URL --
api.telegram.org/bot<TOKEN>/sendMessage -- at INFO level, leaking the
token to the console. This module never prints the request URL; any error
logging here only includes the status code or exception, never the URL
or the token itself.
"""

from __future__ import annotations

import logging
import os

import httpx
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

_TELEGRAM_API_BASE = "https://api.telegram.org"


def send_message(text: str, chat_id: str | None = None, token: str | None = None) -> bool:
    """Push a message to Telegram via a direct Bot API call.

    Returns True on success, False on any failure (missing credentials,
    network error, non-ok response). Never raises -- this is meant to be
    called from the orchestrator without breaking its flow just because
    Telegram isn't configured yet.
    """
    load_dotenv()

    token = token or os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print(
            "No se puede enviar la notificación de Telegram: falta "
            "TELEGRAM_BOT_TOKEN. Configuralo en el archivo .env del proyecto."
        )
        return False

    chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
    if not chat_id:
        print(
            "No se puede enviar la notificación de Telegram: falta "
            "TELEGRAM_CHAT_ID. Un bot no puede iniciar una conversación con "
            "alguien que nunca le escribió -- el dueño del bot tiene que "
            "mandarle al menos un mensaje primero, y luego guardar ese "
            "chat_id en .env como TELEGRAM_CHAT_ID."
        )
        return False

    url = f"{_TELEGRAM_API_BASE}/bot{token}/sendMessage"

    try:
        response = httpx.post(url, json={"chat_id": chat_id, "text": text}, timeout=15)
    except httpx.HTTPError as exc:
        logger.error("Error enviando a Telegram: %s", type(exc).__name__)
        return False

    if response.status_code != 200:
        logger.error("Error enviando a Telegram: status %s", response.status_code)
        return False

    try:
        payload = response.json()
    except ValueError:
        logger.error("Error enviando a Telegram: respuesta no es JSON válido")
        return False

    if not payload.get("ok"):
        logger.error("Error enviando a Telegram: la API respondió ok=False")
        return False

    return True
