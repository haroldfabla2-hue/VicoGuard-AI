"""WASP Telegram bot -- delivers the interpreter's output to the user.

Structural requirement: this module must be importable even when
``TELEGRAM_BOT_TOKEN`` is not set in the environment yet. All token access
is lazy -- it only happens inside ``main()``, never at module import time --
so ``python -c "from centinela.telegram_bot import bot"`` never crashes just
because credentials aren't configured.

Commands:
    /status          -> interpret.summarize() (LLM if available, heuristic otherwise)
    /alertas         -> last N findings, plain listing (no LLM)
    /explicar <id>   -> interpret.explain(id)
    (free text)      -> interpret.answer_question(text)

Run with:
    .venv\\Scripts\\python.exe -m centinela.telegram_bot.bot
"""

from __future__ import annotations

import logging
import os

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from centinela.interpreter import interpret

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
# httpx (used internally by python-telegram-bot for every API call) logs the
# full request URL at INFO level, and Telegram's Bot API embeds the token
# directly in the URL path (api.telegram.org/bot<TOKEN>/method) -- at INFO
# level the token gets printed to the console on every single request. Not
# acceptable for a security project's own demo terminal. WARNING still shows
# real errors.
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

_MAX_ALERTAS = 10


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/status -- resumen priorizado del ledger completo."""
    message = interpret.summarize()
    await update.message.reply_text(message)


async def cmd_alertas(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/alertas -- lista los últimos hallazgos sin resumir (sin LLM)."""
    lines = interpret.list_recent_findings(limit=_MAX_ALERTAS)
    if not lines:
        await update.message.reply_text("No hay hallazgos registrados en el ledger todavía.")
        return
    header = f"Últimos {len(lines)} hallazgo(s):"
    await update.message.reply_text(header + "\n\n" + "\n".join(lines))


async def cmd_explicar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/explicar <id> -- explica un hallazgo o una decisión de gobernanza."""
    if not context.args:
        await update.message.reply_text(
            "Uso: /explicar <id>\n"
            "Esperaba el id de un hallazgo (ver /alertas) o el índice numérico "
            "de una decisión de gobernanza, y no recibí ningún argumento."
        )
        return

    finding_id = context.args[0]
    message = interpret.explain(finding_id)
    await update.message.reply_text(message)


async def handle_free_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Cualquier mensaje que no sea un comando se trata como una pregunta."""
    question = update.message.text or ""
    message = interpret.answer_question(question)
    await update.message.reply_text(message)


def build_application(token: str) -> Application:
    """Construct the Application and wire up handlers. Pure -- no I/O beyond
    the Application builder itself, so it's easy to test independent of
    ``run_polling()``.
    """
    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("alertas", cmd_alertas))
    application.add_handler(CommandHandler("explicar", cmd_explicar))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_free_text))
    return application


def main() -> int:
    """Entry point. Checks for TELEGRAM_BOT_TOKEN lazily -- this is the only
    place the token is read -- and prints a clear, non-cryptic error if it's
    missing instead of letting the Application builder raise deep inside
    python-telegram-bot.
    """
    from dotenv import load_dotenv

    load_dotenv()  # loads .env from the project root into os.environ, if present

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print(
            "ERROR: falta la variable de entorno TELEGRAM_BOT_TOKEN.\n"
            "Configála en tu .env (o exportála en el entorno) con el token "
            "que te da @BotFather antes de correr el bot. Ejemplo:\n"
            "  TELEGRAM_BOT_TOKEN=123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11\n"
        )
        return 1

    application = build_application(token)
    logger.info("Iniciando WASP Telegram bot (polling)...")
    application.run_polling()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
