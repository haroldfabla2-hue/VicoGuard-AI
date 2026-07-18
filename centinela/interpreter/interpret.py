"""Interpreter -- turns raw ledger entries into human-readable messages.

Two modes:
  - LLM mode (Anthropic API, model ``claude-sonnet-5``): used whenever an
    API key is available, either passed explicitly or via the
    ``ANTHROPIC_API_KEY`` environment variable.
  - Heuristic fallback mode: used when no API key is available anywhere.
    This is the "regla de corte de último recurso" from the project plan --
    it must work with zero external dependencies and zero network calls, so
    the bot is never silent just because credentials aren't configured yet.

Both ``summarize`` and ``explain`` (and ``answer_question``) are safe to
call with no API key set, and this module is safe to import with no
``ANTHROPIC_API_KEY``/``TELEGRAM_BOT_TOKEN`` in the environment -- nothing
here touches the network or raises at import time.
"""

from __future__ import annotations

import os

import anthropic

from centinela.ledger import hash_chain

DEFAULT_LEDGER_PATH = hash_chain.DEFAULT_LEDGER_PATH

# Per project instructions: use claude-sonnet-5 for the interpreter calls.
MODEL = "claude-sonnet-5"

_RECENT_WINDOW = 20
_MAX_MESSAGE_CHARS = 140

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U0001F7E2"}
_SEVERITY_LABEL_ES = {
    "critical": "crítico",
    "high": "alto",
    "medium": "medio",
    "low": "bajo",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _resolve_api_key(api_key: str | None) -> str | None:
    """Prefer an explicitly passed key; fall back to the env var; else None."""
    return api_key or os.environ.get("ANTHROPIC_API_KEY") or None


def _findings(entries: list) -> list:
    return [e for e in entries if e.get("type") == "finding"]


def _decisions(entries: list) -> list:
    return [e for e in entries if e.get("type") in ("allowed", "denied")]


def _severity_rank(finding_entry: dict) -> int:
    severity = finding_entry.get("data", {}).get("severity")
    return _SEVERITY_ORDER.get(severity, len(_SEVERITY_ORDER))


def _most_urgent_finding(findings: list) -> dict | None:
    if not findings:
        return None
    return sorted(findings, key=_severity_rank)[0]


def _severity_counts(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for entry in findings:
        severity = entry.get("data", {}).get("severity", "low")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _truncate(text: str, limit: int = _MAX_MESSAGE_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _format_finding_short(finding_entry: dict) -> str:
    data = finding_entry.get("data", {})
    severity = data.get("severity", "?")
    emoji = _SEVERITY_EMOJI.get(severity, "⚪")
    file_ = data.get("file", "?")
    line = data.get("line", "?")
    message = _truncate(data.get("message", ""))
    return f"{emoji} {severity.upper()} {file_}:{line} - {message}"


def _recent(entries: list, n: int = _RECENT_WINDOW) -> list:
    return entries[-n:] if len(entries) > n else entries


def _entry_to_prompt_line(entry: dict) -> str:
    if entry.get("type") == "finding":
        data = entry.get("data", {})
        return (
            f"[finding #{entry.get('index')}] id={data.get('id')} "
            f"severity={data.get('severity')} source={data.get('source')} "
            f"rule={data.get('rule_id')} file={data.get('file')}:{data.get('line')} "
            f"msg={data.get('message')}"
        )
    data = entry.get("data", {})
    return (
        f"[{entry.get('type')} #{entry.get('index')}] tool={data.get('tool')} "
        f"command={data.get('command')} reason={data.get('reason')}"
    )


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------

def summarize(ledger_path: str = DEFAULT_LEDGER_PATH, api_key: str | None = None) -> str:
    """Build a single Telegram-ready summary message from the ledger.

    Uses the LLM (``claude-sonnet-5``) when an API key is available; falls
    back to a deterministic, no-network heuristic otherwise (or if the LLM
    call fails for any reason -- auth, network, rate limit, etc).
    """
    entries = hash_chain.read_entries(ledger_path)
    resolved_key = _resolve_api_key(api_key)

    if resolved_key:
        try:
            return _llm_summarize(entries, resolved_key)
        except Exception as exc:  # pragma: no cover - network/auth dependent
            fallback = _heuristic_summarize(entries)
            return (
                "⚠️ No se pudo generar el resumen con IA "
                f"({type(exc).__name__}). Usando modo heurístico:\n\n" + fallback
            )

    return _heuristic_summarize(entries)


def _heuristic_summarize(entries: list) -> str:
    findings = _findings(entries)
    decisions = _decisions(entries)

    if not findings and not decisions:
        return (
            "\U0001F41D WASP (modo heurístico, sin IA): el ledger está vacío. "
            "Todavía no hay hallazgos ni decisiones de gobernanza registradas."
        )

    counts = _severity_counts(findings)
    parts = []
    if counts["critical"]:
        parts.append(f"\U0001F534 {counts['critical']} crítico{'s' if counts['critical'] != 1 else ''}")
    if counts["high"]:
        parts.append(f"\U0001F7E0 {counts['high']} alto{'s' if counts['high'] != 1 else ''}")
    if counts["medium"]:
        parts.append(f"\U0001F7E1 {counts['medium']} medio{'s' if counts['medium'] != 1 else ''}")
    if counts["low"]:
        parts.append(f"\U0001F7E2 {counts['low']} bajo{'s' if counts['low'] != 1 else ''}")

    lines = ["\U0001F41D WASP (modo heurístico, sin IA -- regla de corte de último recurso):"]
    lines.append(", ".join(parts) + "." if parts else "No hay hallazgos con severidad reconocida.")

    urgent = _most_urgent_finding(findings)
    if urgent:
        lines.append("El más urgente: " + _format_finding_short(urgent))

    denied = [d for d in decisions if d.get("type") == "denied"]
    if denied:
        plural = "es" if len(denied) != 1 else ""
        lines.append(f"⛔ {len(denied)} acción{plural} bloqueada{plural} por gobernanza.")

    lines.append("Revisá el detalle con /alertas o pedí /explicar <id>.")
    return "\n".join(lines)


def _llm_summarize(entries: list, api_key: str) -> str:
    client = anthropic.Anthropic(api_key=api_key)
    recent = _recent(entries)
    context = (
        "\n".join(_entry_to_prompt_line(e) for e in recent)
        if recent
        else "(ledger vacío, sin hallazgos ni decisiones todavía)"
    )

    system = (
        "Sos el intérprete de WASP, un sistema de seguridad automatizado. "
        "Recibís hallazgos crudos de escaneo estático (Semgrep/Gitleaks) y "
        "decisiones de gobernanza de un agente de IA, y generás UN mensaje "
        "en español pensado para enviarse por Telegram: corto, no un "
        "ensayo. El mensaje debe tener: 2-3 líneas de resumen general, el "
        "top 3 de hallazgos más importantes con archivo y línea, y una "
        "acción recomendada al final. No inventes hallazgos que no estén "
        "en el contexto que te paso."
    )
    user = f"Hallazgos y decisiones recientes del ledger:\n\n{context}\n\nGenerá el mensaje."

    response = client.messages.create(
        model=MODEL,
        max_tokens=600,
        output_config={"effort": "low"},
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    return text or _heuristic_summarize(entries)


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

def _find_finding_by_id(entries: list, finding_id: str) -> dict | None:
    for entry in entries:
        if entry.get("type") == "finding" and entry.get("data", {}).get("id") == finding_id:
            return entry
    return None


def _find_decision_by_index(entries: list, identifier: str) -> dict | None:
    if not identifier.isdigit():
        return None
    idx = int(identifier)
    for entry in entries:
        if entry.get("type") in ("allowed", "denied") and entry.get("index") == idx:
            return entry
    return None


def explain(
    finding_id: str,
    ledger_path: str = DEFAULT_LEDGER_PATH,
    api_key: str | None = None,
) -> str:
    """Explain a single ledger entry for the ``/explicar <id>`` command.

    ``finding_id`` is looked up first as a finding's ``id`` (short hash from
    ``noise_guard.make_finding_id``); if that fails and the identifier is
    numeric, it's looked up as the ledger index of an ``allowed``/``denied``
    governance decision (those entries have no ``id`` field of their own).

    Never raises for a not-found identifier -- returns a clear Spanish error
    message instead, since this is called directly from the Telegram bot.
    """
    entries = hash_chain.read_entries(ledger_path)
    entry = _find_finding_by_id(entries, finding_id) or _find_decision_by_index(entries, finding_id)

    if entry is None:
        return (
            f"No encontré ningún hallazgo con id '{finding_id}' ni ninguna decisión "
            f"de gobernanza con índice '{finding_id}' en el ledger. Los hallazgos se "
            "identifican por su id corto (ver /alertas) y las decisiones de "
            "gobernanza (allowed/denied) por su índice numérico dentro del ledger."
        )

    resolved_key = _resolve_api_key(api_key)
    if resolved_key:
        try:
            return _llm_explain(entry, resolved_key)
        except Exception as exc:  # pragma: no cover - network/auth dependent
            fallback = _heuristic_explain(entry)
            return (
                "⚠️ No se pudo generar la explicación con IA "
                f"({type(exc).__name__}). Usando modo heurístico:\n\n" + fallback
            )

    return _heuristic_explain(entry)


def _heuristic_explain(entry: dict) -> str:
    data = entry.get("data", {})

    if entry.get("type") == "finding":
        severity = data.get("severity", "desconocida")
        label = _SEVERITY_LABEL_ES.get(severity, severity)
        urgency = (
            "requiere atención inmediata"
            if severity in ("critical", "high")
            else "conviene revisarlo cuando se pueda"
        )
        return (
            f"Hallazgo {data.get('id')} (severidad {label}), detectado por "
            f"{data.get('source', '?')} con la regla '{data.get('rule_id', '?')}' "
            f"en {data.get('file', '?')}:{data.get('line', '?')}.\n"
            f"Qué es: {data.get('message', 'sin descripción disponible')}\n"
            f"Por qué importa: la severidad es {label}, así que {urgency}.\n"
            "Qué hacer: revisá el archivo y la línea señalados, corregí según el "
            "mensaje del hallazgo y volvé a correr el escaneo para confirmar que "
            "se resolvió."
        )

    decision = data.get("decision", entry.get("type"))
    blocked = decision in ("deny", "denied")
    decision_es = "bloqueada" if blocked else "permitida"
    next_step = (
        "si el bloqueo fue incorrecto, revisá capability_contract.yaml y "
        "ajustá la regla que lo generó"
        if blocked
        else "no requiere acción, quedó registrada para auditoría"
    )
    return (
        f"Decisión de gobernanza #{entry.get('index')}: la herramienta "
        f"'{data.get('tool', '?')}' intentó ejecutar el comando "
        f"'{data.get('command', '?')}' y fue {decision_es}.\n"
        f"Motivo: {data.get('reason', 'sin motivo registrado')}\n"
        f"Qué hacer: {next_step}."
    )


def _llm_explain(entry: dict, api_key: str) -> str:
    client = anthropic.Anthropic(api_key=api_key)
    context = _entry_to_prompt_line(entry)

    system = (
        "Sos el intérprete de WASP, un sistema de seguridad automatizado. Te "
        "doy UN hallazgo o UNA decisión de gobernanza del ledger y generás "
        "una explicación de 3 a 5 líneas en español: qué es, por qué "
        "importa, y qué hacer. Pensado para un mensaje de Telegram, no un "
        "ensayo."
    )
    user = f"Elemento del ledger a explicar:\n{context}"

    response = client.messages.create(
        model=MODEL,
        max_tokens=400,
        output_config={"effort": "low"},
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(block.text for block in response.content if block.type == "text").strip()
    return text or _heuristic_explain(entry)


# ---------------------------------------------------------------------------
# answer_question -- free-text messages in the Telegram bot
# ---------------------------------------------------------------------------

def answer_question(
    question: str,
    ledger_path: str = DEFAULT_LEDGER_PATH,
    api_key: str | None = None,
) -> str:
    """Answer a free-text question using the full ledger as context.

    Without an API key there is no honest way to answer an open-ended
    question, so this says so explicitly instead of pretending to.
    """
    resolved_key = _resolve_api_key(api_key)
    if not resolved_key:
        return (
            "\U0001F41D Modo sin IA: no puedo responder preguntas libres todavía "
            "(hace falta configurar ANTHROPIC_API_KEY). Puedo responder a los "
            "comandos fijos: /status, /alertas y /explicar <id>."
        )

    entries = hash_chain.read_entries(ledger_path)
    recent = _recent(entries)
    context = "\n".join(_entry_to_prompt_line(e) for e in recent) if recent else "(ledger vacío)"

    try:
        client = anthropic.Anthropic(api_key=resolved_key)
        system = (
            "Sos el intérprete de WASP, un sistema de seguridad automatizado. "
            "Respondé la pregunta del usuario en español, en base al "
            "contexto del ledger que te paso. Sé breve, pensado para un "
            "mensaje de Telegram. Si la pregunta no se puede responder con "
            "ese contexto, decilo en vez de inventar."
        )
        user = f"Contexto del ledger (hallazgos y decisiones recientes):\n{context}\n\nPregunta: {question}"
        response = client.messages.create(
            model=MODEL,
            max_tokens=500,
            output_config={"effort": "low"},
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in response.content if block.type == "text").strip()
        return text or "No pude generar una respuesta para eso."
    except Exception as exc:  # pragma: no cover - network/auth dependent
        return (
            "⚠️ No se pudo consultar la IA "
            f"({type(exc).__name__}). Probá con /status, /alertas o /explicar <id>."
        )


# ---------------------------------------------------------------------------
# list_recent_findings -- backs the /alertas command
# ---------------------------------------------------------------------------

def list_recent_findings(ledger_path: str = DEFAULT_LEDGER_PATH, limit: int = 10) -> list:
    """Return up to ``limit`` most recent findings, newest first, formatted
    as short one-line strings (severity + file:line + short message) -- no
    LLM involved, this is a plain listing for ``/alertas``.
    """
    entries = hash_chain.read_entries(ledger_path)
    findings = _findings(entries)
    recent = findings[-limit:] if len(findings) > limit else findings
    recent = list(reversed(recent))
    return [_format_finding_short(f) for f in recent]
