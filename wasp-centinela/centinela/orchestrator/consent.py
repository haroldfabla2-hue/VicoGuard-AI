"""Informed-consent gate before scanning a user-supplied URL.

The system scans real, third-party URLs, not local/owned assets. Before any
scan can run, the operator must state what concerns them and explicitly
confirm they own (or are authorized to test) the target. Both the consent
and any refusal are appended to the tamper-evident hash-chain ledger, so
there is always an auditable record of who authorized what.
"""

from datetime import datetime, timezone

from centinela.ledger import hash_chain

CONCERN_OPTIONS = [
    "Fuga de datos",
    "Disponibilidad del servicio",
    "Cumplimiento normativo",
    "No estoy seguro",
]

_AFFIRMATIVE_ANSWERS = {"s", "si", "sí"}


def _ask_concern_interactively() -> str:
    print("¿Qué te preocupa de este análisis?")
    for i, option in enumerate(CONCERN_OPTIONS, start=1):
        print(f"  {i}. {option}")

    choice = input("Elegí una opción [1-4]: ").strip()

    try:
        index = int(choice) - 1
        if 0 <= index < len(CONCERN_OPTIONS):
            return CONCERN_OPTIONS[index]
    except ValueError:
        pass

    # Anything that doesn't map to a listed option is kept as free text
    # rather than silently discarded.
    return choice


def _ask_confirmation_interactively(url: str) -> bool:
    answer = input(f"¿Confirmás que sos dueño/a de {url} y autorizás este análisis? [s/N]: ")
    return answer.strip().lower() in _AFFIRMATIVE_ANSWERS


def ask_consent(
    url: str,
    concern: str | None = None,
    confirmed: bool = False,
    interactive: bool = True,
    ledger_path: str = "centinela/data/ledger.jsonl",
) -> dict:
    """Request (or record) informed consent to scan ``url``.

    In interactive mode this prompts the operator via the console for the
    concern and the explicit ownership/authorization confirmation. In
    non-interactive mode (scripts/tests) it uses the ``concern``/``confirmed``
    arguments as-is.

    Every call appends a "consent" entry to the hash-chain ledger, whether
    consent was granted or refused, so the decision is always auditable.
    """
    if interactive:
        concern = _ask_concern_interactively()
        confirmed = _ask_confirmation_interactively(url)
    else:
        if confirmed and concern is None:
            concern = "no especificado"

    ts = datetime.now(timezone.utc).isoformat()

    hash_chain.append(
        "consent",
        {"url": url, "concern": concern, "confirmed": confirmed, "ts": ts},
        ledger_path=ledger_path,
    )

    return {"url": url, "concern": concern, "confirmed": confirmed, "ts": ts}
