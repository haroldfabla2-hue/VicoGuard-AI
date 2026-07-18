"""Markdown report generator for the unified WASP + VicoGuard-AI run.

Takes the ``run_summary`` dict produced by
``centinela.orchestrator.unify.run_unified`` and renders a single Markdown
report combining: the LLM/heuristic summary from
``centinela.interpreter.interpret.summarize``, the consent record, DAST
(VicoGuard Hub) and SAST (WASP Centinela) findings, the attack simulation
steps, any errors collected during the run, and the hash-chain ledger
integrity check for the entries produced by this run.

Defensive by design: every field read from ``run_summary`` (and from each
finding/attack-step dict) goes through ``.get()`` with a fallback, so a
missing or unexpected field degrades to a "?" placeholder cell in a table
instead of aborting report generation with a traceback. This module never
raises for malformed input -- a partial report is always better than none,
given the report may be the only record of a run.
"""

from __future__ import annotations

import os

from centinela.interpreter import interpret
from centinela.ledger import hash_chain

DEFAULT_LEDGER_PATH = hash_chain.DEFAULT_LEDGER_PATH
DEFAULT_REPORTS_DIR = "centinela/data/reports"


def _cell(value, placeholder: str = "?") -> str:
    """Render a table cell value, falling back to a placeholder for
    missing/empty values. Pipe characters are escaped so a finding message
    containing '|' can't corrupt the Markdown table structure.
    """
    if value is None or value == "":
        return placeholder
    return str(value).replace("|", "\\|").replace("\n", " ")


def _findings_table(findings: list, include_file_line: bool = False) -> str:
    if not findings:
        return "_Sin hallazgos._"

    if include_file_line:
        header = "| Severidad | Categoría/Regla | Archivo:Línea | Mensaje |\n"
        header += "| --- | --- | --- | --- |\n"
    else:
        header = "| Severidad | Categoría/Regla | Mensaje |\n"
        header += "| --- | --- | --- |\n"

    rows = []
    for finding in findings:
        if not isinstance(finding, dict):
            finding = {}
        severity = _cell(finding.get("severity"))
        rule_id = _cell(finding.get("rule_id"))
        message = _cell(finding.get("message"))
        if include_file_line:
            file_ = finding.get("file")
            line = finding.get("line")
            file_line = _cell(f"{file_}:{line}" if file_ or line else None)
            rows.append(f"| {severity} | {rule_id} | {file_line} | {message} |")
        else:
            rows.append(f"| {severity} | {rule_id} | {message} |")

    return header + "\n".join(rows)


def _attack_table(steps: list) -> str:
    if not steps:
        return "_Sin pasos registrados._"

    header = "| Vector | Éxito | Evidencia |\n| --- | --- | --- |\n"
    rows = []
    for step in steps:
        if not isinstance(step, dict):
            step = {}
        vector = _cell(step.get("vector"))
        success = step.get("success")
        success_label = "Sí" if success is True else ("No" if success is False else "?")
        evidence = _cell(step.get("evidence"))
        rows.append(f"| {vector} | {success_label} | {evidence} |")

    return header + "\n".join(rows)


def _consent_section(consent: dict | None) -> str:
    if not consent:
        consent = {}
    url = _cell(consent.get("url"), "(ninguna)")
    concern = _cell(consent.get("concern"))
    confirmed = "Sí" if consent.get("confirmed") else "No"
    return (
        f"- URL analizada: {url}\n"
        f"- Preocupación indicada: {concern}\n"
        f"- Autorizado: {confirmed}"
    )


def _errors_section(errors: list) -> str:
    if not errors:
        return "Ninguno"
    return "\n".join(f"- {_cell(e)}" for e in errors)


def _last_hash(ledger_path: str) -> str:
    entries = hash_chain.read_entries(ledger_path=ledger_path)
    if not entries:
        return "(ledger vacío)"
    return entries[-1].get("hash", "(sin hash)")


def build_report(
    run_summary: dict,
    ledger_path: str = DEFAULT_LEDGER_PATH,
    api_key: str | None = None,
    reports_dir: str = DEFAULT_REPORTS_DIR,
) -> str:
    """Generate the run's Markdown report and save it to disk.

    Writes ``<reports_dir>/<run_id>.md`` (creating ``reports_dir`` if it
    doesn't exist) and returns the path to the generated file.
    """
    run_summary = run_summary or {}
    run_id = run_summary.get("run_id", "unknown-run")
    started_at = run_summary.get("started_at", "?")
    finished_at = run_summary.get("finished_at", "?")

    summary_text = interpret.summarize(ledger_path=ledger_path, api_key=api_key)

    consent = run_summary.get("consent")

    dast = run_summary.get("dast")
    if dast is None:
        dast_section = (
            "No se corrió (sin consentimiento o VicoGuard no disponible)"
        )
        dast_count = 0
    else:
        dast_findings = dast.get("findings", []) or []
        dast_count = dast.get("count", len(dast_findings))
        dast_section = _findings_table(dast_findings, include_file_line=False)

    sast = run_summary.get("sast")
    if sast is None:
        sast_section = "No se corrió (sin consentimiento o VicoGuard no disponible)"
        sast_count = 0
    else:
        sast_findings = sast.get("findings", []) or []
        sast_count = sast.get("count", len(sast_findings))
        sast_section = _findings_table(sast_findings, include_file_line=True)

    attack = run_summary.get("attack")
    if attack is None:
        attack_section = "No se ejecutó"
        attack_count = 0
    else:
        attack_steps = attack.get("steps", []) or []
        attack_count = attack.get("count", len(attack_steps))
        attack_section = _attack_table(attack_steps)

    errors_section = _errors_section(run_summary.get("errors", []))

    chain_ok = hash_chain.verify_chain(ledger_path=ledger_path)
    ledger_start = run_summary.get("ledger_start_index", "?")
    ledger_end = run_summary.get("ledger_end_index", "?")
    last_hash = _last_hash(ledger_path)

    report = f"""# Informe WASP + VicoGuard Hub — Run {run_id}

**Inicio:** {started_at}  **Fin:** {finished_at}

## Resumen

{summary_text}

## Consentimiento

{_consent_section(consent)}

## Hallazgos DAST (VicoGuard Hub) — {dast_count} encontrados
{dast_section}

## Hallazgos SAST (WASP Centinela) — {sast_count} encontrados
{sast_section}

## Simulación de ataque — {attack_count} pasos
{attack_section}

## Errores durante la corrida
{errors_section}

## Integridad del registro

- Cadena verificada: {chain_ok}
- Rango de índices de esta corrida: {ledger_start} a {ledger_end}
- Hash de la última entrada del ledger: {last_hash}

*Este informe corresponde exactamente al rango de entradas verificado arriba -- cualquier modificación posterior a esas entradas rompería la cadena de hashes.*
"""

    os.makedirs(reports_dir, exist_ok=True)
    report_path = os.path.join(reports_dir, f"{run_id}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    return report_path
