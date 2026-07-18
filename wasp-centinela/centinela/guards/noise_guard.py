"""Deduplicate and prioritize normalized security findings.

Takes findings already normalized to a common schema (from Semgrep,
Gitleaks, etc.) and reduces noise before handing them to the interpreter:
duplicate findings are collapsed, and the remaining ones are ordered by
severity so the most critical issues surface first.
"""

import hashlib

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def make_finding_id(source: str, rule_id: str, file: str, line: int) -> str:
    """Build a stable fingerprint for a finding from its identifying fields."""
    raw = f"{source}:{rule_id}:{file}:{line}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def deduplicate(findings: list) -> list:
    """Collapse findings that share the same ``id`` into a single entry.

    The first occurrence of each ``id`` is kept; later duplicates are
    dropped. The result has at most as many elements as the input.
    """
    seen = set()
    result = []
    for finding in findings:
        finding_id = finding.get("id")
        if finding_id in seen:
            continue
        seen.add(finding_id)
        result.append(finding)
    return result


def prioritize(findings: list) -> list:
    """Return findings sorted by severity, most severe first.

    Order: critical > high > medium > low. Unknown severities sort last.
    """
    return sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity"), len(_SEVERITY_ORDER)),
    )
