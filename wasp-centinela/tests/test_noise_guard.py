from centinela.guards import noise_guard


def _finding(source, rule_id, file, line, severity, message="msg"):
    return {
        "id": noise_guard.make_finding_id(source, rule_id, file, line),
        "source": source,
        "severity": severity,
        "rule_id": rule_id,
        "file": file,
        "line": line,
        "message": message,
        "raw": {},
    }


def test_make_finding_id_is_stable_and_deterministic():
    id_a = noise_guard.make_finding_id("semgrep", "rule-1", "app.py", 10)
    id_b = noise_guard.make_finding_id("semgrep", "rule-1", "app.py", 10)
    id_c = noise_guard.make_finding_id("semgrep", "rule-1", "app.py", 11)

    assert id_a == id_b
    assert id_a != id_c


def test_deduplicate_removes_exact_duplicates():
    findings = [
        _finding("semgrep", "rule-1", "app.py", 10, "high"),
        _finding("semgrep", "rule-1", "app.py", 10, "high"),  # exact duplicate
        _finding("gitleaks", "generic-api-key", "app.py", 11, "critical"),
    ]

    deduped = noise_guard.deduplicate(findings)

    assert len(deduped) < len(findings)
    assert len(deduped) == 2
    ids = {f["id"] for f in deduped}
    assert len(ids) == len(deduped)


def test_deduplicate_never_increases_count():
    findings = [
        _finding("semgrep", "rule-1", "app.py", 10, "high"),
        _finding("gitleaks", "generic-api-key", "app.py", 11, "critical"),
        _finding("semgrep", "rule-2", "other.py", 5, "low"),
    ]

    deduped = noise_guard.deduplicate(findings)

    assert len(deduped) <= len(findings)


def test_prioritize_orders_critical_before_low():
    findings = [
        _finding("semgrep", "rule-low", "a.py", 1, "low"),
        _finding("semgrep", "rule-critical", "b.py", 2, "critical"),
        _finding("semgrep", "rule-medium", "c.py", 3, "medium"),
        _finding("semgrep", "rule-high", "d.py", 4, "high"),
    ]

    ordered = noise_guard.prioritize(findings)

    severities = [f["severity"] for f in ordered]
    assert severities == ["critical", "high", "medium", "low"]
    assert severities.index("critical") < severities.index("low")
