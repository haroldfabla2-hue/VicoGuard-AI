import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import pytest
from api import business_profile



def test_business_profile_schema():
    schema = business_profile.QUESTION_SCHEMA
    assert len(schema) >= 5
    sector_q = next(q for q in schema if q["id"] == "sector")
    assert sector_q["required"] is True


def test_visible_questions_branching():
    # Sin data de pagos/salud/pii -> no aparece la pregunta de compliance
    answers_empty = {"sector": "personal", "data": ["none"]}
    qs_empty = business_profile.visible_questions(answers_empty)
    assert not any(q["id"] == "compliance" for q in qs_empty)

    # Con pagos -> aparece la pregunta de compliance
    answers_payments = {"sector": "fintech", "data": ["payments"]}
    qs_payments = business_profile.visible_questions(answers_payments)
    assert any(q["id"] == "compliance" for q in qs_payments)


def test_reweight_findings_high_stakes():
    findings = [
        {"type": "exposed_secret", "category": "EXPOSED_SECRETS", "severity": "HIGH"},
        {"type": "missing_header", "category": "HTTP_HEADERS", "severity": "MEDIUM"},
    ]
    fintech_profile = {
        "sector": "fintech",
        "data": ["payments", "credentials"],
        "stack": ["supabase"]
    }
    adjusted = business_profile.reweight_findings(findings, fintech_profile)
    # Secreto expuesto en fintech con tarjetas sube a CRITICAL
    assert adjusted[0]["severity"] == "CRITICAL"
    assert "Elevado a CRITICAL" in adjusted[0]["severity_reason"]


def test_reweight_findings_benign():
    findings = [
        {"type": "missing_header", "category": "HTTP_HEADERS", "severity": "MEDIUM"},
    ]
    personal_profile = {
        "sector": "personal",
        "data": ["none"],
        "stack": ["static"]
    }
    adjusted = business_profile.reweight_findings(findings, personal_profile)
    # Cabecera faltante en proyecto personal se atenúa a LOW
    assert adjusted[0]["severity"] == "LOW"


def test_heuristic_risk_summary():
    profile = {
        "sector": "health",
        "data": ["health", "pii"],
        "stack": ["custom_api"]
    }
    summary = business_profile.heuristic_risk_summary(profile)
    assert summary["risk_posture"] == "alto"
    assert "health" in summary["crown_jewels"] or "pii" in summary["crown_jewels"]
