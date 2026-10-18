"""Deterministic risk-scoring engine.

The engine combines the three verification modules, caps each category at its
allocated maximum, prevents duplicate scoring of the same evidence and returns a
single, reproducible result that the UI, the database, the downloadable report
and the tests all share.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import config
from database.models import AnalysisResult
from services.company_checker import run_company_check
from services.document_parser import extract_facts
from services.letter_checker import run_letter_check
from services.recommendations import build_recommendations, build_summary
from services.threat_checker import run_threat_check

CATEGORY_LABELS = {
    "payment": "Payment demands",
    "urgency": "Urgency and pressure",
    "bond": "Bond and penalty clauses",
    "recruitment": "Recruitment-process concerns",
    "company": "Company and domain concerns",
    "threat": "Campus threat matches",
}


def classify(score: int) -> str:
    """Map a numeric score to a Low / Caution / High classification."""
    for low, high, label in config.CLASSIFICATION_BANDS:
        if low <= score <= high:
            return label
    return "High" if score > config.CLASSIFICATION_BANDS[-1][1] else "Low"


def new_analysis_id() -> str:
    return "OG-" + datetime.now(UTC).strftime("%Y%m%d") + "-" + uuid.uuid4().hex[:6].upper()


def _dedupe_findings(findings: list) -> list:
    """Keep the first occurrence of any (rule_id, evidence) pair."""
    seen: set = set()
    unique: list = []
    for finding in findings:
        key = (finding.rule_id, " ".join((finding.evidence or "").lower().split()))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def build_score_breakdown(findings: list) -> dict:
    """Cap each category at its allocation and return the per-category detail."""
    breakdown = {}
    for category, cap in config.SCORE_CAPS.items():
        category_findings = [item for item in findings if item.category == category]
        raw = sum(max(0, int(item.points)) for item in category_findings)
        capped = min(raw, cap)
        breakdown[category] = {
            "label": CATEGORY_LABELS.get(category, category.title()),
            "awarded": capped,
            "raw": raw,
            "cap": cap,
            "capped": raw > cap,
            "points_lost_to_cap": max(0, raw - cap),
            "finding_ids": [item.rule_id for item in category_findings if item.points > 0],
        }
    return breakdown


def _module_payload(module_result: dict, findings: list) -> dict:
    """Serialise a module result for storage, including its findings as plain dicts."""
    return {
        "name": module_result.get("name", module_result.get("module", "")),
        "status": module_result.get("status", "unknown"),
        "points": int(module_result.get("points", 0)),
        "checks": module_result.get("checks", []),
        "report_count": module_result.get("report_count"),
        "corroborated_count": module_result.get("corroborated_count"),
        "unverified_count": module_result.get("unverified_count"),
        "reference": module_result.get("reference"),
        "registration": module_result.get("registration"),
        "matches": module_result.get("matches", {}),
        "findings": [item.to_dict() for item in findings if item.module == module_result.get("module")],
    }


def analyze(
    text: str,
    extraction: dict | None = None,
    facts_override: dict | None = None,
    allow_external: bool = True,
    db_path=None,
    source_filename: str | None = None,
) -> object:
    """Run the full analysis pipeline and return a fully populated AnalysisResult."""
    text = text or ""
    extraction = extraction or {}

    if extraction.get("facts"):
        facts = dict(extraction["facts"])
    else:
        facts = extract_facts(text)
    for key, value in (facts_override or {}).items():
        if value:
            facts[key] = value

    company_name = facts.get("company_name") or ""
    sender_email = facts.get("sender_email") or ""
    sender_domain = facts.get("sender_domain") or ""

    letter_result = run_letter_check(text)
    company_result = run_company_check(
        company_name=company_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        allow_external=allow_external,
        db_path=db_path,
    )
    threat_result = run_threat_check(company_name, sender_domain or "", db_path=db_path)

    findings = _dedupe_findings(
        list(letter_result["findings"]) + list(company_result["findings"]) + list(threat_result["findings"])
    )
    breakdown = build_score_breakdown(findings)
    score = max(0, min(100, sum(item["awarded"] for item in breakdown.values())))
    risk_category = classify(score)

    module_results = {
        "letter": _module_payload(module_result=letter_result, findings=findings),
        "company": _module_payload(module_result=company_result, findings=findings),
        "threat": _module_payload(module_result=threat_result, findings=findings),
    }

    summary = build_summary(score, risk_category, findings, breakdown, module_results)
    recommendations = build_recommendations(score, risk_category, findings, breakdown, module_results)

    created_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    extraction_info = {
        "method": (extraction or {}).get("method", "manual-text" if text else "none"),
        "success": bool((extraction or {}).get("success", bool(text))),
        "warnings": list((extraction or {}).get("warnings", [])),
        "page_count": (extraction or {}).get("page_count", 0),
        "text_length": len(text or ""),
    }

    return AnalysisResult(
        analysis_id=new_analysis_id(),
        created_at=created_at,
        score=score,
        risk_category=risk_category,
        summary=summary,
        extracted_facts=facts,
        findings=findings,
        module_results=module_results,
        score_breakdown=breakdown,
        recommendations=recommendations,
        limitations=list(config.LIMITATIONS),
        extraction=extraction_info,
        source_filename=source_filename or (extraction or {}).get("source_filename"),
    )
