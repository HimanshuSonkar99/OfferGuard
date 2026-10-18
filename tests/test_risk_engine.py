import re

import config
from database.models import Finding
from services import risk_engine
from services.pipeline import run_analysis_from_text
from services.risk_engine import build_score_breakdown, classify

SCAM_LETTER = """Subject: Internship Offer Letter - Acme Technologies Pvt Ltd

Congratulations! You have been selected for our Data Analyst internship program.
To confirm your seat, a refundable registration fee of Rs 4,500 must be paid within 24 hours.
This offer expires immediately after the deadline, so act fast and click here now.
You must sign a 2 year bond with a penalty of Rs 200,000 if you leave early.
Contact our HR team at hr@acme-hiring.example for payment details.
"""


def _finding(rule_id, category, points):
    return Finding(rule_id, "letter", category, "high", points, "evidence", "explanation", "high")


def test_classify_bands():
    assert classify(0) == "Low"
    assert classify(29) == "Low"
    assert classify(30) == "Caution"
    assert classify(59) == "Caution"
    assert classify(60) == "High"
    assert classify(100) == "High"


def test_category_caps_are_enforced():
    breakdown = build_score_breakdown([_finding("A", "payment", 20), _finding("B", "payment", 20)])

    assert breakdown["payment"]["awarded"] == config.SCORE_CAPS["payment"]
    assert breakdown["payment"]["raw"] == 40
    assert breakdown["payment"]["capped"] is True
    assert breakdown["payment"]["points_lost_to_cap"] == 40 - config.SCORE_CAPS["payment"]


def test_duplicate_findings_are_counted_once():
    original = _finding("PAY-REGISTRATION-FEE", "payment", 15)
    duplicate = _finding("PAY-REGISTRATION-FEE", "payment", 15)

    assert len(risk_engine._dedupe_findings([original, duplicate])) == 1


def test_total_score_never_exceeds_maximum():
    breakdown = build_score_breakdown(
        [_finding(f"R{index}", category, 50) for index, category in enumerate(config.SCORE_CAPS)]
    )
    total = sum(item["awarded"] for item in breakdown.values())

    assert total == config.MAX_SCORE
    assert total <= 100


def test_scam_letter_alone_is_caution():
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False, save=False)

    assert 30 <= result.score <= 59
    assert result.risk_category == "Caution"
    assert result.summary
    assert result.recommendations


def test_scam_with_lookalike_domain_reaches_high(seeded_db):
    text = (
        "Company name: Infosys Limited\n"
        "You have been selected for the position of Data Analyst Intern.\n"
        "To confirm your seat, a registration fee of Rs 4,500 must be paid within 24 hours.\n"
        "This offer expires immediately, so act fast.\n"
        "You must sign a 2 year bond with a penalty of Rs 200,000 if you leave early.\n"
        "Contact hr@infosys-careers.com for payment details.\n"
    )
    result = run_analysis_from_text(text, allow_external=False, save=False)

    assert result.score >= 60
    assert result.risk_category == "High"
    assert result.module_results["company"]["status"] == "concerns"


def test_analysis_id_format_and_module_shape():
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False, save=False)

    assert re.fullmatch(r"OG-\d{8}-[0-9A-F]{6}", result.analysis_id)

    for key in ("letter", "company", "threat"):
        module = result.module_results[key]
        assert "status" in module
        assert isinstance(module.get("findings"), list)

    assert result.score_breakdown
    assert result.limitations
    assert result.extraction["method"] == "manual-text"


def test_breakdown_finding_ids_only_include_scoring_findings():
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False, save=False)

    for category in result.score_breakdown.values():
        assert all(isinstance(rule_id, str) and rule_id for rule_id in category["finding_ids"])
