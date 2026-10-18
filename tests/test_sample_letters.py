"""Tests for the built-in demo sample letters shown on the Verify page."""

from __future__ import annotations

import config
from services.pipeline import run_analysis_from_text

SAMPLES_DIR = config.DATA_DIR / "samples"


def _load(filename: str) -> str:
    return (SAMPLES_DIR / filename).read_text(encoding="utf-8")


def test_sample_files_exist():
    assert (SAMPLES_DIR / "fee_scam_letter.txt").is_file()
    assert (SAMPLES_DIR / "lookalike_letter.txt").is_file()


def test_fee_scam_sample_scores_high_with_threat_match(seeded_db):
    result = run_analysis_from_text(_load("fee_scam_letter.txt"), allow_external=False, save=False)

    assert result.risk_category == "High"
    assert result.score >= 60
    assert result.extracted_facts["company_name"] == "Zenith Global Technologies"
    assert result.module_results["threat"]["status"] == "concerns"
    assert result.score_breakdown["threat"]["awarded"] == 15
    assert result.score_breakdown["payment"]["awarded"] == config.SCORE_CAPS["payment"]


def test_lookalike_sample_scores_high_with_domain_finding(seeded_db):
    result = run_analysis_from_text(_load("lookalike_letter.txt"), allow_external=False, save=False)

    assert result.risk_category == "High"
    assert result.score >= 60
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "COMPANY-LOOKALIKE-DOMAIN" in rule_ids
    assert result.module_results["company"]["status"] == "concerns"


def test_samples_are_labelled_as_fictional():
    for filename in ("fee_scam_letter.txt", "lookalike_letter.txt"):
        text = _load(filename).lower()
        assert "fictional" in text
