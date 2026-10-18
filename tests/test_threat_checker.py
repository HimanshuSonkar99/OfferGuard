from database import repository
from services.threat_checker import run_threat_check


def _rule_ids(result):
    return {finding.rule_id for finding in result["findings"]}


def test_no_matching_reports_is_clear(seeded_db):
    result = run_threat_check("Nonexistent Company", "nonexistent.example")

    assert result["status"] == "clear"
    assert result["points"] == 0
    assert "THREAT-NO-REPORTS" in _rule_ids(result)


def test_corroborated_domain_match_awards_full_weight(seeded_db):
    result = run_threat_check("Zenith Global Technologies", "zenithglobaltechnologies.example")

    assert result["status"] == "concerns"
    assert result["points"] == 15
    assert "THREAT-DOMAIN-CORROBORATED" in _rule_ids(result)


def test_unverified_domain_match_awards_low_weight(seeded_db):
    result = run_threat_check("CloudPeak Analytics", "cloudpeakanalytics.example")

    assert result["status"] == "concerns"
    assert result["points"] == 6
    assert "THREAT-DOMAIN-UNVERIFIED" in _rule_ids(result)


def test_rejected_reports_add_nothing(seeded_db):
    result = run_threat_check("TrustedSteps Technologies", "trustedstepstechnologies.example")

    assert result["points"] == 0
    assert "THREAT-REJECTED-ONLY" in _rule_ids(result)
    assert result["status"] == "info"


def test_company_name_only_match_is_weak(seeded_db):
    repository.add_report(
        {
            "company_name": "Company Only Match",
            "sender_domain": "",
            "category": "Other",
            "description": "A student reported a suspicious offer with no domain recorded here.",
            "status": "under_review",
        }
    )

    result = run_threat_check("Company Only Match", "")

    assert result["points"] == 4
    assert "THREAT-COMPANY-NAME-MATCH" in _rule_ids(result)


def test_matches_override_does_not_touch_the_database():
    override = {
        "domain": [
            {
                "company_name": "Override Co",
                "sender_domain": "override.example",
                "category": "Fee fraud",
                "status": "corroborated",
                "incident_date": "2026-01-01",
                "is_demo": False,
            }
        ],
        "company": [],
    }

    result = run_threat_check("Override Co", "override.example", matches_override=override)

    assert result["points"] == 15
    assert result["report_count"] == 1
