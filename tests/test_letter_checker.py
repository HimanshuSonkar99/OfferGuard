from services.letter_checker import run_letter_check

SCAM_LETTER = """Subject: Internship Offer Letter - Acme Technologies Pvt Ltd

Congratulations! You have been selected for our Data Analyst internship program.
To confirm your seat, a refundable registration fee of Rs 4,500 must be paid within 24 hours.
This offer expires immediately after the deadline, so act fast and click here now.
You must sign a 2 year bond with a penalty of Rs 200,000 if you leave early.
Contact our HR team at hr@acme-hiring.example for payment details.
"""

LEGIT_LETTER = """Subject: Internship Offer Letter - Infosys Limited

Dear Candidate, we are pleased to offer you the position of Software Engineer Intern.
Your internship is unpaid and lasts eight weeks, with no bond or service commitment.
The reporting date is 1 July 2026 at our Bengaluru campus. Please confirm your
acceptance through the placement cell. No registration fee is required at any stage.
"""


def _rule_ids(result):
    return {finding.rule_id for finding in result["findings"]}


def test_scam_letter_produces_concerns_and_expected_rules():
    result = run_letter_check(SCAM_LETTER)

    assert result["status"] == "concerns"
    assert result["points"] > 0
    ids = _rule_ids(result)
    assert "PAY-REGISTRATION-FEE" in ids
    assert "PAY-CONFIRM-SEAT" in ids
    assert "URG-HOURS-DEADLINE" in ids
    assert "BOND-LONG-PERIOD" in ids
    assert "BOND-PENALTY-AMOUNT" in ids


def test_negation_suppresses_fee_and_deposit_findings():
    text = (
        "This is a legitimate offer. No registration fee is required at any stage "
        "and no security deposit must be paid. Please confirm your acceptance."
    )
    result = run_letter_check(text)

    assert result["status"] == "clear"
    assert all(finding.points == 0 for finding in result["findings"])


def test_legitimate_letter_is_not_flagged():
    result = run_letter_check(LEGIT_LETTER)

    assert result["status"] == "clear"
    assert result["points"] == 0
    assert all(finding.points == 0 for finding in result["findings"])


def test_empty_text_is_clear_with_no_points():
    result = run_letter_check("")

    assert result["points"] == 0
    assert result["status"] == "clear"


def test_every_finding_has_evidence_and_explanation():
    result = run_letter_check(SCAM_LETTER)
    for finding in result["findings"]:
        assert finding.rule_id
        assert finding.explanation
        if finding.points > 0:
            assert finding.evidence
