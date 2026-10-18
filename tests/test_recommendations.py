from services.pipeline import run_analysis_from_text

SCAM_LETTER = (
    "Company name: Acme Technologies Pvt Ltd\n"
    "You have been selected for the position of Data Analyst Intern.\n"
    "A registration fee of Rs 4,500 must be paid within 24 hours to confirm your seat.\n"
    "Contact hr@acme-hiring.example for payment details.\n"
)


def test_summary_states_it_is_not_a_probability():
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False, save=False)

    assert "not a probability" in result.summary
    assert str(result.score) in result.summary


def test_payment_findings_produce_actionable_recommendations():
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False, save=False)
    joined = " ".join(result.recommendations)

    assert "Do not pay" in joined
    assert "cybercrime.gov.in" in joined
    assert "1930" in joined


def test_clean_offer_still_advises_independent_verification():
    clean = (
        "Dear Candidate, we are pleased to offer you an unpaid summer internship. "
        "Your mentor will share the schedule. Contact your placement coordinator with questions."
    )
    result = run_analysis_from_text(clean, allow_external=False, save=False)
    joined = " ".join(result.recommendations)

    assert result.score == 0
    assert "independently" in joined.lower()
