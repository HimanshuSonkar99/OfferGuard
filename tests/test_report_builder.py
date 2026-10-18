from services import report_builder
from services.pipeline import run_analysis_from_text

SCAM_LETTER = (
    "Company name: Acme Technologies Pvt Ltd\n"
    "You have been selected for the position of Data Analyst Intern.\n"
    "A registration fee of Rs 4,500 must be paid within 24 hours to confirm your seat.\n"
    "Contact hr@acme-hiring.example for payment details.\n"
)


def _analysis():
    return run_analysis_from_text(SCAM_LETTER, allow_external=False, save=False)


def test_html_report_contains_key_facts():
    analysis = _analysis()
    html = report_builder.build_report_html(analysis)

    assert analysis.analysis_id in html
    assert str(analysis.score) in html
    assert analysis.risk_category in html
    assert "OfferGuard" in html


def test_html_report_escapes_untrusted_evidence():
    analysis = _analysis()
    analysis.findings[0].evidence = "<script>alert('xss')</script>"

    html = report_builder.build_report_html(analysis)

    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_text_report_is_plain_text():
    analysis = _analysis()
    text = report_builder.build_report_text(analysis)

    assert analysis.analysis_id in text
    assert "Risk score" in text
    assert "<html" not in text.lower()


def test_report_filename_uses_analysis_id_and_extension():
    analysis = _analysis()

    assert report_builder.report_filename(analysis, "html").endswith(".html")
    assert report_builder.report_filename(analysis, "txt").endswith(".txt")
    assert analysis.analysis_id in report_builder.report_filename(analysis)
