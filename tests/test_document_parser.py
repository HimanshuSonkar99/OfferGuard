import pytest

import config
from services import document_parser
from services.document_parser import DocumentError

OFFER_TEXT = (
    "Subject: Internship Offer - Acme Technologies Pvt Ltd\n"
    "Company name: Acme Technologies Pvt Ltd\n"
    "You have been selected for the position of Data Analyst Intern.\n"
    "A registration fee of Rs 4,500 must be paid within 24 hours to confirm your seat.\n"
    "Contact hr@acme-hiring.example for payment details.\n"
)


def test_validate_upload_rejects_bad_input():
    with pytest.raises(DocumentError):
        document_parser.validate_upload("offer.txt", b"some bytes")
    with pytest.raises(DocumentError):
        document_parser.validate_upload("offer.pdf", b"")


def test_validate_upload_rejects_oversized_file():
    oversized = b"x" * (config.MAX_FILE_SIZE_BYTES + 1)
    with pytest.raises(DocumentError):
        document_parser.validate_upload("offer.pdf", oversized)


def test_validate_upload_accepts_supported_extensions():
    assert document_parser.validate_upload("offer.PDF", b"data") == ".pdf"
    assert document_parser.validate_upload("scan.png", b"data") == ".png"


def test_parse_manual_text_extracts_facts():
    result = document_parser.parse_manual_text(OFFER_TEXT)

    assert result.success is True
    assert result.method == "manual-text"
    assert "Acme Technologies" in (result.facts["company_name"] or "")
    assert result.facts["sender_email"] == "hr@acme-hiring.example"
    assert result.facts["sender_domain"] == "acme-hiring.example"
    assert result.facts["payment_amount"] == 4500
    assert "registration" in (result.facts["payment_purpose"] or "").lower()


def test_parse_manual_text_flags_empty_input():
    result = document_parser.parse_manual_text("   ")

    assert result.success is False
    assert result.text == ""
    assert result.warnings


def test_extract_pdf_reads_selectable_text():
    pymupdf = pytest.importorskip("pymupdf", reason="PyMuPDF is required for PDF extraction")

    document = pymupdf.open()
    page = document.new_page()
    page.insert_text((72, 72), "Offer letter from Acme Technologies Pvt Ltd.", fontsize=12)
    page.insert_text((72, 96), "A registration fee of Rs 4,500 is required.", fontsize=12)
    page.insert_text((72, 120), "Contact hr@acme-hiring.example for details.", fontsize=12)
    data = document.tobytes()
    document.close()

    result = document_parser.parse_document("offer.pdf", data)

    assert result.success is True
    assert result.method == "pdf-text"
    assert "acme" in result.text.lower()
    assert result.facts["sender_domain"] == "acme-hiring.example"


def test_image_without_ocr_degrades_gracefully():
    pytest.importorskip("PIL", reason="Pillow is required for image handling")

    import io

    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (10, 10), "white").save(buffer, format="PNG")

    result = document_parser.parse_document("scan.png", buffer.getvalue())

    # OCR is unavailable on this machine, so extraction must fail with a warning,
    # never raise, and never pretend the document was read.
    assert result.success is False
    assert result.warnings
    assert result.text == ""


def test_corrupt_image_does_not_raise():
    result = document_parser.parse_document("scan.png", b"not really an image")

    assert result.success is False
    assert result.warnings
