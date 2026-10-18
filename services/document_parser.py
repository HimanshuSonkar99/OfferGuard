"""Real document extraction for OfferGuard.

Handles selectable-text PDFs (PyMuPDF), scanned PDFs and images (OCR through
pytesseract when the Tesseract engine is available) and structured fact
extraction. Everything is processed in memory: original documents are never
written to disk.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import config
from services import ocr_service
from services.normalizer import extract_emails, extract_urls, registered_domain

try:  # PyMuPDF exposes both module names depending on the version
    import pymupdf  # type: ignore
except ImportError:  # pragma: no cover
    try:
        import fitz as pymupdf  # type: ignore
    except ImportError:
        pymupdf = None  # type: ignore

MIN_PDF_TEXT_CHARS = 40
OCR_PAGE_LIMIT = 3

AMOUNT_PATTERNS = [
    re.compile(r"(?:₹|rs\.?|inr)\s*([0-9][0-9,]*(?:\.\d{1,2})?)", re.IGNORECASE),
    re.compile(r"([0-9][0-9,]{2,})\s*/-"),
    re.compile(r"([0-9][0-9,]{2,})\s*(?:rupees|inr)\b", re.IGNORECASE),
]

PURPOSE_KEYWORDS = {
    "laptop deposit": ["refundable laptop", "laptop deposit", "laptop charges", "device deposit"],
    "training fee": ["training fee", "training charges", "training cost", "certification fee"],
    "registration fee": ["registration fee", "registration charge", "enrolment fee", "enrollment fee", "joining fee"],
    "document verification fee": ["document verification", "verification fee", "verification charge", "background verification"],
    "processing fee": ["processing fee", "processing charge", "administrative fee", "administration fee"],
    "security deposit": ["security deposit", "refundable deposit", "caution deposit"],
    "other fee": ["fee", "charges", "deposit", "amount payable"],
}

ROLE_PATTERNS = [
    re.compile(r"(?:position|post|designation|role|job title)\s*[:\-]\s*([A-Za-z][A-Za-z0-9 /&(),.\-]{2,60})", re.IGNORECASE),
    re.compile(r"(?:offer for the (?:post|position) of|hired as|selected as|internship as)\s+([A-Za-z][A-Za-z0-9 /&(),.\-]{2,60})", re.IGNORECASE),
    re.compile(r"\b((?:software|data|business|marketing|hr|human resource|mechanical|civil|electrical|content|graphic|cyber|cloud|devops|qa|test|web|android)\s+[A-Za-z]+(?:\s+intern(?:ship)?)?)\b", re.IGNORECASE),
]

COMPANY_PATTERNS = [
    re.compile(r"company name\s*[:\-]\s*([A-Za-z0-9][A-Za-z0-9&.,'\- ]{2,70})", re.IGNORECASE),
    re.compile(r"(?:organisation|organization|firm|employer)\s*[:\-]\s*([A-Za-z0-9][A-Za-z0-9&.,'\- ]{2,70})", re.IGNORECASE),
    re.compile(r"\b([A-Z][A-Za-z0-9&.'\-]*(?:\s+[A-Z][A-Za-z0-9&.'\-]*){0,4}\s+(?:Technologies|Technology|Solutions|Services|Consulting|Consultancy|Systems|Labs|Software|Infotech|Enterprises|Industries|Corporation|Limited|Ltd\.?|LLP))\b"),
]

DEADLINE_PATTERNS = [
    re.compile(r"within\s+(\d{1,3})\s*(hours?|hrs?|days?|working days?)", re.IGNORECASE),
    re.compile(r"(?:on or before|before|by|latest by)\s+([0-9]{1,2}[/\-][0-9]{1,2}[/\-][0-9]{2,4})", re.IGNORECASE),
    re.compile(r"(?:on or before|before|by|latest by)\s+(\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9},?\s*\d{0,4})", re.IGNORECASE),
    re.compile(r"(?:offer\s+)?(?:expires|valid till|valid until)\s*[:\-]?\s*([0-9A-Za-z ,/\-]{3,30})", re.IGNORECASE),
]

BOND_DURATION_PATTERNS = [
    re.compile(r"bond(?:\s+period)?\s*(?:of|for)?\s*(\d{1,2})\s*(months?|years?)", re.IGNORECASE),
    re.compile(r"(?:service agreement|employment bond|training bond)\s*(?:of|for)?\s*(\d{1,2})\s*(months?|years?)", re.IGNORECASE),
    re.compile(r"(\d{1,2})\s*(?:months?|years?)\s*(?:service\s+)?bond", re.IGNORECASE),
]

BOND_PENALTY_RE = re.compile(
    r"(?:penalty|liquidated damages|recover(?:y)?|payable)[^.\n]{0,80}", re.IGNORECASE
)


class DocumentError(Exception):
    """Raised for unsupported, oversized, malformed or unreadable documents."""


@dataclass
class ExtractionResult:
    """Result of extracting a document."""

    text: str = ""
    method: str = "none"
    success: bool = False
    warnings: list[str] = field(default_factory=list)
    page_count: int = 0
    facts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def clean_text(text: str, limit: int | None = None) -> str:
    """Collapse noisy whitespace, strip control characters and cap the length."""
    if not text:
        return ""
    limit = limit or config.MAX_EXTRACTED_CHARS
    cleaned = text.replace("\x00", " ")
    cleaned = re.sub(r"[ \t\u00a0]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = "\n".join(line.strip() for line in cleaned.splitlines())
    return cleaned.strip()[:limit]


def extract_snippet(text: str, start: int, end: int, radius: int = 90) -> str:
    """Return a readable, single-line snippet around a match."""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    snippet = re.sub(r"\s+", " ", text[left:right]).strip()
    prefix = "..." if left > 0 else ""
    suffix = "..." if right < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def _parse_amount(raw: str) -> int | None:
    try:
        value = float(str(raw).replace(",", ""))
    except (TypeError, ValueError):
        return None
    if value <= 0 or value > 10_000_000:
        return None
    return int(round(value))


def find_amounts(text: str) -> list[dict[str, Any]]:
    """Find money mentions together with an inferred purpose from nearby words."""
    results: list[dict[str, Any]] = []
    seen: set = set()
    for pattern in AMOUNT_PATTERNS:
        for match in pattern.finditer(text or ""):
            amount = _parse_amount(match.group(1))
            if amount is None:
                continue
            window = text[max(0, match.start() - 180): match.end() + 180].lower()
            purpose = "unclear purpose"
            for label, keywords in PURPOSE_KEYWORDS.items():
                if any(keyword in window for keyword in keywords):
                    purpose = label
                    break
            key = (amount, purpose)
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "amount": amount,
                    "amount_display": f"INR {amount:,}",
                    "purpose": purpose,
                    "snippet": extract_snippet(text, match.start(), match.end()),
                }
            )
    results.sort(key=lambda item: (-item["amount"], item["purpose"]))
    return results


def _first_group(pattern: re.Pattern, text: str) -> str | None:
    match = pattern.search(text or "")
    if not match:
        return None
    value = (match.group(1) or "").strip(" \t:,-.")
    return value or None


def extract_facts(text: str) -> dict[str, Any]:
    """Extract structured facts. Unknown fields stay None: nothing is invented."""
    text = text or ""
    facts: dict[str, Any] = {
        "company_name": None,
        "sender_email": None,
        "sender_domain": None,
        "other_domains": [],
        "company_website": None,
        "role": None,
        "payment_amount": None,
        "payment_amount_display": None,
        "payment_purpose": None,
        "payment_deadline": None,
        "bond_duration": None,
        "bond_penalty": None,
        "emails": extract_emails(text),
        "amounts": find_amounts(text),
    }

    facts["company_name"] = next(
        (value for value in (_first_group(pattern, text) for pattern in COMPANY_PATTERNS) if value),
        None,
    )

    emails = facts["emails"]
    if emails:
        preferred = next(
            (item for item in emails if re.search(r"(hr|careers?|recruit|talent|jobs?|hiring)", item, re.IGNORECASE)),
            emails[0],
        )
        facts["sender_email"] = preferred
        facts["sender_domain"] = registered_domain(preferred)

    urls = extract_urls(text)
    if urls:
        facts["company_website"] = urls[0]
        facts["other_domains"] = sorted({registered_domain(url) for url in urls if registered_domain(url)})

    facts["role"] = next(
        (
            re.sub(r"\s+", " ", value).strip()
            for value in (_first_group(pattern, text) for pattern in ROLE_PATTERNS)
            if value
        ),
        None,
    )

    amounts = facts["amounts"]
    if amounts:
        relevant = next((item for item in amounts if item["purpose"] != "unclear purpose"), amounts[0])
        facts["payment_amount"] = relevant["amount"]
        facts["payment_amount_display"] = relevant["amount_display"]
        facts["payment_purpose"] = relevant["purpose"]

    for pattern in DEADLINE_PATTERNS:
        match = pattern.search(text)
        if match:
            facts["payment_deadline"] = re.sub(r"\s+", " ", match.group(0)).strip()
            break

    for pattern in BOND_DURATION_PATTERNS:
        match = pattern.search(text)
        if match:
            facts["bond_duration"] = re.sub(r"\s+", " ", match.group(0)).strip()
            break

    penalty = BOND_PENALTY_RE.search(text)
    if penalty:
        facts["bond_penalty"] = re.sub(r"\s+", " ", penalty.group(0)).strip()[:200]

    return facts


def validate_upload(filename: str, data: bytes) -> str:
    """Validate extension and size, returning the lowercase extension. Raises DocumentError."""
    if not data:
        raise DocumentError("The uploaded file is empty. Please choose a valid offer letter.")
    if len(data) > config.MAX_FILE_SIZE_BYTES:
        limit_mb = config.MAX_FILE_SIZE_BYTES // (1024 * 1024)
        raise DocumentError(f"The file is larger than the {limit_mb} MB limit.")
    extension = Path(filename or "").suffix.lower()
    if extension not in config.ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(config.ALLOWED_EXTENSIONS))
        raise DocumentError(
            f"Unsupported file type '{extension or 'unknown'}'. Allowed types: {allowed}."
        )
    if pymupdf is None and extension == ".pdf":
        raise DocumentError("PDF support is unavailable because PyMuPDF is not installed.")
    return extension


def extract_pdf(data: bytes) -> ExtractionResult:
    """Extract text from a PDF, falling back to OCR when the PDF is scanned."""
    result = ExtractionResult(method="pdf-text")
    if pymupdf is None:
        result.warnings.append("PyMuPDF is not installed, so PDF text cannot be extracted.")
        return result

    try:
        document = pymupdf.open(stream=data, filetype="pdf")
    except Exception:
        raise DocumentError(
            "This PDF could not be opened. The file may be corrupted or password protected."
        )

    try:
        if getattr(document, "needs_pass", False):
            result.warnings.append(
                "This PDF is password protected, so only limited text could be read."
            )
        result.page_count = document.page_count
        if document.page_count > config.MAX_PDF_PAGES:
            raise DocumentError(
                f"The PDF has {document.page_count} pages, above the {config.MAX_PDF_PAGES} page limit."
            )

        pages: list[str] = []
        for page in document:
            try:
                pages.append(page.get_text("text") or "")
            except Exception:
                pages.append("")
        text = clean_text("\n".join(pages))

        if len(text) >= MIN_PDF_TEXT_CHARS:
            result.text = text
            result.success = True
            return result

        ocr_pages = min(document.page_count, OCR_PAGE_LIMIT)
        result.method = "pdf-ocr"
        result.warnings.append(
            f"No selectable text found, so this looks like a scanned PDF. "
            f"Tried OCR on the first {ocr_pages} page(s)."
        )
        ocr_texts: list[str] = []
        for index in range(ocr_pages):
            page_text, warnings = ocr_service.ocr_pdf_page(document.load_page(index))
            result.warnings.extend(warnings)
            if page_text:
                ocr_texts.append(page_text)
        combined = clean_text("\n".join(ocr_texts))
        if combined:
            result.text = combined
            result.success = True
        else:
            result.text = ""
            result.success = False
            if not result.warnings:
                result.warnings.append(
                    "No text could be extracted from this document. Paste the letter text manually."
                )
        return result
    finally:
        document.close()


def extract_image(data: bytes) -> ExtractionResult:
    """Extract text from an image through OCR."""
    result = ExtractionResult(method="image-ocr")
    text, warnings = ocr_service.extract_text_from_image_bytes(data)
    result.warnings.extend(warnings)
    text = clean_text(text)
    if text:
        result.text = text
        result.success = True
    else:
        result.success = False
        if not result.warnings:
            result.warnings.append(
                "No text could be read from this image. Try a clearer scan or paste the text manually."
            )
    return result


def parse_document(filename: str, data: bytes, run_fact_extraction: bool = True) -> ExtractionResult:
    """Validate and extract an uploaded document. Raises DocumentError for bad input."""
    extension = validate_upload(filename, data)
    if extension == ".pdf":
        result = extract_pdf(data)
    else:
        result = extract_image(data)
    result.facts = extract_facts(result.text) if run_fact_extraction else {}
    return result


def parse_manual_text(text: str) -> ExtractionResult:
    """Build an extraction result from manually pasted text."""
    cleaned = clean_text(text)
    result = ExtractionResult(
        text=cleaned,
        method="manual-text",
        success=bool(cleaned),
        warnings=[] if cleaned else ["No text was provided."],
    )
    result.facts = extract_facts(cleaned)
    return result
