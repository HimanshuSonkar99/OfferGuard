"""End-to-end analysis pipeline.

Kept free of Streamlit so that it can be tested directly and reused by the UI,
the CLI or a future API layer.
"""

from __future__ import annotations

from typing import Any

from database import repository
from database.models import AnalysisResult
from services import document_parser, risk_engine
from services.document_parser import DocumentError


def _blocking_message(extraction) -> str:
    warnings = " ".join(extraction.warnings).strip()
    base = (
        "No text could be extracted from this document, so no analysis was produced. "
        "An unreadable document is not treated as safe. "
    )
    return base + (warnings or "Try a different file or paste the offer letter text manually.")


def run_analysis_from_bytes(
    filename: str,
    data: bytes,
    facts_override: dict[str, Any] | None = None,
    allow_external: bool = True,
    db_path=None,
    save: bool = True,
) -> AnalysisResult:
    """Validate, extract and analyse an uploaded document."""
    extraction = document_parser.parse_document(filename, data)
    if not extraction.text or not extraction.success:
        raise DocumentError(_blocking_message(extraction))

    extraction_payload = extraction.to_dict()
    extraction_payload["source_filename"] = filename
    result = risk_engine.analyze(
        extraction.text,
        extraction=extraction_payload,
        facts_override=facts_override,
        allow_external=allow_external,
        db_path=db_path,
        source_filename=filename,
    )
    if save:
        repository.save_analysis(result, db_path=db_path)
    return result


def run_analysis_from_text(
    text: str,
    facts_override: dict[str, Any] | None = None,
    allow_external: bool = True,
    db_path=None,
    save: bool = True,
    source_filename: str | None = None,
) -> AnalysisResult:
    """Analyse manually pasted offer-letter text."""
    extraction = document_parser.parse_manual_text(text)
    if not extraction.text:
        raise DocumentError(
            "The pasted text is empty, so no analysis was produced. "
            "Paste the offer letter text to run the verification layers."
        )
    result = risk_engine.analyze(
        extraction.text,
        extraction=extraction.to_dict(),
        facts_override=facts_override,
        allow_external=allow_external,
        db_path=db_path,
        source_filename=source_filename,
    )
    if save:
        repository.save_analysis(result, db_path=db_path)
    return result
