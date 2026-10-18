"""OCR support built on pytesseract with safe fallbacks.

Installing the Python package does NOT install the Tesseract executable, so every
function here degrades gracefully when the binary is missing.
"""

from __future__ import annotations

import io
import os
import shutil

try:  # Pillow is a required dependency
    from PIL import Image, ImageOps
except ImportError:  # pragma: no cover - Pillow is required in requirements.txt
    Image = None  # type: ignore
    ImageOps = None  # type: ignore

try:
    import pytesseract
except ImportError:  # pragma: no cover - pytesseract is required in requirements.txt
    pytesseract = None  # type: ignore

OCR_UNAVAILABLE_MESSAGE = (
    "OCR is unavailable on this machine because the Tesseract engine is not installed. "
    "Upload a PDF with selectable text, or paste the offer letter text manually."
)


def tesseract_cmd() -> str | None:
    """Return the configured Tesseract executable path, or None when not found."""
    configured = os.environ.get("TESSERACT_CMD")
    if configured and os.path.exists(configured):
        return configured
    return shutil.which("tesseract")


def ocr_available() -> bool:
    """True when both pytesseract and the Tesseract binary are usable."""
    if pytesseract is None or Image is None:
        return False
    found = tesseract_cmd()
    if not found:
        return False
    if pytesseract.pytesseract.tesseract_cmd != found:
        pytesseract.pytesseract.tesseract_cmd = found
    return True


def _prepare(image) -> Image.Image:
    """Normalise orientation and colour mode before OCR."""
    prepared = ImageOps.exif_transpose(image)
    if prepared.mode not in ("L", "RGB"):
        prepared = prepared.convert("RGB")
    return prepared


def extract_text_from_image_bytes(data: bytes) -> tuple[str, list[str]]:
    """OCR raw image bytes. Returns (text, warnings). Never raises."""
    warnings: list[str] = []
    if Image is None:
        return "", ["Image support is unavailable (Pillow is not installed)."]
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.load()
            prepared = _prepare(image)
    except Exception:
        return "", ["The uploaded image could not be opened or is corrupted."]

    if not ocr_available():
        warnings.append(OCR_UNAVAILABLE_MESSAGE)
        return "", warnings

    try:
        text = pytesseract.image_to_string(prepared)
    except Exception:
        warnings.append("OCR failed while reading the image. Try a clearer scan or paste the text manually.")
        return "", warnings
    return (text or "").strip(), warnings


def ocr_pdf_page(page) -> tuple[str, list[str]]:
    """OCR a single PyMuPDF page object (used for scanned PDFs). Returns (text, warnings)."""
    if not ocr_available():
        return "", [OCR_UNAVAILABLE_MESSAGE]
    try:
        pixmap = page.get_pixmap(dpi=200)
        image = Image.open(io.BytesIO(pixmap.tobytes("png")))
    except Exception:
        return "", ["A scanned page could not be rendered for OCR."]
    return extract_text_from_image_bytes(_image_to_bytes(image))


def _image_to_bytes(image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
