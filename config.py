"""Central configuration for OfferGuard.

All tunable limits, scoring allocations and external-service settings live here
so that the application, the tests and the documentation stay in sync.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv() -> None:
    """Load KEY=VALUE pairs from a local .env file without requiring a dependency.

    Existing environment variables always win, matching standard dotenv behaviour.
    """
    env_file = BASE_DIR / ".env"
    if not env_file.is_file():
        return
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass


_load_dotenv()


def _env_flag(name: str, default: bool) -> bool:
    """Read a boolean environment variable, defaulting when it is unset."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off", "")


DATA_DIR = BASE_DIR / "data"

DB_PATH = BASE_DIR / "data" / "offerguard.db"

APP_NAME = "OfferGuard"
APP_SUBTITLE = "AI Verifier for Fake Internship & Job Offers"
TAGLINE = "Verify Before You Pay"
VERSION = "1.0.0"

ALLOWED_EXTENSIONS = (".pdf", ".png", ".jpg", ".jpeg")
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024
MAX_PDF_PAGES = 20
MAX_EXTRACTED_CHARS = 40000

SCORE_CAPS = {
    "payment": 30,
    "urgency": 15,
    "bond": 10,
    "recruitment": 10,
    "company": 20,
    "threat": 15,
}

MAX_SCORE = sum(SCORE_CAPS.values())

CLASSIFICATION_BANDS = (
    (0, 29, "Low"),
    (30, 59, "Caution"),
    (60, 100, "High"),
)

EXTERNAL_CHECK_TIMEOUT = 4
EXTERNAL_LOOKUPS_ENABLED = _env_flag("OFFERGUARD_EXTERNAL_CHECKS", True)

APPROVED_LOOKUP_HOSTS = ("rdap.org", "rdap.iana.org")

REPORT_CATEGORIES = [
    "Advance payment or fee demand",
    "Fake or unverifiable company",
    "Lookalike domain or impersonation",
    "Misleading offer or bond terms",
    "Ghosted after payment",
    "Other",
]

REPORT_STATUSES = ["submitted", "under_review", "corroborated", "rejected"]

LIMITATIONS = [
    "Scores are heuristic risk indicators, not proof that an offer is genuine or fraudulent.",
    "A score of 80 does not mean there is an 80% probability of fraud.",
    "Company registries, RDAP and domain checks depend on external services that may be unavailable.",
    "Only text that is present in the uploaded document can be analysed; images and logos are not verified.",
    "The Campus Threat Network reflects self-reported information and is not a legal finding of fraud.",
    "OfferGuard never stores your original offer letter by default.",
]

REFERENCE_DATA_SOURCE = "Publicly documented corporate website (verify independently)"

PRIVACY_NOTICE = (
    "Documents are processed in memory and are not stored. Only the extracted facts, "
    "findings and score are saved so you can review your analysis history. "
    "Never share bank details, OTPs or identity documents with a recruiter."
)
