"""Pure-Python helpers for normalising companies, domains and emails."""

from __future__ import annotations

import re

LEGAL_SUFFIXES = {
    "pvt", "pvtltd", "private", "ltd", "limited", "llp", "inc", "incorporated",
    "corp", "corporation", "company", "co", "plc", "llc", "gmbh", "solutions",
}

MULTI_PART_SUFFIXES = {
    "co.in", "com.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "firm.in",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.sg", "co.nz",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
URL_RE = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)


def normalize_company(name: str | None) -> str:
    """Lowercase a company name and strip punctuation and legal suffixes."""
    if not name:
        return ""
    cleaned = re.sub(r"[^a-z0-9\s]", " ", str(name).lower())
    tokens = [token for token in cleaned.split() if token and token not in LEGAL_SUFFIXES]
    return " ".join(tokens).strip()


def normalize_domain(domain: str | None) -> str:
    """Strip scheme, path and a leading www. from a domain-ish string."""
    if not domain:
        return ""
    value = str(domain).strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split("@")[-1]
    value = value.split(":")[0]
    value = value.strip(".")
    if value.startswith("www."):
        value = value[4:]
    return value


def registered_domain(domain: str | None) -> str:
    """Return the registrable domain, handling common multi-part Indian/foreign suffixes."""
    value = normalize_domain(domain)
    if not value:
        return ""
    parts = value.split(".")
    if len(parts) < 2:
        return value
    suffix_two = ".".join(parts[-2:])
    if suffix_two in MULTI_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_valid_email(value: str | None) -> bool:
    if not value:
        return False
    match = EMAIL_RE.fullmatch(str(value).strip())
    if not match:
        return False
    return is_valid_domain(str(value).split("@")[-1])


def is_valid_domain(value: str | None) -> bool:
    domain = normalize_domain(value)
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_RE.match(domain))


def extract_emails(text: str) -> list[str]:
    return sorted({match.lower() for match in EMAIL_RE.findall(text or "")})


def extract_urls(text: str) -> list[str]:
    return sorted({match.lower() for match in URL_RE.findall(text or "")})


def describe_domain_input(value: str | None) -> dict:
    """Classify an arbitrary string as a domain, URL or unknown input."""
    raw = (value or "").strip()
    if not raw:
        return {"kind": "empty", "registered_domain": "", "raw": ""}
    if URL_RE.match(raw):
        return {"kind": "url", "registered_domain": registered_domain(raw), "raw": raw}
    if is_valid_email(raw):
        return {"kind": "email", "registered_domain": registered_domain(raw), "raw": raw}
    if is_valid_domain(raw):
        return {"kind": "domain", "registered_domain": registered_domain(raw), "raw": raw}
    return {"kind": "unknown", "registered_domain": normalize_domain(raw), "raw": raw}
