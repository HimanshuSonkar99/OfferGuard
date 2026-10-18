"""Company Check: honest, layered verification of company and sender information.

Layers:
1. Email / domain parsing and validation.
2. Comparison against independently sourced official domains (reference data).
3. Lookalike-domain detection (warning, never proof of fraud).
4. Optional domain-registration lookup through a public RDAP service using a
   strict allow-list and SSRF protection. Failures never block the analysis.

Every unchecked item is reported as "not checked" or "unavailable" instead of
being silently treated as safe.
"""

from __future__ import annotations

import difflib
import ipaddress
import logging
import socket
from datetime import UTC, datetime
from typing import Any

import requests

import config
from database import repository
from database.models import Finding
from services.normalizer import (
    describe_domain_input,
    is_valid_domain,
    is_valid_email,
    normalize_domain,
    registered_domain,
)

FREE_MAIL_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.in",
    "outlook.com", "hotmail.com", "live.com", "rediffmail.com", "aol.com",
    "protonmail.com", "proton.me", "icloud.com", "mail.com", "zohomail.com",
}

CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "!": "i",
})

_RDAP_CACHE: dict[str, dict[str, Any]] = {}

logger = logging.getLogger("offerguard.company")


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _skeleton(domain: str) -> str:
    """Replace common lookalike characters so 'inf0sys' and 'infosys' compare equal."""
    value = normalize_domain(domain).translate(CONFUSABLES)
    return value.replace("rn", "m").replace("vv", "w").replace("-", "").replace(".", "")


def detect_lookalike(sender: str, official: str) -> dict[str, Any]:
    """Compare a sender domain with an official domain. Similarity is a warning, not proof."""
    sender_registered = registered_domain(sender)
    official_registered = registered_domain(official)
    result = {
        "is_lookalike": False,
        "kind": "none",
        "similarity": 0.0,
        "explanation": "",
    }
    if not sender_registered or not official_registered:
        return result

    if sender_registered == official_registered:
        result["kind"] = "exact"
        result["similarity"] = 1.0
        return result

    sender_skel = _skeleton(sender_registered)
    official_skel = _skeleton(official_registered)
    official_label = official_registered.split(".")[0]
    sender_label = sender_registered.split(".")[0]
    similarity = difflib.SequenceMatcher(None, sender_skel, official_skel).ratio()
    result["similarity"] = round(similarity, 3)

    # 1. Confusable character substitution, e.g. inf0sys.com vs infosys.com
    if sender_skel == official_skel:
        result.update(
            is_lookalike=True,
            kind="character-substitution",
            explanation="The sender domain uses lookalike characters that copy the official domain.",
        )
        return result

    # 2. Official domain used as a misleading subdomain, e.g. infosys.com.verify-now.in
    if official_registered in sender_registered and not sender_registered.endswith(official_registered):
        result.update(
            is_lookalike=True,
            kind="misleading-subdomain",
            explanation="The official domain appears inside the sender domain as a subdomain, which is a common impersonation trick.",
        )
        return result

    # 3. Same brand name on a different top-level domain, e.g. infosys.co instead of infosys.com
    if sender_label == official_label and sender_registered != official_registered:
        result.update(
            is_lookalike=True,
            kind="different-tld",
            explanation="The sender domain uses the same company name with a different top-level domain.",
        )
        return result

    # 4. Brand name embedded with extra words or hyphens, e.g. infosys-careers.com
    if official_label and official_label in sender_label.replace("-", ""):
        result.update(
            is_lookalike=True,
            kind="brand-with-extra-words",
            explanation="The sender domain contains the official brand name mixed with extra words or hyphens.",
        )
        return result

    # 5. Very similar spelling
    if similarity >= 0.82:
        result.update(
            is_lookalike=True,
            kind="similar-spelling",
            explanation="The sender domain is spelt almost identically to the official domain.",
        )
        return result

    return result


def _is_safe_public_host(host: str) -> tuple[bool, str]:
    """Return (safe, reason). Blocks localhost, private networks and metadata endpoints."""
    if not host:
        return False, "empty host"
    host = host.strip().strip("[]")
    if host in {"localhost", "metadata", "metadata.google.internal"}:
        return False, "internal host blocked"
    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "host could not be resolved"
    for entry in addresses:
        address = ipaddress.ip_address(entry[4][0])
        if (
            address.is_private
            or ipaddress.ip_address(address).is_loopback
            or address.is_link_local
            or ipaddress.ip_address(address).is_reserved
            or ipaddress.ip_address(address).is_multicast
            or str(address) == "169.254.169.254"
        ):
            return False, f"destination {address} is not a public address"
    return True, "ok"


def check_domain_registration(domain: str, allow_external: bool = True) -> dict[str, Any]:
    """Query a public RDAP service for domain registration data. Never raises."""
    outcome: dict[str, Any] = {
        "checked": False,
        "status": "unavailable",
        "message": "Domain registration was not checked.",
        "registered_at": None,
        "registrar": None,
        "source": "RDAP (rdap.org)",
        "checked_at": None,
    }
    registered = registered_domain(domain)
    if not registered or not is_valid_domain(registered):
        outcome["message"] = "No valid domain was available to check."
        return outcome
    if not allow_external or not config.EXTERNAL_LOOKUPS_ENABLED:
        outcome["message"] = "External verification is disabled, so registration data was not checked."
        return outcome
    if registered in _RDAP_CACHE:
        cached = dict(_RDAP_CACHE[registered])
        cached["cached"] = True
        return cached

    host = config.APPROVED_LOOKUP_HOSTS[0]
    safe, reason = _is_safe_public_host(host)
    if not safe:
        outcome["status"] = "blocked"
        outcome["message"] = f"The registration lookup was blocked for safety: {reason}."
        return outcome

    url = f"https://{host}/domain/{registered}"
    try:
        response = requests.get(
            url,
            timeout=config.EXTERNAL_CHECK_TIMEOUT,
            headers={"Accept": "application/rdap+json", "User-Agent": "OfferGuard/1.0"},
            allow_redirects=False,
        )
        outcome["checked"] = True
        outcome["checked_at"] = _now()
        if response.status_code == 404:
            outcome["status"] = "not-found"
            outcome["message"] = "The RDAP service has no registration record for this domain."
        elif response.status_code == 429:
            outcome["status"] = "rate-limited"
            outcome["message"] = "The RDAP service rate-limited the request. Registration date is unknown."
        elif response.status_code >= 400:
            outcome["status"] = "error"
            outcome["message"] = f"The RDAP service returned status {response.status_code}. Registration date is unknown."
        else:
            payload = response.json()
            events = payload.get("events", []) or []
            registered_at = next(
                (event.get("eventDate") for event in events if event.get("eventAction") == "registration"),
                None,
            )
            registrar = None
            for entity in payload.get("entities", []) or []:
                if "registrar" in (entity.get("roles") or []):
                    vcard = entity.get("vcardArray") or []
                    if len(vcard) > 1 and vcard[1]:
                        for item in vcard[1]:
                            if item and item[0] == "fn":
                                registrar = item[3]
                                break
                    break
            outcome["registered_at"] = registered_at
            outcome["registrar"] = registrar
            outcome["status"] = "ok" if registered_at else "no-registration-date"
            outcome["message"] = (
                "Registration data retrieved from RDAP."
                if registered_at
                else "The RDAP record did not include a registration date."
            )
    except requests.exceptions.Timeout:
        outcome["status"] = "timeout"
        outcome["message"] = "The registration lookup timed out. Registration date is unknown."
        logger.warning("RDAP lookup timed out for %s", registered)
    except ValueError:
        # Covers malformed JSON. requests' JSONDecodeError is both a
        # ValueError and a RequestException, so this must come first.
        outcome["status"] = "error"
        outcome["message"] = "The RDAP response could not be parsed. Registration date is unknown."
        logger.warning("RDAP response for %s could not be parsed", registered)
    except requests.exceptions.RequestException as exc:
        outcome["status"] = "unavailable"
        outcome["message"] = "The registration service could not be reached. Registration date is unknown."
        logger.warning("RDAP lookup failed for %s: %s", registered, exc)

    # Only cache definitive answers. Transient failures (timeout, rate limit,
    # network errors) must not poison the cache for the process lifetime.
    if outcome["status"] in ("ok", "not-found", "no-registration-date"):
        _RDAP_CACHE[registered] = dict(outcome)
    return outcome


def _days_since(iso_date: str | None) -> int | None:
    """Return the age in days of an ISO date, or None when it cannot be parsed."""
    if not iso_date:
        return None
    cleaned = str(iso_date).strip().replace("Z", "+00:00")
    for parser in (
        lambda value: datetime.fromisoformat(value),
        lambda value: datetime.strptime(value[:10], "%Y-%m-%d"),
    ):
        try:
            parsed = parser(cleaned)
        except (ValueError, TypeError):
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - parsed).days)
    return None


def _finding(
    rule_id: str,
    severity: str,
    points: int,
    evidence: str,
    explanation: str,
    confidence: str = "medium",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        module="company",
        category="company",
        severity=severity,
        points=points,
        evidence=evidence,
        explanation=explanation,
        confidence=confidence,
    )


def run_company_check(
    company_name: str = "",
    sender_email: str | None = None,
    sender_domain: str | None = None,
    allow_external: bool = True,
    db_path=None,
) -> dict[str, Any]:
    """Run the layered company check. Returns findings, statuses and the raw lookups."""
    findings: list[Finding] = []
    checks: list[dict[str, str]] = []
    company = (company_name or "").strip()
    email = (sender_email or "").strip()
    domain_input = (sender_domain or "").strip() or email
    info = describe_domain_input(domain_input)
    sender_registered = info["registered_domain"] if info["kind"] != "empty" else ""

    references = repository.get_references(company, db_path) if company else []
    reference = references[0] if references else None
    official_domains = [
        registered_domain(item["official_domain"]) for item in references if item.get("official_domain")
    ]
    official_domain = references[0]["official_domain"] if references else ""

    # ---- Layer 1: email and domain parsing ----
    if email:
        if is_valid_email(email):
            checks.append({"label": "Sender email format", "status": "pass", "detail": email})
        else:
            checks.append({"label": "Sender email format", "status": "fail", "detail": email})
            findings.append(
                _finding(
                    "COMPANY-INVALID-EMAIL",
                    "medium",
                    6,
                    email,
                    "The sender email address is malformed, so the claimed sender identity cannot be trusted.",
                    "high",
                )
            )
        if sender_registered in FREE_MAIL_PROVIDERS and company:
            findings.append(
                _finding(
                    "COMPANY-FREE-MAIL-SENDER",
                    "high",
                    10,
                    email,
                    "A free public email service is used while claiming to represent a company. "
                    "Genuine recruiters normally write from a company domain.",
                    "high",
                )
            )
            checks.append({"label": "Corporate email domain", "status": "warn", "detail": f"{sender_registered} is a free mail provider"})
        else:
            checks.append({"label": "Corporate email domain", "status": "pass" if sender_registered else "unknown", "detail": sender_registered or "not provided"})
    else:
        checks.append({"label": "Sender email format", "status": "unknown", "detail": "no sender email found in the letter"})
        if company:
            findings.append(
                _finding(
                    "COMPANY-NO-SENDER-EMAIL",
                    "low",
                    3,
                    "No email address found in the extracted text.",
                    "No sender email was found, so the sender could not be verified. This is a small concern, not proof of fraud.",
                    "low",
                )
            )

    # ---- Layer 2: official domain comparison ----
    if company and references:
        checks.append(
            {
                "label": "Official domain reference",
                "status": "pass",
                "detail": f"{', '.join(official_domains)} (source: {references[0].get('source', 'reference data')})",
            }
        )
        if official_domains and sender_registered:
            matched = next((item for item in official_domains if item == sender_registered), None)
            if matched:
                checks.append({"label": "Sender domain match", "status": "pass", "detail": sender_registered})
            else:
                lookalike = detect_lookalike(sender_registered, official_domains[0])
                for candidate in official_domains[1:]:
                    alternative = detect_lookalike(sender_registered, candidate)
                    if alternative["similarity"] > lookalike["similarity"]:
                        lookalike = alternative
                if lookalike["is_lookalike"]:
                    checks.append({"label": "Sender domain match", "status": "fail", "detail": f"{sender_registered} vs official {', '.join(official_domains)}"})
                    findings.append(
                        _finding(
                            "COMPANY-LOOKALIKE-DOMAIN",
                            "high",
                            12,
                            f"sender: {sender_registered} | official: {', '.join(official_domains)}",
                            f"Likely lookalike domain ({lookalike['kind']}). {lookalike['explanation']} "
                            "A similarity match is a warning that requires independent confirmation, not proof of fraud.",
                            "high",
                        )
                    )
                else:
                    checks.append({"label": "Sender domain match", "status": "warn", "detail": f"{sender_registered} is not an official domain ({', '.join(official_domains)})"})
                    findings.append(
                        _finding(
                            "COMPANY-DOMAIN-MISMATCH",
                            "medium",
                            8,
                            f"sender: {sender_registered} | official: {', '.join(official_domains)}",
                            "The sender domain does not match any official domain stored for this company.",
                            "medium",
                        )
                    )
        elif official_domains and not sender_registered:
            checks.append({"label": "Sender domain match", "status": "unknown", "detail": "no sender domain available to compare"})
    elif company:
        checks.append({"label": "Official domain reference", "status": "unknown", "detail": "no independent reference data for this company"})
    else:
        checks.append({"label": "Official domain reference", "status": "unknown", "detail": "no company name was extracted"})

    # ---- Layer 3: domain registration through RDAP ----
    registration = check_domain_registration(sender_registered, allow_external=allow_external) if sender_registered else {
        "checked": False,
        "status": "unavailable",
        "message": "No sender domain was available for a registration check.",
        "registered_at": None,
        "registrar": None,
        "source": "RDAP (rdap.org)",
        "checked_at": None,
    }
    if sender_registered:
        checks.append(
            {
                "label": "Domain registration (RDAP)",
                "status": "pass" if registration["status"] == "ok" else "unknown",
                "detail": registration["message"],
            }
        )
    if registration.get("registered_at"):
        age = _days_since(registration["registered_at"])
        if age is not None and age <= 30:
            findings.append(
                _finding(
                    "COMPANY-NEW-DOMAIN",
                    "high",
                    10,
                    f"{sender_registered} registered {registration['registered_at']} (about {age} days ago)",
                    "The sender domain was registered very recently. New domains are frequently used for short-lived recruitment scams.",
                    "high",
                )
            )
        elif age is not None and age <= 180:
            findings.append(
                _finding(
                    "COMPANY-RECENT-DOMAIN",
                    "medium",
                    5,
                    f"{sender_registered} registered {registration['registered_at']} (about {age} days ago)",
                    "The sender domain is less than six months old, which is worth verifying independently.",
                    "medium",
                )
            )

    risk_findings = [item for item in findings if item.points > 0]
    if risk_findings:
        status = "concerns"
    elif official_domain and sender_registered == registered_domain(official_domain):
        status = "verified"
    else:
        status = "unknown"

    return {
        "module": "company",
        "name": "Company Check",
        "status": status,
        "points": sum(item.points for item in risk_findings),
        "category_points": {"company": sum(item.points for item in risk_findings)} if risk_findings else {},
        "findings": findings,
        "checks": checks,
        "reference": reference,
        "registration": registration,
        "sender_registered_domain": sender_registered,
        "official_domain": official_domain,
    }


