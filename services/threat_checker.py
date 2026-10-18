"""Campus Threat Network: matching an offer against stored student reports.

Matching rules:
* exact registered sender domain  -> strong match
* normalized company name         -> weak match (lower confidence)

Scoring is deliberately conservative:
* a corroborated domain match awards the full category weight,
* unverified (submitted / under review) matches award only a low weight,
* rejected reports award nothing,
* no reports awards nothing,
* a company is never labelled fraudulent based only on an unverified report.
"""

from __future__ import annotations

from typing import Any

from database import repository
from database.models import Finding

UNVERIFIED_STATUSES = {"submitted", "under_review"}


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
        module="threat",
        category="threat",
        severity=severity,
        points=points,
        evidence=evidence,
        explanation=explanation,
        confidence=confidence,
    )


def _format_matches(reports: list[dict[str, Any]], limit: int = 2) -> str:
    """Compact, readable evidence string for matching reports."""
    parts: list[str] = []
    for report in reports[:limit]:
        date = report.get("incident_date") or (report.get("created_at") or "")[:10]
        demo = " (fictional demo data)" if report.get("is_demo") else ""
        parts.append(f"{report.get('category', 'report')} on {date or 'unknown date'}{demo}")
    if len(reports) > limit:
        parts.append(f"and {len(reports) - limit} more")
    return "; ".join(parts)


def _summarise(reports: list[dict[str, Any]], limit: int = 4) -> str:
    parts = []
    for report in reports[:limit]:
        date = report.get("incident_date") or (report.get("created_at") or "")[:10]
        demo = " [fictional demo record]" if report.get("is_demo") else ""
        parts.append(f"{report.get('category', 'Report')} ({report.get('status', 'submitted')}, {date or 'date unknown'}){demo}")
    if len(reports) > limit:
        parts.append(f"and {len(reports) - limit} more")
    return "; ".join(parts)


def run_threat_check(
    company_name: str = "",
    sender_domain: str = "",
    db_path=None,
    matches_override: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Match an offer against stored reports and return findings plus module status."""
    matches = (
        matches_override
        if matches_override is not None
        else repository.find_reports_for(company_name, sender_domain, db_path)
    )
    domain_reports = matches.get("domain", []) or []
    company_reports = matches.get("company", []) or []

    active_domain = [item for item in domain_reports if item["status"] != "rejected"]
    rejected_domain = [item for item in domain_reports if item["status"] == "rejected"]
    corroborated_domain = [item for item in active_domain if item["status"] == "corroborated"]
    unverified_domain = [item for item in active_domain if item["status"] in UNVERIFIED_STATUSES]
    active_company = [item for item in company_reports if item["status"] != "rejected"]

    findings: list[Finding] = []
    points = 0

    if corroborated_domain:
        points = 15
        findings.append(
            _finding(
                "THREAT-DOMAIN-CORROBORATED",
                "high",
                points,
                f"{len(corroborated_domain)} corroborated report(s) for domain {sender_domain}: "
                + _format_matches(corroborated_domain),
                "The sender domain appears in reports that were corroborated by review. "
                "This is strong supporting evidence, but it is still student-reported information and not a legal finding.",
                "high",
            )
        )
    elif unverified_domain:
        points = 6
        findings.append(
            _finding(
                "THREAT-DOMAIN-UNVERIFIED",
                "medium",
                points,
                f"{len(unverified_domain)} unverified report(s) for domain {sender_domain}: "
                + _format_matches(unverified_domain),
                "The sender domain appears in unverified student reports. Treat this as a warning to verify further, "
                "not as proof that the company is fraudulent.",
                "low",
            )
        )

    if active_company and not active_domain:
        company_points = 4 if points == 0 else 0
        if company_points:
            points = company_points
            findings.append(
                _finding(
                    "THREAT-COMPANY-NAME-MATCH",
                    "low",
                    company_points,
                    f"{len(active_company)} report(s) share the company name '{company_name}': "
                    + _format_matches(active_company),
                    "The company name appears in reports, but the sender domain did not match. "
                    "Company-name matches can be coincidental, so the confidence is low.",
                    "low",
                )
            )

    if rejected_domain and not active_domain:
        findings.append(
            _finding(
                "THREAT-REJECTED-ONLY",
                "info",
                0,
                f"{len(rejected_domain)} rejected report(s) for domain {sender_domain}",
                "Reports for this domain were rejected during moderation, so they do not add to the score.",
                "low",
            )
        )

    if not domain_reports and not company_reports:
        findings.append(
            _finding(
                "THREAT-NO-REPORTS",
                "info",
                0,
                "No stored reports matched the company name or sender domain.",
                "No matching reports were found in the Campus Threat Network. This does not confirm the offer is genuine.",
                "low",
            )
        )

    total_reports = len(domain_reports) + len(company_reports)
    if any(item["is_demo"] for item in domain_reports + company_reports):
        findings.append(
            _finding(
                "THREAT-DEMO-DATA-NOTE",
                "info",
                0,
                "Matching reports include seeded demonstration records.",
                "Some matching records are clearly labelled fictional demonstration data created for this project, "
                "not real cybercrime reports.",
                "low",
            )
        )

    if points > 0:
        status = "concerns"
    elif total_reports:
        status = "info"
    else:
        status = "clear"

    return {
        "module": "threat",
        "name": "Campus Threat Network",
        "status": status,
        "points": points,
        "category_points": {"threat": points} if points else {},
        "findings": findings,
        "matches": {"domain": domain_reports, "company": company_reports},
        "report_count": total_reports,
        "corroborated_count": len(corroborated_domain),
        "unverified_count": len(unverified_domain),
    }
