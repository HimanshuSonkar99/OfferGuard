"""Human-readable summaries and recommendations derived from actual findings."""

from __future__ import annotations

from typing import Any


def _active_categories(breakdown: dict[str, dict[str, Any]]) -> list[tuple]:
    return [
        (item["label"], item["awarded"])
        for item in breakdown.values()
        if item.get("awarded", 0) > 0
    ]


def build_summary(
    score: int,
    risk_category: str,
    findings: list[Any],
    breakdown: dict[str, dict[str, Any]],
    module_results: dict[str, dict[str, Any]],
) -> str:
    """Compose a short, factual summary of the analysis."""
    active = _active_categories(breakdown)
    if active:
        detail = ", ".join(f"{label} ({points} pts)" for label, points in active)
        concern_text = f"Concerns that contributed points: {detail}."
    else:
        concern_text = "No risk rule produced points for this document."

    threat = module_results.get("threat", {})
    report_count = threat.get("report_count") or 0
    if report_count:
        threat_text = (
            f"The Campus Threat Network matched {report_count} stored report(s) "
            f"({threat.get('corroborated_count') or 0} corroborated, {threat.get('unverified_count') or 0} unverified)."
        )
    else:
        threat_text = "No matching reports were found in the Campus Threat Network."

    company = module_results.get("company", {})
    company_status = company.get("status", "unknown")
    company_text = {
        "verified": "The sender domain matched an independently sourced official domain reference.",
        "concerns": "Company or domain checks raised at least one concern.",
        "unknown": "Company and sender details could not be confirmed with independent reference data.",
    }.get(company_status, "Company verification status is unknown.")

    return (
        f"Risk score {score}/100 — {risk_category}. {concern_text} {company_text} {threat_text} "
        "This score is a heuristic risk indicator, not a probability that the offer is fraudulent."
    )


def build_recommendations(
    score: int,
    risk_category: str,
    findings: list[Any],
    breakdown: dict[str, dict[str, Any]],
    module_results: dict[str, dict[str, Any]],
) -> list[str]:
    """Generate practical next steps from the findings, always including verification advice."""
    recommendations: list[str] = []

    if breakdown.get("payment", {}).get("awarded", 0) > 0:
        recommendations.append(
            "Do not pay any registration, training, verification, deposit or processing fee. "
            "Genuine employers never ask candidates for money."
        )
    if breakdown.get("urgency", {}).get("awarded", 0) > 0:
        recommendations.append(
            "Ignore the artificial deadline. Verify the offer independently before responding; "
            "urgency is a common pressure tactic."
        )
    if breakdown.get("bond", {}).get("awarded", 0) > 0:
        recommendations.append(
            "Do not sign a bond or agreement with penalties, and never hand over original certificates."
        )
    if breakdown.get("company", {}).get("awarded", 0) > 0:
        recommendations.append(
            "Compare the sender domain with the official domain you find yourself on the company's website, "
            "not with any link in the letter."
        )
    if breakdown.get("threat", {}).get("awarded", 0) > 0:
        recommendations.append(
            "Review the matching Campus Threat Network reports, then ask your placement cell to confirm "
            "whether other students received the same offer."
        )

    recommendations.append(
        "Contact the company using the phone number or email obtained independently from its official website."
    )
    recommendations.append(
        "Ask your college placement cell or a faculty mentor to confirm the offer before you act on it."
    )

    if risk_category == "High":
        recommendations.append(
            "Treat this as high risk: do not pay or share documents until the offer has been verified "
            "through an independent, trusted channel."
        )
        recommendations.append(
            "Preserve the offer letter, emails and payment requests as evidence, and report the incident."
        )
    elif risk_category == "Caution":
        recommendations.append(
            "Some elements remained unverified. Confirm the sender identity, the company registration "
            "and the role before paying or sharing any document."
        )
    else:
        recommendations.append(
            "No strong risk pattern was detected, but that is not proof of authenticity. "
            "Still verify the recruiter and company independently before paying anything."
        )

    recommendations.append(
        "If you suspect cyber financial fraud in India, file a complaint at https://cybercrime.gov.in/ "
        "or call the 1930 financial-fraud helpline."
    )
    return recommendations
