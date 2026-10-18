"""Letter Check: explainable, rule-based analysis of offer-letter wording.

Every rule returns a Finding with a rule id, severity, points, the exact evidence
snippet and a plain-language explanation. Rules are deliberately phrase-based so
that the word "fee" or "bond" alone is never flagged without context, and simple
negation ("no registration fee is required") suppresses a match.
"""

from __future__ import annotations

import re
from typing import Any

from database.models import Finding
from services.document_parser import extract_snippet

MODULE = "letter"

NEGATION_RE = re.compile(
    r"\b(no|not|never|without|cannot|can't|cannot be|do not|does not|doesn't|won't|"
    r"will not|is not|isn't|are not|aren't|free of|waived|no such)\b[^.]{0,45}$",
    re.IGNORECASE,
)

RULES: list[dict[str, Any]] = [
    # ---------------- Payment demands ----------------
    {
        "rule_id": "PAY-REFUNDABLE-DEPOSIT",
        "category": "payment",
        "severity": "high",
        "points": 15,
        "confidence": "high",
        "patterns": [
            r"refundable\s+(?:security\s+|laptop\s+|device\s+)?deposit",
            r"refundable\s+amount",
            r"laptop\s+(?:deposit|charges|cost)",
            r"deposit\s+(?:of\s+)?(?:₹|rs\.?|inr)\s*[0-9]",
        ],
        "explanation": "A refundable deposit is requested. Genuine employers do not collect money from interns or candidates.",
    },
    {
        "rule_id": "PAY-TRAINING-FEE",
        "category": "payment",
        "severity": "high",
        "points": 15,
        "confidence": "high",
        "patterns": [
            r"training\s+(?:fee|charges|cost|programme\s+fee)",
            r"fee\s+for\s+training",
            r"pay[a-z]*\s+(?:for\s+)?(?:the\s+)?training",
            r"certification\s+fee",
        ],
        "explanation": "Training or certification fees are requested before joining. Legitimate employers pay for employee training.",
    },
    {
        "rule_id": "PAY-REGISTRATION-FEE",
        "category": "payment",
        "severity": "high",
        "points": 15,
        "confidence": "high",
        "patterns": [
            r"registration\s+(?:fee|charges|amount)",
            r"enrol[lm]?ment\s+fee",
            r"joining\s+(?:fee|charges)",
            r"sign[\s\-]?up\s+fee",
        ],
        "explanation": "A registration, enrolment or joining fee is requested. Recruitment registration fees are a common fraud pattern.",
    },
    {
        "rule_id": "PAY-CONFIRM-SEAT",
        "category": "payment",
        "severity": "high",
        "points": 15,
        "confidence": "high",
        "patterns": [
            r"(?:confirm|secure|reserve)\s+(?:your|the)\s+(?:seat|position|offer|place|admission|slot)[^.\n]{0,80}?(?:fee|amount|deposit|payment|pay|paid|transfer|remit)",
            r"(?:fee|amount|deposit|payment|pay|paid)\b[^.\n]{0,80}?(?:confirm|secure|reserve)\s+(?:your|the)\s+(?:seat|position|offer|place|admission|slot)",
        ],
        "explanation": "A payment is tied to confirming or securing your seat. Genuine employers never ask candidates to pay to confirm an offer.",
    },
    {
        "rule_id": "PAY-DOCUMENT-VERIFICATION",
        "category": "payment",
        "severity": "high",
        "points": 12,
        "confidence": "high",
        "patterns": [
            r"document\s+verification\s+(?:fee|charges|amount)",
            r"verification\s+(?:fee|charges)",
            r"background\s+verification\s+(?:fee|charges)",
        ],
        "explanation": "A document or background verification fee is requested. Genuine background checks are paid for by the employer.",
    },
    {
        "rule_id": "PAY-PROCESSING-FEE",
        "category": "payment",
        "severity": "medium",
        "points": 10,
        "confidence": "high",
        "patterns": [
            r"processing\s+(?:fee|charges)",
            r"(?:administrative|administration)\s+(?:fee|charges)",
        ],
        "explanation": "A processing or administration fee is requested, which is not normal for a genuine offer.",
    },
    {
        "rule_id": "PAY-SECURITY-DEPOSIT",
        "category": "payment",
        "severity": "high",
        "points": 12,
        "confidence": "high",
        "patterns": [
            r"security\s+deposit",
            r"caution\s+deposit",
            r"advance\s+deposit",
            r"deposit\s+(?:amount\s+)?(?:to\s+be\s+)?(?:paid|payable)",
        ],
        "explanation": "A security or caution deposit is requested, which is not a normal part of an internship or job offer.",
    },
    {
        "rule_id": "PAY-ADVANCE-TO-SECURE",
        "category": "payment",
        "severity": "high",
        "points": 15,
        "confidence": "high",
        "patterns": [
            r"(?:to\s+)?(?:confirm|secure|reserve|accept)\s+(?:your\s+|the\s+)?(?:offer|seat|position)[^.\n]{0,60}(?:pay|payment|deposit|transfer|remit)",
            r"(?:pay|payment|deposit|transfer|remit)[^.\n]{0,60}(?:to\s+)?(?:confirm|secure|reserve)\s+(?:your\s+|the\s+)?(?:offer|seat|position)",
            r"payment\s+(?:is\s+)?required\s+to\s+(?:confirm|secure|process)",
        ],
        "explanation": "Money is requested to confirm or secure the offer, which is a strong indicator of a recruitment scam.",
    },
    {
        "rule_id": "PAY-UPFRONT-DEMAND",
        "category": "payment",
        "severity": "medium",
        "points": 10,
        "confidence": "medium",
        "patterns": [
            r"(?:pay|payment|deposit|transfer|remit)\s+(?:the\s+)?(?:amount\s+)?(?:of\s+)?(?:₹|rs\.?|inr)\s*[0-9][0-9,]*[^.\n]{0,60}(?:upi|gpay|google pay|phonepe|paytm|bank transfer|account number|neft|imps)",
            r"(?:upi|gpay|google pay|phonepe|paytm)\s+(?:id|number|account)?[^.\n]{0,40}(?:₹|rs\.?|inr)\s*[0-9]",
            r"(?:send|transfer)\s+(?:the\s+)?money\s+(?:to|via)",
        ],
        "explanation": "An upfront payment is requested through a personal or informal payment channel.",
    },
    {
        "rule_id": "PAY-DEPOSIT-OR-DOCS",
        "category": "payment",
        "severity": "medium",
        "points": 9,
        "confidence": "medium",
        "patterns": [
            r"deposit\s+(?:the\s+)?(?:documents?|original\s+documents?)",
            r"original\s+documents?\s+(?:must\s+be\s+)?(?:submitted|deposited)",
        ],
        "explanation": "Original documents are asked for before joining, which is a risk to your identity if the employer is not genuine.",
    },
    # ---------------- Urgency and pressure ----------------
    {
        "rule_id": "URG-PAY-IMMEDIATELY",
        "category": "urgency",
        "severity": "high",
        "points": 10,
        "confidence": "high",
        "patterns": [
            r"pay\s+(?:the\s+amount\s+)?immediately",
            r"(?:immediate|instant)\s+payment",
            r"payment\s+(?:is\s+)?(?:required\s+)?(?:immediately|at the earliest|urgently)",
            r"pay\s+(?:it\s+)?(?:as\s+soon\s+as\s+possible|today)",
        ],
        "explanation": "Immediate payment is demanded, which pressures you into acting before you can verify the offer.",
    },
    {
        "rule_id": "URG-OFFER-EXPIRES",
        "category": "urgency",
        "severity": "medium",
        "points": 8,
        "confidence": "high",
        "patterns": [
            r"offer\s+(?:will\s+)?expire[sd]?\s+(?:today|tomorrow|within|immediately)",
            r"valid\s+(?:till|until|only)\s+(?:today|tonight)",
            r"expires?\s+(?:today|immediately)",
            r"last\s+date\s+(?:of|for)\s+payment",
        ],
        "explanation": "The offer or payment window is unrealistically short, a classic pressure tactic.",
    },
    {
        "rule_id": "URG-LIMITED-SEATS",
        "category": "urgency",
        "severity": "low",
        "points": 6,
        "confidence": "medium",
        "patterns": [
            r"limited\s+(?:seats|slots|openings|vacancies)",
            r"only\s+\d+\s+(?:seats|slots|positions)\s+(?:left|available)",
            r"first\s+come\s+first\s+serve",
        ],
        "explanation": "Scarcity language such as limited seats is used to rush candidates.",
    },
    {
        "rule_id": "URG-LOSE-SELECTION",
        "category": "urgency",
        "severity": "medium",
        "points": 9,
        "confidence": "high",
        "patterns": [
            r"(?:selection|candidature|offer|seat)\s+(?:will\s+be\s+)?(?:cancelled|rejected|withdrawn|lost)\s+if[^.\n]{0,60}(?:not\s+)?(?:paid|payment|deposit|within)",
            r"(?:otherwise|lest)[^.\n]{0,40}(?:your\s+)?(?:selection|candidature|seat)[^.\n]{0,40}(?:cancelled|rejected|lost)",
            r"fail(?:ure)?\s+to\s+pay[^.\n]{0,60}(?:cancel|reject|withdraw|forfeit)",
        ],
        "explanation": "You are threatened with losing the offer if you do not pay, which is coercion.",
    },
    {
        "rule_id": "URG-HOURS-DEADLINE",
        "category": "urgency",
        "severity": "medium",
        "points": 8,
        "confidence": "medium",
        "patterns": [
            r"within\s+(?:24|48|12|6)\s+(?:hours|hrs)",
            r"within\s+(?:one|two|three)\s+(?:day|days)\s+of\s+(?:receiving|this)",
        ],
        "explanation": "A very short deadline is placed on your response or payment.",
    },
    {
        "rule_id": "URG-PRESSURE-LANGUAGE",
        "category": "urgency",
        "severity": "medium",
        "points": 6,
        "confidence": "medium",
        "patterns": [
            r"act\s+(?:fast|now|quickly|immediately)",
            r"click\s+here",
            r"\bhurry\b",
            r"limited\s+time",
            r"don'?t\s+miss",
            r"apply\s+(?:now|immediately|today)",
        ],
        "explanation": "Pressure language is used to rush you into acting before you can verify the offer.",
    },
    # ---------------- Bond and penalty clauses ----------------
    {
        "rule_id": "BOND-LONG-PERIOD",
        "category": "bond",
        "severity": "medium",
        "points": 6,
        "confidence": "medium",
        "patterns": [
            r"bond\s*(?:period)?\s*(?:of|for)\s*(?:[2-9]|[1-9][0-9])\s*(?:years?|yrs?)",
            r"(?:[2-9]|[1-9][0-9])\s*(?:years?|yrs?)\s*(?:service\s+)?bond",
            r"bond\s*(?:period)?\s*(?:of|for)\s*(?:[1-9][0-9]|[2-9][0-9])\s*months",
            r"minimum\s+(?:service\s+)?(?:period|commitment)[^.\n]{0,30}(?:[3-9]|1[0-9])\s*(?:years?|months?)",
        ],
        "explanation": "A long mandatory bond or service commitment is attached to a junior or internship role.",
    },
    {
        "rule_id": "BOND-PENALTY-AMOUNT",
        "category": "bond",
        "severity": "medium",
        "points": 7,
        "confidence": "high",
        "patterns": [
            r"(?:penalty|liquidated damages|damages)[^.\n]{0,80}(?:₹|rs\.?|inr)\s*[0-9]",
            r"(?:₹|rs\.?|inr)\s*[0-9][0-9,]*[^.\n]{0,60}(?:penalty|liquidated damages)",
            r"(?:recover|refund)\s*(?:the\s+)?(?:training|joining|onboarding)?\s*cost[^.\n]{0,60}(?:penalty|bond|if\s+you\s+leave)",
        ],
        "explanation": "A monetary penalty is attached to leaving or breaking the agreement.",
    },
    {
        "rule_id": "BOND-ORIGINAL-DOCS-HELD",
        "category": "bond",
        "severity": "high",
        "points": 8,
        "confidence": "high",
        "patterns": [
            r"original\s+(?:certificates?|documents?|marksheets?)[^.\n]{0,60}(?:retained|withheld|kept|held|surrendered)",
            r"(?:surrender|handover|hand\s+over|deposit)\s+(?:your\s+)?original\s+(?:certificates?|documents?|marksheets?)",
        ],
        "explanation": "Original certificates are asked to be held by the employer, which is a serious retention risk.",
    },
    {
        "rule_id": "BOND-RESTRICTIVE-TERMS",
        "category": "bond",
        "severity": "low",
        "points": 5,
        "confidence": "medium",
        "patterns": [
            r"not\s+(?:permitted|allowed|eligible)\s+to\s+(?:resign|leave|terminate)",
            r"(?:cannot|may\s+not)\s+(?:resign|leave)[^.\n]{0,30}(?:bond|agreement|period)",
            r"notice\s+period\s+of\s+(?:[3-9]|[1-9][0-9])\s*months",
            r"confidentiality\s+clause[^.\n]{0,60}(?:indefinite|perpetual|forever)",
        ],
        "explanation": "Unusually restrictive employment conditions are described.",
    },
    # ---------------- Recruitment process concerns ----------------
    {
        "rule_id": "REC-GUARANTEED-SELECTION",
        "category": "recruitment",
        "severity": "high",
        "points": 8,
        "confidence": "high",
        "patterns": [
            r"guaranteed\s+(?:selection|placement|job|internship)",
            r"100\s*%\s*(?:selection|placement|job|guarantee)",
            r"assured\s+(?:selection|placement|job)",
            r"direct\s+(?:joining|offer)\s+without\s+(?:interview|test)",
        ],
        "explanation": "Guaranteed selection or placement is promised, which is a hallmark of a recruitment scam.",
    },
    {
        "rule_id": "REC-NO-INTERVIEW",
        "category": "recruitment",
        "severity": "low",
        "points": 4,
        "confidence": "low",
        "patterns": [
            r"no\s+(?:interview|written\s+test|technical\s+round)\s+(?:is\s+)?(?:required|needed|necessary)",
            r"without\s+any\s+(?:interview|test|screening)",
            r"selection\s+(?:is\s+)?(?:purely\s+)?based\s+on\s+(?:your\s+)?(?:resume|cv)\s+only",
        ],
        "explanation": "No interview or screening is mentioned. This alone is not proof of fraud, but it weakens the offer's credibility.",
    },
    {
        "rule_id": "REC-INCONSISTENT-CLAIMS",
        "category": "recruitment",
        "severity": "medium",
        "points": 5,
        "confidence": "medium",
        "patterns": [
            r"immediate\s+joining\s+without\s+(?:any\s+)?(?:interview|verification|documents?)",
            r"offer\s+(?:letter\s+)?issued\s+without[^.\n]{0,40}(?:interview|verification)",
            r"selected\s+for\s+(?:the\s+post|the\s+position)[^.\n]{0,40}without\s+(?:applying|application|interview)",
        ],
        "explanation": "The recruitment process described is inconsistent with normal hiring practice.",
    },
    {
        "rule_id": "REC-UNREALISTIC-SALARY",
        "category": "recruitment",
        "severity": "low",
        "points": 5,
        "confidence": "medium",
        "patterns": [
            r"(?:stipend|salary|package)[^.\n]{0,50}(?:₹|rs\.?|inr)\s*(?:[5-9][0-9]|[1-9][0-9]{2}),?[0-9]{3}\s*(?:per\s+month|pm|monthly)",
            r"(?:earn|earnings?)\s+(?:up\s+to\s+)?(?:₹|rs\.?)\s*[0-9,]{2,}\s*(?:per\s+day|daily|per\s+week)",
            r"part[\s\-]?time[^.\n]{0,50}(?:₹|rs\.?)\s*[0-9,]{4,}\s*(?:per\s+month|monthly)",
        ],
        "explanation": "The promised pay is unusually high for the role described, which is often used as bait.",
    },
    {
        "rule_id": "REC-PAYMENT-BEFORE-JOINING",
        "category": "recruitment",
        "severity": "medium",
        "points": 6,
        "confidence": "high",
        "patterns": [
            r"before\s+(?:the\s+)?joining[^.\n]{0,60}(?:pay|payment|deposit|fee)",
            r"(?:pay|payment|fee|deposit)[^.\n]{0,60}before\s+(?:the\s+)?(?:joining|onboarding|internship\s+start)",
            r"prior\s+to\s+joining[^.\n]{0,60}(?:payment|deposit|fee)",
        ],
        "explanation": "Payment is expected before joining or onboarding begins.",
    },
]

INFO_RULES = {
    "no_payment_signal": {
        "rule_id": "LTR-NO-PAYMENT-SIGNAL",
        "category": "payment",
        "severity": "info",
        "points": 0,
        "explanation": "No request for money was detected in the extracted text. This does not by itself prove the offer is genuine.",
        "confidence": "low",
    },
    "thin_text": {
        "rule_id": "LTR-LIMITED-TEXT",
        "category": "recruitment",
        "severity": "info",
        "points": 0,
        "explanation": "Only a small amount of text was available, so the letter could not be examined thoroughly. Try the manual paste option for a fuller check.",
        "confidence": "low",
    },
}


def _is_negated(text: str, match_start: int) -> bool:
    window = text[max(0, match_start - 70): match_start]
    return bool(NEGATION_RE.search(window))


def run_letter_check(text: str, min_chars: int = 120) -> dict[str, Any]:
    """Analyse letter text and return findings plus a module summary."""
    text = text or ""
    findings: list[Any] = []
    matched_rule_ids: set = set()

    if text:
        for rule in RULES:
            for pattern in rule["patterns"]:
                match = None
                for candidate in re.finditer(pattern, text, re.IGNORECASE):
                    if not _is_negated(text, candidate.start()):
                        match = candidate
                        break
                if not match:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        module="letter",
                        category=rule["category"],
                        severity=rule["severity"],
                        points=int(rule["points"]),
                        evidence=extract_snippet(text, match.start(), match.end()),
                        explanation=rule["explanation"],
                        confidence=rule.get("confidence", "medium"),
                    )
                )
                matched_rule_ids.add(rule["rule_id"])
                break

    if not text or len(text) < min_chars:
        info = INFO_RULES["thin_text"]
        findings.append(
            Finding(
                rule_id=info["rule_id"],
                module="letter",
                category=info["category"],
                severity=info["severity"],
                points=0,
                evidence=text[:120] or "(no text extracted)",
                explanation=info["explanation"],
                confidence="low",
            )
        )

    if not any(item.points > 0 for item in findings):
        info = INFO_RULES["no_payment_signal"]
        findings.append(
            Finding(
                rule_id=info["rule_id"],
                module="letter",
                category=info["category"],
                severity="info",
                points=0,
                evidence="No payment request detected in the extracted text.",
                explanation=info["explanation"],
                confidence="low",
            )
        )

    risk_findings = [item for item in findings if item.points > 0]
    category_points = {}
    for item in risk_findings:
        category_points[item.category] = category_points.get(item.category, 0) + item.points

    return {
        "module": "letter",
        "name": "Letter Check",
        "status": "concerns" if risk_findings else "clear",
        "points": sum(category_points.values()),
        "category_points": category_points,
        "findings": findings,
        "rules_matched": sorted(matched_rule_ids),
    }
