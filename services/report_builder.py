"""Self-contained HTML/TXT report builder using only the standard library.

Document text is HTML-escaped before it is embedded, so hostile content inside an
uploaded offer letter can never become markup in the downloaded report.
"""

from __future__ import annotations

import html
from typing import Any

from database.models import AnalysisResult

RISK_COLORS = {"High": "#C62828", "Caution": "#A65B00", "Low": "#167647"}
SEVERITY_LABELS = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

STYLE_TEMPLATE = """
  body { margin: 0; background: #F3F7FC; font-family: Segoe UI, Arial, sans-serif; color: #10243A; }
  .wrap { max-width: 960px; margin: 24px auto; background: #ffffff; border: 1px solid #D8E3EF; border-radius: 16px; padding: 32px; }
  h1 { margin: 0 0 4px; font-size: 26px; }
  h2 { font-size: 17px; margin-top: 28px; border-bottom: 1px solid #D8E3EF; padding-bottom: 6px; }
  .sub { color: #52677F; margin: 0 0 18px; }
  .score { font-size: 40px; font-weight: 700; color: __COLOR__; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 999px; background: __COLOR__; color: #ffffff; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
  th, td { text-align: left; border-bottom: 1px solid #E6EEF6; padding: 7px 8px; vertical-align: top; }
  th { background: #F7FAFE; }
  .points { text-align: right; white-space: nowrap; }
  .evidence { color: #52677F; font-size: 12px; }
  .muted { color: #52677F; }
  .notice { background: #FFF7E6; border: 1px solid #F0D9A8; border-radius: 10px; padding: 12px 14px; font-size: 13px; }
  ul { margin: 8px 0 0 18px; }
  footer { margin-top: 28px; color: #52677F; font-size: 12px; }
"""


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _findings_table(findings: list[Any]) -> str:
    if not findings:
        return "<p class='muted'>No findings were recorded for this analysis.</p>"
    rows = []
    for finding in findings:
        rows.append(
            "<tr>"
            f"<td><code>{_escape(finding.rule_id)}</code></td>"
            f"<td>{_escape(finding.module.title())}</td>"
            f"<td>{_escape(SEVERITY_LABELS.get(finding.severity, finding.severity))}</td>"
            f"<td class='points'>{int(finding.points)}</td>"
            f"<td>{_escape(finding.explanation)}</td>"
            f"<td class='evidence'>{_escape(finding.evidence)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Rule</th><th>Layer</th><th>Severity</th><th>Points</th>"
        "<th>Explanation</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _facts_table(facts: dict[str, Any]) -> str:
    labels = [
        ("company_name", "Company name"),
        ("sender_email", "Sender email"),
        ("sender_domain", "Sender domain"),
        ("company_website", "Website found"),
        ("role", "Role / position"),
        ("payment_amount_display", "Payment amount"),
        ("payment_purpose", "Payment purpose"),
        ("payment_deadline", "Payment deadline"),
        ("bond_duration", "Bond duration"),
        ("bond_penalty", "Bond penalty"),
    ]
    rows = []
    for key, label in labels:
        value = (facts or {}).get(key)
        display = _escape(value) if value else "<span class='muted'>not found</span>"
        rows.append(f"<tr><th>{_escape(label)}</th><td>{display}</td></tr>")
    return "<table class='facts'>" + "".join(rows) + "</table>"


def _breakdown_table(breakdown: dict[str, dict[str, Any]]) -> str:
    rows = []
    for key, item in (breakdown or {}).items():
        note = " (capped at category maximum)" if item.get("capped") else ""
        rows.append(
            "<tr>"
            f"<td>{_escape(item.get('label', key))}</td>"
            f"<td class='points'>{int(item.get('awarded', 0))} / {int(item.get('cap', 0))}</td>"
            f"<td>{_escape(str(item.get('raw', 0)) + note)}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Category</th><th>Awarded / Max</th><th>Raw points</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _module_table(modules: dict[str, dict[str, Any]]) -> str:
    rows = []
    for key in ("letter", "company", "threat"):
        module = (modules or {}).get(key, {})
        extra = ""
        if key == "company":
            registration = module.get("registration") or {}
            extra = _escape(registration.get("message", ""))
        elif key == "threat":
            extra = _escape(
                f"{module.get('report_count') or 0} matching report(s); "
                f"{module.get('corroborated_count') or 0} corroborated"
            )
        rows.append(
            "<tr>"
            f"<td>{_escape(module.get('name', key.title()))}</td>"
            f"<td>{_escape(str(module.get('status', 'unknown')).title())}</td>"
            f"<td class='points'>{int(module.get('points', 0))}</td>"
            f"<td>{extra}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Verification layer</th><th>Status</th><th>Points</th>"
        "<th>Notes</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def build_report_html(analysis: AnalysisResult) -> str:
    """Build a complete standalone HTML report from a real analysis result."""
    color = RISK_COLORS.get(analysis.risk_category, RISK_COLORS["Caution"])
    style = STYLE_TEMPLATE.replace("__COLOR__", color)
    recommendations = "".join(f"<li>{_escape(item)}</li>" for item in analysis.recommendations)
    limitations = "".join(f"<li>{_escape(item)}</li>" for item in analysis.limitations)
    extraction = analysis.extraction or {}

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>OfferGuard Risk Report {_escape(analysis.analysis_id)}</title>",
        f"<style>{style}</style>",
        "</head>",
        "<body>",
        '<div class="wrap">',
        "<h1>OfferGuard Risk Report</h1>",
        "<p class='sub'>AI Verifier for Fake Internship &amp; Job Offers &middot; Verify Before You Pay</p>",
        "<h2>Analysis</h2>",
        "<table class='facts'>",
        f"<tr><th>Analysis ID</th><td>{_escape(analysis.analysis_id)}</td></tr>",
        f"<tr><th>Created at</th><td>{_escape(analysis.created_at)}</td></tr>",
        f"<tr><th>Source file</th><td>{_escape(analysis.source_filename or 'manually pasted text')}</td></tr>",
        f"<tr><th>Extraction method</th><td>{_escape(extraction.get('method', 'unknown'))}</td></tr>",
        (
            "<tr><th>Risk score</th><td>"
            f"<span class='score'>{int(analysis.score)}</span> / 100 &nbsp; "
            f"<span class='badge'>{_escape(analysis.risk_category)}</span></td></tr>"
        ),
        "</table>",
        f"<p>{_escape(analysis.summary)}</p>",
        "<h2>Extracted information</h2>",
        _facts_table(analysis.extracted_facts),
        "<h2>Verification layers</h2>",
        _module_table(analysis.module_results),
        "<h2>Detailed findings</h2>",
        _findings_table(analysis.findings),
        "<h2>Score breakdown</h2>",
        _breakdown_table(analysis.score_breakdown),
        "<h2>Recommendations</h2>",
        f"<ul>{recommendations}</ul>",
        "<h2>Limitations and disclaimer</h2>",
        "<div class='notice'>",
        "<p style='margin:0 0 8px;'><strong>This score is a heuristic risk indicator, "
        "not proof of fraud or authenticity.</strong> A score of 80 does not mean an 80% probability of fraud.</p>",
        f"<ul>{limitations}</ul>",
        "</div>",
        "<footer>Generated by OfferGuard. Report suspected cyber financial fraud at "
        "https://cybercrime.gov.in/ or call 1930. Your original document was not stored by this application."
        "</footer>",
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)


def build_report_text(analysis: AnalysisResult) -> str:
    """Build a plain-text version of the report."""
    lines: list[str] = []
    lines.append("OFFERGUARD RISK REPORT")
    lines.append("AI Verifier for Fake Internship & Job Offers - Verify Before You Pay")
    lines.append("=" * 72)
    lines.append(f"Analysis ID    : {analysis.analysis_id}")
    lines.append(f"Created at     : {analysis.created_at}")
    lines.append(f"Source file    : {analysis.source_filename or 'manually pasted text'}")
    lines.append(f"Extraction     : {(analysis.extraction or {}).get('method', 'unknown')}")
    lines.append(f"Risk score     : {analysis.score}/100 ({analysis.risk_category})")
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  {analysis.summary}")
    lines.append("")
    lines.append("EXTRACTED INFORMATION")
    for key, value in (analysis.extracted_facts or {}).items():
        if isinstance(value, (list, dict)) or not value:
            continue
        lines.append(f"  {key.replace('_', ' ').title()}: {value}")
    lines.append("")
    lines.append("FINDINGS")
    if not analysis.findings:
        lines.append("  No findings were recorded.")
    for finding in analysis.findings:
        lines.append(
            f"  [{finding.module}] {finding.rule_id} ({finding.severity}, {finding.points} pts)"
        )
        lines.append(f"      {finding.explanation}")
        if finding.evidence:
            lines.append(f"      evidence: {finding.evidence}")
    lines.append("")
    lines.append("SCORE BREAKDOWN")
    for key, item in (analysis.score_breakdown or {}).items():
        lines.append(f"  {item.get('label', key)}: {item.get('awarded', 0)}/{item.get('cap', 0)}")
    lines.append("")
    lines.append("RECOMMENDATIONS")
    for index, item in enumerate(analysis.recommendations, start=1):
        lines.append(f"  {index}. {item}")
    lines.append("")
    lines.append("LIMITATIONS AND DISCLAIMER")
    lines.append("  This score is a heuristic risk indicator, not proof of fraud or authenticity.")
    for item in analysis.limitations:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Report cyber financial fraud: https://cybercrime.gov.in/ | Helpline 1930")
    return "\n".join(lines)


def report_filename(analysis: AnalysisResult, extension: str = "html") -> str:
    return f"offerguard-report-{analysis.analysis_id}.{extension}"
