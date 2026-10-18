"""Reusable, theme-aware HTML building blocks for the OfferGuard interface."""

from __future__ import annotations

import html
from collections.abc import Sequence
from typing import Any

from components.theme import get_palette

STATUS_ICON = {
    "pass": ("&#10003;", "pass", "Passed"),
    "fail": ("&#10007;", "fail", "Concern"),
    "warn": ("&#9888;", "warn", "Warning"),
    "unknown": ("&#8212;", "unknown", "Not checked"),
}

MODULE_META = {
    "letter": ("Letter Check", "Payment demands, urgency, bonds and recruitment wording inside the document."),
    "company": ("Company Check", "Sender email, official domain comparison, lookalike domains and domain age."),
    "threat": ("Campus Threat Network", "Matching against reports submitted by other students."),
}


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def shield_svg(palette: dict[str, str], size: int = 36) -> str:
    return f"""
<svg width="{size}" height="{size}" viewBox="0 0 48 48" fill="none" aria-hidden="true">
  <defs>
    <linearGradient id="ogShield" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="{palette['primary']}"/>
      <stop offset="100%" stop-color="{palette['secondary']}"/>
    </linearGradient>
  </defs>
  <path d="M24 3 L41 9 V25 C41 36 32 43 24 46 C16 43 7 36 7 25 V9 Z"
        fill="url(#ogShield)" opacity="0.16" stroke="{palette['primary']}" stroke-width="2"/>
  <path d="M24 8 L37 12.5 V25 C37 34 31 39.5 24 42 C17 39.5 11 34 11 25 V12.5 Z"
        fill="none" stroke="{palette['primary']}" stroke-width="1.2" opacity="0.7" />
  <path d="M16 30 L21 24 L25 27 L33 17" fill="none" stroke="{palette['primary']}"
        stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" />
  <circle cx="33" cy="17" r="2.6" fill="{palette['secondary']}" />
</svg>
"""


def brand_block(palette: dict[str, str]) -> str:
    return f"""
<div class="og-logo">
  {shield_svg(palette, 36)}
  <div>
    <div class="og-wordmark">Offer<span>Guard</span></div>
    <div class="og-tag">Verify before you pay</div>
  </div>
</div>
"""


def hero(title: str, subtitle: str, description: str) -> str:
    return f"""
<div class="og-hero">
  <h1>{esc(title)}</h1>
  <p style="font-weight:600;color:var(--og-primary);margin-top:2px;">{esc(subtitle)}</p>
  <p>{esc(description)}</p>
</div>
"""


def workflow_indicator(current_step: str, palette: dict[str, str] | None = None) -> str:
    """Three-step workflow indicator: upload -> analysis -> results."""
    steps = [
        ("upload", "Upload Offer Letter", "PDF, PNG or JPG up to the size limit"),
        ("analysis", "AI Analysis", "Three verification layers run on the text"),
        ("results", "Get Results", "Score, evidence and recommendations"),
    ]
    order = {"upload": 0, "analysis": 1, "results": 2}
    current_index = order.get(current_step, 0)
    cards: list[str] = []
    for index, (key, title, description) in enumerate(steps):
        state = "og-active" if index == current_index else ("og-done" if index < current_index else "")
        cards.append(
            f"""
<div class="og-step {state}">
  <div><span class="og-step-num">{index + 1}</span><span class="og-step-title">{esc(title)}</span></div>
  <div class="og-step-desc">{esc(description)}</div>
</div>
"""
        )
    return f"<div class='og-steps'>{''.join(cards)}</div>"


def module_cards(modules: dict[str, dict[str, Any]], palette: dict[str, str] | None = None) -> str:
    """Three verification-layer cards with honest status labels."""
    palette = palette or get_palette("dark")
    status_map = {
        "concerns": ("Concerns found", palette["high"]),
        "verified": ("Verified against reference", palette["low"]),
        "clear": ("No concerns detected", palette["low"]),
        "unknown": ("Not verified", palette["muted"]),
        "info": ("Information only", palette["muted"]),
    }
    cards: list[str] = []
    for key, (name, description) in MODULE_META.items():
        module = (modules or {}).get(key, {})
        status = str(module.get("status", "unknown"))
        label, color = status_map.get(status, (status.title(), palette["muted"]))
        points = int(module.get("points", 0))
        findings = module.get("findings") or []
        detail = ""
        if key == "company":
            registration = module.get("registration") or {}
            if registration.get("message"):
                detail = esc(registration["message"])
        elif key == "threat":
            detail = f"{module.get('report_count') or 0} matching report(s)"
        cards.append(
            f"""
<div class="og-card">
  <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
    <strong style="font-size:15px;">{esc(name)}</strong>
    <span class="og-chip" style="color:{color};border-color:{color};">{esc(label)}</span>
  </div>
  <p class="og-muted" style="margin:8px 0 6px;">{esc(description)}</p>
  <div class="og-chip-row">
    <span class="og-chip">points <b>{points}</b></span>
    <span class="og-chip">findings <b>{len(findings)}</b></span>
  </div>
  {f'<p class="og-muted og-small" style="margin:8px 0 0;">{detail}</p>' if detail else ''}
</div>
"""
        )
    return f"<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;'>{''.join(cards)}</div>"


def finding_card(finding: Any) -> str:
    severity = str(getattr(finding, "severity", "info")).lower()
    return f"""
<div class="og-finding og-finding-{esc(severity)}">
  <div class="og-finding-head">
    <span class="og-mono">{esc(finding.rule_id)}</span>
    <span class="og-chip">{esc(finding.module.title())}</span>
    <span class="og-chip">{esc(finding.severity.title())}</span>
    <span class="og-chip">{int(finding.points)} pts</span>
    <span class="og-chip">confidence: {esc(finding.confidence)}</span>
  </div>
  <div class="og-finding-title">{esc(finding.explanation)}</div>
  {f'<div class="og-evidence">{esc(finding.evidence)}</div>' if finding.evidence else ''}
</div>
"""


def findings_block(findings: Sequence[Any]) -> str:
    if not findings:
        return empty_state("No findings in this view", "Try a different filter.")
    return "".join(finding_card(item) for item in findings)


def status_html(status: str) -> str:
    icon, css, label = STATUS_ICON.get(status, ("&#8212;", "unknown", "Unknown"))
    return f"<span class='og-status-{css}'>{icon} {esc(label)}</span>"


def checks_table(checks: Sequence[dict[str, str]]) -> str:
    if not checks:
        return ""
    rows = []
    for check in checks:
        rows.append(
            "<tr>"
            f"<td>{esc(check.get('label', ''))}</td>"
            f"<td>{status_html(check.get('status', 'unknown'))}</td>"
            f"<td class='og-muted og-small'>{esc(check.get('detail', ''))}</td>"
            "</tr>"
        )
    return "<table><tbody>" + "".join(rows) + "</tbody></table>"


def facts_rows(facts: dict[str, Any]) -> str:
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
        display = esc(value) if value else "<span class='og-muted'>not found</span>"
        rows.append(f"<tr><th>{esc(label)}</th><td>{display}</td></tr>")
    return "<table><tbody>" + "".join(rows) + "</tbody></table>"


def recommendations_html(items: Sequence[str]) -> str:
    if not items:
        return "<p class='og-muted'>No recommendations available.</p>"
    return "<ul class='og-list'>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ul>"


def bullet_list(items: Sequence[str]) -> str:
    return "<ul class='og-list'>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ul>"


def empty_state(title: str, message: str, icon: str = "&#128269;") -> str:
    return f"""
<div class="og-empty">
  <div style="font-size:24px;">{icon}</div>
  <strong>{esc(title)}</strong>
  <span class="og-muted">{esc(message)}</span>
</div>
"""


def stat_card(label: str, value: Any, hint: str = "") -> str:
    hint_html = f"<div class='og-muted og-small'>{esc(hint)}</div>" if hint else ""
    return f"""
<div class="og-card">
  <div class="og-muted og-small">{esc(label)}</div>
  <div style="font-size:26px;font-weight:700;color:var(--og-primary);">{esc(value)}</div>
  {hint_html}
</div>
"""


def disclaimer_card() -> str:
    return """
<div class="og-card" style="border-left:3px solid var(--og-caution);">
  <strong>Important limitation</strong>
  <p class="og-muted" style="margin:6px 0 0;">
    OfferGuard explains <em>why</em> an offer looks risky. It never guarantees that an offer is genuine or fraudulent,
    and a score of 80 does not mean an 80% probability of fraud. Always verify independently through official channels.
  </p>
</div>
"""
