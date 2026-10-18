"""Charts and visual indicators for OfferGuard (pure SVG / CSS, theme aware)."""

from __future__ import annotations

import math
from typing import Any

from components.theme import get_palette


def risk_color(category: str, palette: dict[str, str] | None = None) -> str:
    palette = palette or get_palette("dark")
    return {
        "High": palette["high"],
        "Caution": palette["caution"],
        "Low": palette["low"],
    }.get(category, palette["primary"])


def risk_gauge(score: int, category: str, palette: dict[str, str] | None = None, size: int = 220) -> str:
    """Return an arc gauge as inline SVG that adapts to the active theme."""
    palette = palette or get_palette("dark")
    score = max(0, min(100, int(score)))
    color = risk_color(category, palette)
    radius = 82
    center = 100
    stroke = 16
    circumference = math.pi * radius
    filled = circumference * (score / 100.0)
    track = palette["elevated"]
    text = palette["text"]
    muted = palette["muted"]
    return f"""
<div style="display:flex;justify-content:center;">
<svg width="{size}" height="{int(size * 0.68)}" viewBox="0 0 200 118" role="img"
     aria-label="Risk score {score} out of 100, classification {category}">
  <path d="M 18 100 A {radius} {radius} 0 0 1 182 100"
        fill="none" stroke="{track}" stroke-width="{stroke}" stroke-linecap="round" />
  <path d="M 18 100 A {radius} {radius} 0 0 1 182 100"
        fill="none" stroke="{color}" stroke-width="{stroke}" stroke-linecap="round"
        stroke-dasharray="{filled:.2f} {circumference:.2f}" />
  <text x="{center}" y="78" text-anchor="middle" font-size="40" font-weight="700" fill="{text}">{score}</text>
  <text x="{center}" y="99" text-anchor="middle" font-size="13" fill="{muted}">out of 100</text>
</svg>
</div>
"""


def breakdown_bars(breakdown: dict[str, dict[str, Any]], palette: dict[str, str] | None = None) -> str:
    """Render the score breakdown as theme-aware horizontal bars."""
    palette = palette or get_palette("dark")
    rows: list[str] = []
    for key, item in (breakdown or {}).items():
        cap = max(1, int(item.get("cap", 0)))
        awarded = int(item.get("awarded", 0))
        percent = min(100, round(awarded / cap * 100))
        if awarded == 0:
            color = palette["muted"]
        elif percent >= 70:
            color = palette["high"]
        elif percent >= 35:
            color = palette["caution"]
        else:
            color = palette["low"]
        capped_note = " (capped)" if item.get("capped") else ""
        rows.append(
            f"""
<div style="margin-bottom:10px;">
  <div class="og-bar-row">
    <span>{item.get('label', key)}</span>
    <span><b style="color:{palette['text']};">{awarded}</b> / {cap}{capped_note} &middot; raw {int(item.get('raw', 0))}</span>
  </div>
  <div class="og-bar-track"><div class="og-bar-fill" style="width:{percent}%;background:{color};"></div></div>
</div>
"""
        )
    return "".join(rows)


def module_status_chips(modules: dict[str, dict[str, Any]], palette: dict[str, str] | None = None) -> str:
    """Compact verification-status chips for the header of the results area."""
    palette = palette or get_palette("dark")
    labels = {"letter": "Letter Check", "company": "Company Check", "threat": "Campus Threat Network"}
    map_status = {
        "concerns": (palette["high"], "concerns found"),
        "verified": (palette["low"], "verified"),
        "clear": (palette["low"], "no concerns"),
        "unknown": (palette["muted"], "not verified"),
        "info": (palette["muted"], "information"),
    }
    chips: list[str] = []
    for key, label in labels.items():
        module = (modules or {}).get(key, {})
        status = str(module.get("status", "unknown"))
        color, text = map_status.get(status, (palette["muted"], status))
        chips.append(
            f"<span class='og-chip'><span style='color:{color};'>&#9679;</span> "
            f"<b>{label}</b> {text}</span>"
        )
    return f"<div class='og-chip-row'>{''.join(chips)}</div>"
