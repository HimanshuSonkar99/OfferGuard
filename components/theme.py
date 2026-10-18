"""OfferGuard application theme system.

Streamlit's built-in theme cannot be changed at runtime, so OfferGuard applies a
complete application-level CSS theme on every run. Both palettes use the same
design language, which keeps every page consistent in Dark and Light mode.

The selected theme is stored in st.session_state and persisted to a small local
preference file so it survives browser sessions.
"""

from __future__ import annotations

import json

import streamlit as st

import config

PREFERENCE_FILE = config.BASE_DIR / ".offerguard_prefs.json"

DARK = {
    "name": "dark",
    "label": "Dark mode",
    "bg": "#061525",
    "sidebar_bg": "#04111F",
    "card_bg": "#082238",
    "elevated": "#0B2D45",
    "primary": "#00C8F0",
    "secondary": "#168BFF",
    "text": "#F2F8FF",
    "muted": "#A7C0D8",
    "border": "#124563",
    "high": "#FF514F",
    "caution": "#FFB547",
    "low": "#32D583",
    "glow": "rgba(0, 200, 240, 0.22)",
    "shadow": "0 12px 30px rgba(0, 0, 0, 0.35)",
    "overlay": "rgba(11, 45, 69, 0.72)",
    "is_dark": True,
}

LIGHT = {
    "name": "light",
    "label": "Light mode",
    "bg": "#F3F7FC",
    "sidebar_bg": "#FFFFFF",
    "card_bg": "#FFFFFF",
    "elevated": "#F7FAFE",
    "primary": "#007EAA",
    "secondary": "#1769D2",
    "text": "#10243A",
    "muted": "#52677F",
    "border": "#D8E3EF",
    "high": "#C62828",
    "caution": "#A65B00",
    "low": "#167647",
    "glow": "rgba(23, 105, 210, 0.16)",
    "shadow": "0 10px 24px rgba(16, 36, 58, 0.08)",
    "card_shadow": "0 1px 2px rgba(16, 36, 58, 0.06)",
    "primary_soft": "#E7F1FB",
}

DARK.setdefault("card_shadow", "0 1px 2px rgba(0, 0, 0, 0.25)")
DARK.setdefault("primary_soft", "#0B2D45")

PALETTES: dict[str, dict[str, str]] = {"dark": DARK, "light": LIGHT}


def get_palette(name: str = "dark") -> dict[str, str]:
    return PALETTES.get(name, DARK)


def severity_color(palette: dict[str, str], severity: str) -> str:
    return {
        "high": palette["high"],
        "medium": palette["caution"],
        "low": palette["low"],
        "info": palette["muted"],
    }.get(severity, palette["muted"])


def category_color(palette: dict[str, str], category: str) -> str:
    return {
        "High": palette["high"],
        "Caution": palette["caution"],
        "Low": palette["low"],
    }.get(category, palette["muted"])


def load_preference() -> str:
    """Read the persisted theme preference, defaulting to dark mode."""
    try:
        if PREFERENCE_FILE.exists():
            data = json.loads(PREFERENCE_FILE.read_text(encoding="utf-8"))
            value = str(data.get("theme", "dark")).lower()
            if value in PALETTES:
                return value
    except (OSError, ValueError):
        pass
    return "dark"


def save_preference(name: str) -> None:
    try:
        PREFERENCE_FILE.write_text(json.dumps({"theme": name}), encoding="utf-8")
    except OSError:
        pass


def init_theme_state() -> None:
    """Initialise the theme in session state, restoring the saved preference once."""
    if "theme" not in st.session_state:
        st.session_state["theme"] = load_preference()


def set_theme(name: str) -> None:
    if name not in PALETTES:
        name = "dark"
    st.session_state["theme"] = name
    save_preference(name)


def toggle_theme() -> None:
    current = st.session_state.get("theme", "dark")
    set_theme("light" if current == "dark" else "dark")


def build_css(palette: dict[str, str]) -> str:
    """Build the complete application CSS for a palette."""
    css = """
<style>
:root {
  --og-bg: __BG__;
  --og-sidebar: __SIDEBAR__;
  --og-card: __CARD__;
  --og-elevated: __ELEVATED__;
  --og-primary: __PRIMARY__;
  --og-secondary: __SECONDARY__;
  --og-text: __TEXT__;
  --og-muted: __MUTED__;
  --og-border: __BORDER__;
  --og-high: __HIGH__;
  --og-caution: __CAUTION__;
  --og-low: __LOW__;
  --og-shadow: __SHADOW__;
  --og-glow: __GAP__;
  --og-card-shadow: __CARDSHADOW__;
  --og-soft: __SOFT__;
}

html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
  background: var(--og-bg) !important;
  color: var(--og-text) !important;
  font-family: "Segoe UI", "Inter", system-ui, -apple-system, sans-serif;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stToolbar"] { right: 1rem; }
[data-testid="stAppViewContainer"] > .main { background: transparent; }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1500px; }

/* Sidebar */
section[data-testid="stSidebar"] {
  background: var(--og-sidebar) !important;
  border-right: 1px solid var(--og-border);
}
section[data-testid="stSidebar"] * { color: var(--og-text); }
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color: var(--og-text); }
section[data-testid="stSidebar"] hr { border-color: var(--og-border); }
[data-testid="stSidebarNav"] { display: none; }

/* Typography */
h1, h2, h3, h4, h5, h6 { color: var(--og-text) !important; letter-spacing: -0.01em; }
p, span, label, li, div { color: var(--og-text); }
a { color: var(--og-primary) !important; }
code {
  background: var(--og-elevated) !important;
  color: var(--og-primary) !important;
  border: 1px solid var(--og-border);
  border-radius: 6px;
  padding: 1px 5px;
}

/* Buttons */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button,
button[data-testid="stBaseButton-secondary"], button[data-testid="stBaseButton-primary"] {
  border-radius: 10px !important;
  font-weight: 600 !important;
  border: 1px solid var(--og-border) !important;
  background: var(--og-elevated) !important;
  color: var(--og-text) !important;
  transition: transform 0.08s ease, box-shadow 0.15s ease, background 0.15s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {
  border-color: var(--og-primary) !important;
  color: var(--og-primary) !important;
  box-shadow: 0 0 0 3px var(--og-glow);
}
button[kind="primary"], button[data-testid="stBaseButton-primary"] {
  background: linear-gradient(135deg, var(--og-primary), var(--og-secondary)) !important;
  color: __PRIMARY_TEXT__ !important;
  border: none !important;
}
button[kind="primary"]:hover, button[data-testid="stBaseButton-primary"]:hover {
  color: __PRIMARY_TEXT__ !important;
  box-shadow: 0 6px 20px var(--og-glow);
}
button:disabled, button[disabled] { opacity: 0.5 !important; }

/* Inputs */
input, textarea, [data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div {
  background: var(--og-elevated) !important;
  color: var(--og-text) !important;
  border-color: var(--og-border) !important;
  border-radius: 10px !important;
}
input::placeholder, textarea::placeholder { color: var(--og-muted) !important; }
[data-testid="stFileUploaderDropzone"] {
  background: var(--og-card) !important;
  border: 1.5px dashed var(--og-border) !important;
  border-radius: 14px !important;
}
[data-testid="stFileUploaderDropzone"]:hover { border-color: var(--og-primary) !important; }
[data-testid="stFileUploaderDropzoneInstructions"] * { color: var(--og-muted) !important; }
[data-testid="stWidgetLabel"] p, [data-testid="stWidgetLabel"] label { color: var(--og-text) !important; }

/* Cards and containers */
div[data-testid="stVerticalBlockBorderWrapper"] {
  background: var(--og-card) !important;
  border: 1px solid var(--og-border) !important;
  border-radius: 16px !important;
  box-shadow: var(--og-card-shadow);
  padding: 2px;
}
[data-testid="stExpander"] details {
  background: var(--og-card) !important;
  border: 1px solid var(--og-border) !important;
  border-radius: 14px !important;
}
[data-testid="stExpander"] summary { color: var(--og-text) !important; }
[data-testid="stExpander"] summary:hover { color: var(--og-primary) !important; }

/* Alerts */
[data-testid="stAlert"] {
  background: var(--og-elevated) !important;
  border: 1px solid var(--og-border) !important;
  border-radius: 12px !important;
}
[data-testid="stAlert"] * { color: var(--og-text) !important; }
[data-testid="stAlert"] svg { fill: var(--og-primary) !important; }

/* Tabs */
[data-testid="stTabs"] [role="tablist"] { border-bottom: 1px solid var(--og-border); gap: 4px; }
[data-testid="stTabs"] button[role="tab"] {
  color: var(--og-muted) !important;
  border-radius: 10px 10px 0 0;
  padding: 6px 14px;
}
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
  color: var(--og-primary) !important;
  background: var(--og-elevated) !important;
  border-bottom: 2px solid var(--og-primary) !important;
}

/* Metrics */
[data-testid="stMetric"] {
  background: var(--og-card) !important;
  border: 1px solid var(--og-border) !important;
  border-radius: 14px !important;
  padding: 12px 16px !important;
}
[data-testid="stMetricValue"] { color: var(--og-text) !important; }
[data-testid="stMetricLabel"] * { color: var(--og-muted) !important; }

/* Tables / dataframes */
[data-testid="stDataFrame"], [data-testid="stTable"] {
  background: var(--og-card) !important;
  border: 1px solid var(--og-border) !important;
  border-radius: 12px !important;
  overflow: hidden;
}
table { color: var(--og-text); }
table th { background: var(--og-elevated) !important; color: var(--og-text) !important; }
table td, table th { border-color: var(--og-border) !important; }

/* Radio / checkbox / toggle / selectbox menus */
[role="radiogroup"] label, [data-testid="stCheckbox"] label, [data-testid="stToggle"] label {
  color: var(--og-text) !important;
}
ul[data-testid="stSelectboxVirtualDropdown"] li, [role="option"] {
  background: var(--og-card) !important;
  color: var(--og-text) !important;
}
[role="option"]:hover { background: var(--og-elevated) !important; }
[data-baseweb="popover"] div { background: var(--og-card) !important; color: var(--og-text) !important; }
[data-testid="stProgress"] div[role="progressbar"] > div { background: var(--og-primary) !important; }
hr { border-color: var(--og-border) !important; }
[data-testid="stCaptionContainer"] * { color: var(--og-muted) !important; }

/* ---------------- OfferGuard custom components ---------------- */
.og-logo { display: flex; align-items: center; gap: 10px; }
.og-wordmark { font-size: 22px; font-weight: 700; color: var(--og-text); letter-spacing: -0.02em; }
.og-wordmark span { color: var(--og-primary); }
.og-tag { color: var(--og-muted); font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; }
.og-mission { color: var(--og-muted); font-size: 12px; line-height: 1.5; }

.og-hero {
  background: linear-gradient(135deg, __CARD_GRADIENT_FROM__, __CARD_GRADIENT_TO__);
  border: 1px solid var(--og-border);
  border-radius: 18px;
  padding: 22px 26px;
  box-shadow: var(--og-shadow);
}
.og-hero h1 { margin: 0; font-size: 30px; }
.og-hero p { margin: 6px 0 0; color: var(--og-muted); }

.og-card {
  background: var(--og-card);
  border: 1px solid var(--og-border);
  border-radius: 16px;
  padding: 18px 20px;
  box-shadow: var(--og-card-shadow);
  height: 100%;
}
.og-card h3 { margin: 0 0 4px; font-size: 16px; }
.og-card .og-muted { color: var(--og-muted); font-size: 13px; }
.og-card-accent { border-left: 3px solid var(--og-primary); }

.og-grid { display: grid; gap: 14px; }
.og-kpi { display: flex; flex-direction: column; gap: 2px; }
.og-kpi .og-kpi-value { font-size: 28px; font-weight: 700; color: var(--og-primary); }
.og-kpi .og-kpi-label { font-size: 12px; color: var(--og-muted); text-transform: uppercase; letter-spacing: 0.05em; }

.og-badge {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: 12px; font-weight: 700; letter-spacing: 0.03em;
  border: 1px solid transparent;
}
.og-badge-high { background: __HIGH_BG__; color: var(--og-high); border-color: var(--og-high); }
.og-badge-caution { background: __CAUTION_BG__; color: var(--og-caution); border-color: var(--og-caution); }
.og-badge-low { background: __LOW_BG__; border-color: var(--og-low); color: var(--og-low); }
.og-pill {
  display: inline-block; padding: 3px 10px; border-radius: 999px;
  background: var(--og-elevated); border: 1px solid var(--og-border);
  color: var(--og-muted); font-size: 12px; margin: 0 6px 6px 0;
}

.og-steps { display: flex; gap: 12px; flex-wrap: wrap; margin: 6px 0 18px; }
.og-step {
  flex: 1 1 180px;
  background: var(--og-card);
  border: 1px solid var(--og-border);
  border-radius: 14px;
  padding: 12px 16px;
}
.og-step .og-step-num {
  display: inline-flex; align-items: center; justify-content: center;
  width: 22px; height: 22px; border-radius: 50%;
  background: var(--og-elevated); color: var(--og-muted);
  font-size: 12px; font-weight: 700; margin-right: 8px;
}
.og-step-title { font-weight: 600; font-size: 14px; }
.og-step-desc { color: var(--og-muted); font-size: 12px; margin-top: 4px; }
.og-step.og-active { border-color: var(--og-primary); box-shadow: 0 0 0 3px var(--og-glow); }
.og-step.og-active .og-step-num { background: var(--og-primary); color: __PRIMARY_TEXT__; }
.og-step.og-done .og-step-num { background: var(--og-low); color: __PRIMARY_TEXT__; }

.og-finding {
  background: var(--og-elevated);
  border: 1px solid var(--og-border);
  border-left: 3px solid var(--og-primary);
  border-radius: 10px;
  padding: 10px 14px;
  margin-bottom: 8px;
}
.og-finding-high { border-left-color: var(--og-high); }
.og-finding-medium { border-left-color: var(--og-caution); }
.og-finding-low { border-left-color: var(--og-low); }
.og-finding-info { border-left-color: var(--og-muted); }
.og-finding-head { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-size: 12px; color: var(--og-muted); }
.og-finding-title { font-weight: 600; color: var(--og-text); font-size: 14px; }
.og-finding p { margin: 4px 0 0; font-size: 13px; }
.og-evidence {
  font-family: "Consolas", "Menlo", monospace; font-size: 12px;
  color: var(--og-muted); background: var(--og-card);
  border: 1px dashed var(--og-border); border-radius: 8px;
  padding: 6px 8px; margin-top: 6px; word-break: break-word;
}

.og-bar-track {
  background: var(--og-elevated); border: 1px solid var(--og-border);
  border-radius: 8px; height: 12px; overflow: hidden;
}
.og-bar-fill { height: 100%; border-radius: 8px; }
.og-bar-row { display: flex; justify-content: space-between; font-size: 12px; color: var(--og-muted); margin-bottom: 4px; }

.og-kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.og-empty {
  text-align: center; padding: 28px 18px; border: 1px dashed var(--og-border);
  border-radius: 14px; background: var(--og-card); color: var(--og-muted);
}
.og-empty strong { color: var(--og-text); display: block; margin-bottom: 4px; }

.og-chip-row { display: flex; flex-wrap: wrap; gap: 8px; }
.og-chip {
  display: inline-flex; align-items: center; gap: 6px;
  background: var(--og-elevated); border: 1px solid var(--og-border);
  border-radius: 999px; padding: 4px 12px; font-size: 12px; color: var(--og-muted);
}
.og-chip b { color: var(--og-text); font-weight: 600; }
.og-status-pass { color: var(--og-low) !important; }
.og-status-fail { color: var(--og-high) !important; }
.og-status-warn { color: var(--og-caution) !important; }
.og-status-unknown { color: var(--og-muted) !important; }

.og-list { margin: 6px 0 0 18px; padding: 0; }
.og-list li { margin-bottom: 6px; font-size: 13.5px; line-height: 1.45; }
.og-divider { height: 1px; background: var(--og-border); margin: 14px 0; border: 0; }
.og-muted { color: var(--og-muted); font-size: 13px; }
.og-small { font-size: 12px; }
.og-mono { font-family: "Consolas", "Menlo", monospace; font-size: 12px; }
</style>
"""
    gradient_from = palette["elevated"] if palette["name"] == "dark" else "#EAF3FD"
    gradient_to = palette["card_bg"]
    primary_text = "#04111F" if palette["name"] == "dark" else "#FFFFFF"
    replacements = {
        "__BG__": palette["bg"],
        "__SIDEBAR__": palette["sidebar_bg"],
        "__CARD__": palette["card_bg"],
        "__ELEVATED__": palette["elevated"],
        "__PRIMARY__": palette["primary"],
        "__SECONDARY__": palette["secondary"],
        "__TEXT__": palette["text"],
        "__MUTED__": palette["muted"],
        "__BORDER__": palette["border"],
        "__HIGH__": palette["high"],
        "__CAUTION__": palette["caution"],
        "__LOW__": palette["low"],
        "__SHADOW__": palette["shadow"],
        "__CARDSHADOW__": palette["card_shadow"],
        "__SOFT__": palette["primary_soft"],
        "__GAP__": palette["glow"],
        "__PRIMARY_TEXT__": primary_text,
        "__CARD_GRADIENT_FROM__": gradient_from,
        "__CARD_GRADIENT_TO__": gradient_to,
    }
    for token, value in replacements.items():
        css = css.replace(token, value)
    return css


def apply_theme(name: str = None) -> dict[str, str]:
    """Inject the CSS for the active theme and return its palette."""
    palette = get_palette(name or st.session_state.get("theme", "dark"))
    st.markdown(build_css(palette), unsafe_allow_html=True)
    return palette


def theme_toggle_widget() -> None:
    """Sidebar theme switch that applies immediately and persists locally."""
    current = st.session_state.get("theme", "dark")
    is_dark = current == "dark"
    columns = st.columns([3, 1])
    with columns[0]:
        st.markdown(
            f"<div class='og-small' style='padding-top:6px;'>"
            f"{'🌙' if is_dark else '☀️'} {get_palette(current)['label']}</div>",
            unsafe_allow_html=True,
        )
    with columns[1]:
        clicked = st.button(
            "☀️" if is_dark else "🌙",
            key="theme_toggle_button",
            help="Switch between Dark and Light mode",
            use_container_width=True,
        )
    if clicked:
        toggle_theme()
        st.rerun()
