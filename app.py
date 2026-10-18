"""OfferGuard - AI Verifier for Fake Internship & Job Offers.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import logging
from typing import Any

import streamlit as st

import config
from components import charts, theme
from components import ui_components as ui
from database import repository
from database.models import AnalysisResult
from services import report_builder
from services.document_parser import DocumentError
from services.normalizer import registered_domain
from services.pipeline import run_analysis_from_bytes, run_analysis_from_text

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("offerguard")

st.set_page_config(
    page_title="OfferGuard | Verify Before You Pay",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAV_ITEMS = [
    ("home", "Home"),
    ("verify", "Verify an Offer"),
    ("threat", "Campus Threat Network"),
    ("report", "Report a Suspicious Offer"),
    ("history", "Analysis History"),
    ("about", "About & Safety"),
]

FINDING_FILTERS = {
    "All findings": None,
    "Letter Check": "letter",
    "Company Check": "company",
    "Threat Network": "threat",
}

STATUS_BADGE = {
    "submitted": "Submitted",
    "under_review": "Under review",
    "corroborated": "Corroborated",
    "rejected": "Rejected",
}


# --------------------------------------------------------------------------- #
# Session helpers
# --------------------------------------------------------------------------- #
def initialise_state() -> None:
    theme.init_theme_state()
    st.session_state.setdefault("page", "home")
    st.session_state.setdefault("analysis", None)
    st.session_state.setdefault("flash", None)
    st.session_state.setdefault("allow_external", config.EXTERNAL_LOOKUPS_ENABLED)
    repository.seed_database()


def go(page_id: str) -> None:
    st.session_state["page"] = page_id
    st.rerun()


def set_flash(message: str, level: str = "error") -> None:
    """Queue a one-shot message that survives the rerun triggered by navigation."""
    st.session_state["flash"] = {"message": message, "level": level}


def render_flash() -> None:
    flash = st.session_state.pop("flash", None)
    if not flash:
        return
    message = str(flash.get("message", "")) if isinstance(flash, dict) else str(flash)
    level = flash.get("level", "error") if isinstance(flash, dict) else "error"
    if not message:
        return
    {"error": st.error, "success": st.success, "info": st.info}.get(level, st.error)(message)


def current_analysis():
    stored = st.session_state.get("analysis")
    if isinstance(stored, AnalysisResult):
        return stored
    if isinstance(stored, dict):
        return AnalysisResult.from_dict(stored)
    return None


def clear_upload() -> None:
    st.session_state["offer_file"] = None
    st.session_state["flash"] = None


def start_new_analysis() -> None:
    st.session_state["analysis"] = None
    st.session_state["offer_file"] = None
    st.session_state["manual_text"] = ""


def page_header(title: str, description: str) -> None:
    st.markdown(
        f"""
<div class="og-hero" style="margin-bottom:16px;">
  <h1>{ui.esc(title)}</h1>
  <p>{ui.esc(description)}</p>
</div>
""",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Built-in demo samples
# --------------------------------------------------------------------------- #
SAMPLE_LETTERS = (
    ("fee_scam_letter.txt", "Fee scam with a matching Campus Threat Network report"),
    ("lookalike_letter.txt", "Lookalike sender domain impersonating a well-known company"),
)


def run_sample_analysis(filename: str, label: str) -> None:
    """Analyse a bundled fictional sample letter and jump straight to the results."""
    path = config.DATA_DIR / "samples" / filename
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        logger.error("Sample letter could not be read: %s", path)
        set_flash("The built-in sample letter could not be loaded.")
        st.rerun()
        return
    st.session_state["manual_text"] = text
    with st.spinner("Running the three verification layers on the built-in sample..."):
        try:
            result = run_analysis_from_text(
                text,
                allow_external=st.session_state.get("allow_external", True),
            )
        except Exception:
            logger.exception("Sample analysis failed for %s", filename)
            set_flash("Something went wrong while analysing the built-in sample.")
            st.rerun()
            return
    st.session_state["analysis"] = result
    set_flash(f"Demo run complete: {label}. This letter is fictional sample data.", "info")
    go("results")


# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
def render_sidebar(palette: dict[str, str]) -> None:
    with st.sidebar:
        st.markdown(ui.brand_block(palette), unsafe_allow_html=True)
        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

        active = st.session_state.get("page", "home")
        for page_id, label in NAV_ITEMS:
            clicked = st.button(
                label,
                key=f"nav_{page_id}",
                use_container_width=True,
                type="primary" if page_id == active else "secondary",
            )
            if clicked and page_id != active:
                go(page_id)

        st.markdown("<hr class='og-divider'>", unsafe_allow_html=True)
        theme.theme_toggle_widget()
        st.markdown("<hr class='og-divider'>", unsafe_allow_html=True)
        st.markdown(
            """
<div class="og-mission">
  <strong style="color:var(--og-text);">Our mission</strong><br>
  OfferGuard is a student safety tool that helps identify recruitment-fee fraud through
  transparent, explainable checks. It never guarantees that an offer is genuine or fraudulent.
</div>
""",
            unsafe_allow_html=True,
        )
        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        st.caption("Documents are processed in memory and never stored.")
        st.caption("Demo records are fictional and clearly labelled.")


# --------------------------------------------------------------------------- #
# Page: Home
# --------------------------------------------------------------------------- #
def render_home(palette: dict[str, str]) -> None:
    stats = repository.get_stats()
    st.markdown(
        ui.hero(
            "OfferGuard",
            config.APP_SUBTITLE,
            "Upload an offer letter and get an explainable risk assessment from three verification layers. "
            "OfferGuard shows exactly which words, domains and reported incidents raised a concern, so you can "
            "verify before you pay.",
        ),
        unsafe_allow_html=True,
    )

    left, right = st.columns([1, 3])
    with left:
        if st.button("Verify an Offer", type="primary", use_container_width=True):
            go("verify")
    with right:
        if st.button("Review the Campus Threat Network", use_container_width=True):
            go("threat")

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.markdown(ui.workflow_indicator("upload"), unsafe_allow_html=True)

    st.subheader("Three verification layers")
    cards = []
    for key, (name, description) in ui.MODULE_META.items():
        cards.append(
            f"""
<div class="og-card">
  <strong style="font-size:15px;">{ui.esc(name)}</strong>
  <p class="og-muted" style="margin:8px 0 0;">{ui.esc(description)}</p>
</div>
"""
        )
    st.markdown(
        "<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;'>"
        + "".join(cards)
        + "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.subheader("Live activity from this installation")
    stat_columns = st.columns(4)
    with stat_columns[0]:
        st.markdown(
            ui.stat_card("Analyses stored", stats["analyses"], "Every run saved in SQLite"), unsafe_allow_html=True
        )
    with stat_columns[1]:
        st.markdown(
            ui.stat_card("Student reports", stats["user_reports"], "Submitted through OfferGuard"),
            unsafe_allow_html=True,
        )
    with stat_columns[2]:
        st.markdown(
            ui.stat_card("Total reports", stats["reports"], "Includes labelled demo records"), unsafe_allow_html=True
        )
    with stat_columns[3]:
        st.markdown(ui.stat_card("Maximum score", config.MAX_SCORE, "Heuristic, bounded 0-100"), unsafe_allow_html=True)

    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    st.subheader("Recent analysis activity")
    recent = repository.list_analyses(limit=5)
    if not recent:
        st.markdown(
            ui.empty_state("No analyses yet", "Run your first verification to see activity here."),
            unsafe_allow_html=True,
        )
    else:
        for row in recent:
            st.markdown(
                f"""
<div class="og-card" style="margin-bottom:8px;">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
    <span><strong>{ui.esc(row['company_name'])}</strong>
      <span class="og-muted og-small">&middot; {ui.esc(row['analysis_id'])}</span></span>
    <span class="og-chip">score <b>{int(row['score'])}</b> &middot; {ui.esc(row['risk_category'])}</span>
  </div>
  <div class="og-muted og-small" style="margin-top:6px;">{ui.esc(str(row['created_at'])[:19].replace('T', ' '))} UTC</div>
</div>
""",
                unsafe_allow_html=True,
            )

    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
    st.info(config.PRIVACY_NOTICE)
    st.markdown(ui.disclaimer_card(), unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Page: Verify
# --------------------------------------------------------------------------- #
def render_verify(palette: dict[str, str]) -> None:
    page_header(
        "Verify an Offer",
        "Upload the offer letter as a PDF, PNG or JPG, or paste the text. Analysis starts only when you press the button.",
    )
    st.markdown(ui.workflow_indicator("upload"), unsafe_allow_html=True)

    with st.container(border=True):
        st.markdown("**No file handy? Run a built-in demo letter**")
        st.caption(
            "Two fictional samples ship with OfferGuard, so a full analysis can be shown in one click. "
            "The letters are loaded into the paste box below, so you can read and edit them afterwards."
        )
        demo_columns = st.columns(2)
        with demo_columns[0]:
            if st.button(
                "Demo 1: fee scam + threat report",
                key="demo_fee",
                use_container_width=True,
                help=SAMPLE_LETTERS[0][1],
            ):
                run_sample_analysis(*SAMPLE_LETTERS[0])
                return
        with demo_columns[1]:
            if st.button(
                "Demo 2: lookalike sender domain",
                key="demo_lookalike",
                use_container_width=True,
                help=SAMPLE_LETTERS[1][1],
            ):
                run_sample_analysis(*SAMPLE_LETTERS[1])
                return

    limit_mb = config.MAX_FILE_SIZE_BYTES // (1024 * 1024)
    tab_upload, tab_text = st.tabs(["Upload a file", "Paste text manually"])

    with tab_upload:
        with st.container(border=True):
            uploaded = st.file_uploader(
                "Offer letter file",
                type=["pdf", "png", "jpg", "jpeg"],
                key="offer_file",
                help=f"Maximum {limit_mb} MB. PDF, PNG, JPG or JPEG only. Page limit {config.MAX_PDF_PAGES}.",
            )
            if uploaded is not None:
                size_mb = len(uploaded.getbuffer()) / (1024 * 1024)
                columns = st.columns([3, 1])
                with columns[0]:
                    st.markdown(
                        "<div class='og-chip-row'><span class='og-chip'><b>"
                        + ui.esc(uploaded.name)
                        + f"</b> &middot; {size_mb:.2f} MB</span></div>",
                        unsafe_allow_html=True,
                    )
                with columns[1]:
                    st.button("Remove file", on_click=clear_upload, use_container_width=True)
            else:
                st.caption(
                    f"Supported: PDF, PNG, JPG, JPEG. Maximum {limit_mb} MB, up to {config.MAX_PDF_PAGES} pages."
                )

            analyze_file = st.button("Analyze Offer", type="primary", key="analyze_file")

        if analyze_file:
            if uploaded is None:
                set_flash("Choose a PDF, PNG or JPG file before analysing.")
                st.rerun()
            with st.spinner("Reading the document and running the three verification layers..."):
                try:
                    result = run_analysis_from_bytes(
                        uploaded.name,
                        uploaded.getvalue(),
                        facts_override=collect_overrides(),
                        allow_external=st.session_state.get("allow_external", True),
                    )
                except DocumentError as exc:
                    set_flash(str(exc))
                    st.rerun()
                except Exception:
                    logger.exception("Analysis failed for uploaded file %s", getattr(uploaded, "name", "?"))
                    set_flash(
                        "Something went wrong while analysing this document. "
                        "Try a different file or paste the text manually."
                    )
                    st.rerun()
                else:
                    st.session_state["analysis"] = result
                    go("results")

    with tab_text:
        with st.container(border=True):
            st.text_area(
                "Offer letter text",
                key="manual_text",
                height=220,
                placeholder="Paste the offer letter text here, including any payment, fee or bond wording.",
            )
            analyze_text = st.button("Analyze pasted text", type="primary", key="analyze_text")

        if analyze_text:
            if not (st.session_state.get("manual_text") or "").strip():
                set_flash("Paste the offer letter text before analysing.")
                st.rerun()
            with st.spinner("Running the three verification layers..."):
                try:
                    result = run_analysis_from_text(
                        st.session_state["manual_text"],
                        facts_override=collect_overrides(),
                        allow_external=st.session_state.get("allow_external", True),
                    )
                except DocumentError as exc:
                    set_flash(str(exc))
                    st.rerun()
                except Exception:
                    logger.exception("Analysis failed for pasted text input")
                    set_flash(
                        "Something went wrong while analysing this text. "
                        "Try shortening the pasted text or using a file upload."
                    )
                    st.rerun()
                else:
                    st.session_state["analysis"] = result
                    go("results")

    with st.expander("Optional: correct the extracted details"):
        st.caption(
            "If the letter omits a detail or OCR misread it, enter the correct value here. These values are used "
            "by the Company Check and Campus Threat Network layers of the next analysis."
        )
        columns = st.columns(3)
        with columns[0]:
            st.text_input("Company name", key="override_company", placeholder="e.g. Acme Technologies Pvt Ltd")
        with columns[1]:
            st.text_input("Sender email", key="override_email", placeholder="e.g. hr@acme.com")
        with columns[2]:
            st.text_input("Sender domain", key="override_domain", placeholder="e.g. acme.com")

    with st.expander("Verification settings and privacy"):
        st.checkbox(
            "Allow external domain-registration lookup (RDAP, requires internet)",
            key="allow_external",
            help="Only the sender domain is sent to rdap.org. Disable this to run completely offline.",
        )
        st.markdown(
            "- Files and links inside the document are never executed or opened.\n"
            "- The original document is processed in memory and is never saved.\n"
            "- Only extracted facts, findings and the score are written to the local SQLite database."
        )


def collect_overrides() -> dict[str, Any]:
    """Read the optional correction fields. Returns only values the user actually typed."""
    overrides: dict[str, Any] = {}
    company = (st.session_state.get("override_company") or "").strip()
    email = (st.session_state.get("override_email") or "").strip()
    domain = (st.session_state.get("override_domain") or "").strip()
    if company:
        overrides["company_name"] = company
    if email:
        overrides["sender_email"] = email
        overrides["sender_domain"] = registered_domain(email)
    if domain:
        overrides["sender_domain"] = domain
    return overrides


# --------------------------------------------------------------------------- #
# Page: Results
# --------------------------------------------------------------------------- #
def render_results(palette: dict[str, str]) -> None:
    analysis = current_analysis()
    if analysis is None:
        st.markdown(
            ui.empty_state("No analysis selected", "Run a verification, or open one from Analysis History."),
            unsafe_allow_html=True,
        )
        if st.button("Go to Verify an Offer", type="primary"):
            go("verify")
        return

    st.markdown(ui.workflow_indicator("results"), unsafe_allow_html=True)
    main_column, side_column = st.columns([2.1, 1])

    with main_column:
        with st.container(border=True):
            gauge_column, summary_column = st.columns([1, 1.4])
            with gauge_column:
                st.markdown(
                    charts.risk_gauge(analysis.score, analysis.risk_category, palette), unsafe_allow_html=True
                )
            with summary_column:
                st.markdown(
                    f"""
<div class="og-chip-row" style="margin-bottom:8px;">
  <span class="og-chip">Analysis ID <b>{ui.esc(analysis.analysis_id)}</b></span>
  <span class="og-chip">{ui.esc(str(analysis.created_at)[:19].replace('T', ' '))}</span>
</div>
<div style="font-size:22px;font-weight:700;">Score {int(analysis.score)}/100
  <span class="og-chip" style="margin-left:6px;">{ui.esc(analysis.risk_category)} risk</span>
</div>
<p class="og-muted" style="margin-top:8px;">{ui.esc(analysis.summary)}</p>
""",
                    unsafe_allow_html=True,
                )
                st.markdown(charts.module_status_chips(analysis.module_results, palette), unsafe_allow_html=True)

        warnings = (analysis.extraction or {}).get("warnings") or []
        if warnings:
            st.warning("Extraction notes: " + " ".join(warnings))
        if not (analysis.extraction or {}).get("success", True):
            st.error("The document text could not be fully extracted, so some checks may be incomplete.")

        st.subheader("Verification layers")
        st.markdown(ui.module_cards(analysis.module_results, palette), unsafe_allow_html=True)

        with st.expander("Company Check verification status", expanded=False):
            checks = (analysis.module_results.get("company") or {}).get("checks") or []
            if checks:
                st.markdown(ui.checks_table(checks), unsafe_allow_html=True)
            else:
                st.markdown("<p class='og-muted'>No company checks were recorded.</p>", unsafe_allow_html=True)
            reference = (analysis.module_results.get("company") or {}).get("reference")
            if reference:
                st.caption(
                    f"Reference source: {reference.get('source', 'unknown')} "
                    f"(recorded {reference.get('verified_at', 'date unknown')})"
                )

        st.subheader("Detailed findings")
        filter_label = st.radio(
            "Finding filter",
            options=list(FINDING_FILTERS.keys()),
            horizontal=True,
            key="finding_filter",
            label_visibility="collapsed",
        )
        module_key = FINDING_FILTERS.get(filter_label)
        shown = [item for item in analysis.findings if module_key is None or item.module == module_key]
        st.caption(f"{len(shown)} of {len(analysis.findings)} findings shown")
        st.markdown(ui.findings_block(shown), unsafe_allow_html=True)

        st.subheader("Score breakdown")
        st.markdown(charts.breakdown_bars(analysis.score_breakdown, palette), unsafe_allow_html=True)
        st.caption(
            "Each category is capped at its allocation. Raw points show what the findings would have scored before capping."
        )

    with side_column:
        with st.container(border=True):
            st.markdown("<strong>Recommended actions</strong>", unsafe_allow_html=True)
            st.markdown(ui.recommendations_html(analysis.recommendations), unsafe_allow_html=True)

        with st.container(border=True):
            st.markdown("<strong>Extracted information</strong>", unsafe_allow_html=True)
            st.markdown(ui.facts_rows(analysis.extracted_facts), unsafe_allow_html=True)

        with st.container(border=True):
            st.markdown("<strong>Next steps</strong>", unsafe_allow_html=True)
            if st.button("Report this suspicious offer", use_container_width=True, key="results_report"):
                go("report")
            html_report = report_builder.build_report_html(analysis)
            text_report = report_builder.build_report_text(analysis)
            st.download_button(
                "Download report (HTML)",
                data=html_report,
                file_name=report_builder.report_filename(analysis, "html"),
                mime="text/html",
                use_container_width=True,
            )
            st.download_button(
                "Download report (TXT)",
                data=text_report,
                file_name=report_builder.report_filename(analysis, "txt"),
                mime="text/plain",
                use_container_width=True,
            )
            if st.button("New analysis", on_click=start_new_analysis, use_container_width=True):
                go("verify")

    st.markdown(ui.disclaimer_card(), unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Page: Campus Threat Network
# --------------------------------------------------------------------------- #
def render_threat(palette: dict[str, str]) -> None:
    page_header(
        "Campus Threat Network",
        "Search reports submitted by students. Domain matches are stronger evidence than company-name matches, "
        "and an unverified report is never treated as proof of fraud.",
    )

    total = repository.count_reports(include_demo=True)
    user_reports = repository.count_reports(include_demo=False)
    demo_reports = total - user_reports
    columns = st.columns(4)
    with columns[0]:
        st.markdown(ui.stat_card("Reports stored", total), unsafe_allow_html=True)
    with columns[1]:
        st.markdown(ui.stat_card("Submitted here", user_reports), unsafe_allow_html=True)
    with columns[2]:
        st.markdown(ui.stat_card("Demonstration data", demo_reports, "Fictional records"), unsafe_allow_html=True)
    with columns[3]:
        st.markdown(ui.stat_card("Categories", len(config.REPORT_CATEGORIES)), unsafe_allow_html=True)

    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
    with st.container(border=True):
        filter_columns = st.columns([2, 1, 1])
        with filter_columns[0]:
            search = st.text_input("Search by company or domain", key="threat_search", placeholder="e.g. acme or acme-hiring.example")
        with filter_columns[1]:
            category = st.selectbox("Category", ["All categories"] + config.REPORT_CATEGORIES, key="threat_category")
        with filter_columns[2]:
            status_labels = ["All statuses"] + [STATUS_BADGE[item] for item in config.REPORT_STATUSES]
            status_label = st.selectbox("Moderation status", status_labels, key="threat_status")

    category_value = "" if category == "All categories" else category
    status_value = ""
    if status_label != "All statuses":
        status_value = next(key for key, value in STATUS_BADGE.items() if value == status_label)

    reports = repository.list_reports(search=search, category=category_value, status=status_value)
    st.caption(f"{len(reports)} report(s) match the current filters.")

    if not reports:
        st.markdown(
            ui.empty_state(
                "No matching reports",
                "Try a different search term, or submit the first report about this company.",
            ),
            unsafe_allow_html=True,
        )
        return

    for report in reports:
        demo_badge = (
            "<span class='og-chip' style='border-color:var(--og-caution);color:var(--og-caution);'>"
            "demonstration data</span>"
            if report["is_demo"]
            else "<span class='og-chip'>student submission</span>"
        )
        title = report["company_name"] or "Unknown company"
        status_label_text = STATUS_BADGE.get(report["status"], report["status"])
        st.markdown(
            f"""
<div class="og-card" style="margin-bottom:10px;">
  <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
    <strong>{ui.esc(title)}</strong>
    <span class="og-chip-row">
      <span class="og-chip">{ui.esc(status_label_text)}</span>
      {demo_badge}
    </span>
  </div>
  <div class="og-chip-row" style="margin-top:8px;">
    <span class="og-chip">domain <b>{ui.esc(report['sender_domain'] or 'not provided')}</b></span>
    <span class="og-chip">category <b>{ui.esc(report['category'])}</b></span>
    <span class="og-chip">incident <b>{ui.esc(report['incident_date'] or 'unknown')}</b></span>
  </div>
  <p style="margin:10px 0 0;font-size:13.5px;">{ui.esc(report['description'])}</p>
</div>
""",
            unsafe_allow_html=True,
        )

    st.info(
        "Reports are student-reported observations. A matching report raises concern and helps you ask better "
        "questions, but only corroborated reports carry higher confidence, and none of them is a legal finding of fraud."
    )


# --------------------------------------------------------------------------- #
# Page: Report a Suspicious Offer
# --------------------------------------------------------------------------- #
def render_report(palette: dict[str, str]) -> None:
    page_header(
        "Report a Suspicious Offer",
        "Your report helps other students recognise a scam pattern. Do not include passwords, bank details or "
        "identity documents.",
    )

    report_ref = st.session_state.pop("report_success", None)
    if report_ref is not None:
        st.success(
            "Thank you. Your report was saved and will be used for matching future analyses."
            + (f" Reference #{report_ref}." if report_ref else "")
        )

    repository.seed_database()
    with st.form("report_form", clear_on_submit=True):
        columns = st.columns(2)
        with columns[0]:
            company = st.text_input("Company name *", placeholder="As written in the offer letter")
        with columns[1]:
            domain = st.text_input("Sender email or domain (optional)", placeholder="hr@example.com or example.com")

        category = st.selectbox("Report category *", config.REPORT_CATEGORIES)
        description = st.text_area(
            "What happened? *",
            height=140,
            placeholder="Describe the offer, what was requested, how you were contacted and any payment demand.",
        )
        date_columns = st.columns(2)
        with date_columns[0]:
            use_date = st.checkbox("I can provide an approximate date")
        with date_columns[1]:
            incident_date = st.date_input("Approximate incident date", value=None, disabled=not use_date)

        consent = st.checkbox(
            "I confirm this report describes a real experience and contains no private contact details or documents. *"
        )
        submitted = st.form_submit_button("Submit report", type="primary")

    if submitted:
        errors: list[str] = []
        if not company.strip():
            errors.append("Company name is required.")
        if len(description.strip()) < 20:
            errors.append("Please describe the incident in at least 20 characters.")
        if not consent:
            errors.append("Consent confirmation is required before submitting.")
        if domain.strip() and len(domain.strip()) < 4:
            errors.append("The sender email or domain looks too short.")
        if errors:
            for error in errors:
                st.error(error)
            return

        outcome = repository.add_report(
            {
                "company_name": company.strip(),
                "sender_domain": domain.strip(),
                "category": category,
                "description": description.strip(),
                "incident_date": incident_date.isoformat() if (use_date and incident_date) else "",
                "status": "submitted",
            }
        )
        if outcome["created"]:
            logger.info("Threat report %s submitted", outcome["id"])
            st.session_state["report_success"] = outcome["id"]
            go("report")
        else:
            st.info("This looks like a report that already exists in the network, so it was not duplicated.")
            st.caption(f"Report reference #{outcome['id']}")

    st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
    st.markdown(
        ui.bullet_list(
            [
                "Never send money, OTPs, original certificates or identity documents to a recruiter.",
                "Keep the offer letter, emails and payment requests as evidence.",
                "Report cyber financial fraud in India at https://cybercrime.gov.in/ or call 1930.",
            ]
        ),
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Page: Analysis History
# --------------------------------------------------------------------------- #
def render_history(palette: dict[str, str]) -> None:
    page_header(
        "Analysis History",
        "Every analysis you run is stored locally in SQLite with its extracted facts, findings and score, so you can "
        "reopen it later. Original documents are not stored.",
    )

    analyses = repository.list_analyses(limit=100)
    if not analyses:
        st.markdown(
            ui.empty_state("No saved analyses", "Run a verification and it will appear here."),
            unsafe_allow_html=True,
        )
        if st.button("Verify an Offer", type="primary"):
            go("verify")
        return

    st.caption(f"{len(analyses)} stored analysis record(s).")
    for row in analyses:
        card = st.container(border=True)
        with card:
            info_column, action_column = st.columns([3, 1])
            with info_column:
                st.markdown(
                    f"""
<div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;">
  <span><strong>{ui.esc(row['company_name'])}</strong>
    <span class="og-muted og-small">&middot; {ui.esc(row['analysis_id'])}</span></span>
  <span class="og-chip">score <b>{int(row['score'])}</b> &middot; {ui.esc(row['risk_category'])}</span>
</div>
<div class="og-muted og-small" style="margin-top:6px;">
  {ui.esc(str(row['created_at'])[:19].replace('T', ' '))} &middot;
  domain {ui.esc(row['sender_domain'] or 'not recorded')}
</div>
""",
                    unsafe_allow_html=True,
                )
            with action_column:
                if st.button("View details", key=f"view_{row['analysis_id']}", use_container_width=True):
                    stored = repository.get_analysis(row["analysis_id"])
                    if stored is None:
                        st.error("That record could not be loaded. It may have been deleted.")
                    else:
                        st.session_state["analysis"] = stored
                        go("results")
                if st.button("Delete", key=f"delete_{row['analysis_id']}", use_container_width=True):
                    if repository.delete_analysis(row["analysis_id"]):
                        logger.info("Deleted analysis %s", row["analysis_id"])
                        set_flash("Analysis deleted.", "success")
                        st.rerun()
                    else:
                        st.error("That record could not be deleted.")

    st.markdown("<hr class='og-divider'>", unsafe_allow_html=True)
    if st.button("Delete all saved analyses"):
        count = 0
        for row in repository.list_analyses(limit=1000):
            if repository.delete_analysis(row["analysis_id"]):
                count += 1
        set_flash(f"Deleted {count} analysis record(s).", "success")
        st.rerun()


# --------------------------------------------------------------------------- #
# Page: About & Safety
# --------------------------------------------------------------------------- #
def render_about(palette: dict[str, str]) -> None:
    page_header(
        "About & Safety",
        "How OfferGuard works, what it can and cannot tell you, and how to verify an offer safely.",
    )

    st.markdown("### What OfferGuard does")
    st.markdown(
        "OfferGuard reads an offer letter, extracts the important details, and applies three verification layers. "
        "It returns a bounded risk score from 0 to 100, a Low / Caution / High classification, the evidence behind "
        "every point, and practical next steps. **It never guarantees that an offer is genuine or fraudulent.**"
    )

    columns = st.columns(3)
    with columns[0]:
        st.markdown(
            "<div class='og-card'><strong>1. Letter Check</strong><p class='og-muted'>Rule-based detection of payment "
            "demands, urgency pressure, bond and penalty clauses, and recruitment-process red flags, with the exact "
            "evidence snippet for each finding.</p></div>",
            unsafe_allow_html=True,
        )
    with columns[1]:
        st.markdown(
            "<div class='og-card'><strong>2. Company Check</strong><p class='og-muted'>Sender email parsing, comparison "
            "against independently sourced official domains, lookalike-domain detection, and an optional RDAP domain "
            "registration lookup. Unavailable checks are reported as not checked.</p></div>",
            unsafe_allow_html=True,
        )
    with columns[2]:
        st.markdown(
            "<div class='og-card'><strong>3. Campus Threat Network</strong><p class='og-muted'>Matching against student "
            "reports by exact sender domain (strong) or company name (weak). Corroborated reports count more than "
            "unverified ones, and rejected reports count for nothing.</p></div>",
            unsafe_allow_html=True,
        )

    st.markdown("### Scoring methodology")
    rows = "".join(
        f"<tr><th>{ui.esc(label)}</th><td>{cap}</td></tr>"
        for label, cap in [
            ("Payment demands", config.SCORE_CAPS["payment"]),
            ("Urgency and pressure", config.SCORE_CAPS["urgency"]),
            ("Bond and penalty clauses", config.SCORE_CAPS["bond"]),
            ("Recruitment-process concerns", config.SCORE_CAPS["recruitment"]),
            ("Company and domain concerns", config.SCORE_CAPS["company"]),
            ("Campus threat matches", config.SCORE_CAPS["threat"]),
        ]
    )
    st.markdown(
        f"""
<table>
  <thead><tr><th>Category</th><th>Maximum points</th></tr></thead>
  <tbody>{rows}<tr><th>Total</th><td>{config.MAX_SCORE}</td></tr></tbody>
</table>
""",
        unsafe_allow_html=True,
    )
    st.markdown(
        "- 0-29 = **Low** risk, 30-59 = **Caution**, 60-100 = **High** risk.\n"
        "- These are heuristic weights, not validated fraud probabilities. A score of 80 does **not** mean an 80% "
        "chance of fraud.\n"
        "- Each category is capped, duplicate evidence is counted once, an unavailable external check is treated as "
        "unknown, and no threat points are awarded when no reports exist."
    )
    st.markdown(ui.disclaimer_card(), unsafe_allow_html=True)

    st.markdown("### Limitations")
    st.markdown(ui.bullet_list(config.LIMITATIONS), unsafe_allow_html=True)

    st.markdown("### Privacy and safety practices")
    st.markdown(
        ui.bullet_list(
            [
                "Offer letters are parsed in memory and the original file is never written to disk.",
                "Only extracted facts, findings, scores and the reports you submit are stored in the local SQLite database.",
                "Files, macros and links inside a document are never executed, and OfferGuard never fetches URLs found in a letter.",
                "External network access is limited to an allow-listed RDAP registration service and can be switched off.",
                "Report submissions require consent and must not contain private contact details or identity documents.",
            ]
        ),
        unsafe_allow_html=True,
    )

    st.markdown("### Safe verification steps")
    st.markdown(
        ui.bullet_list(
            [
                "Find the company's official website yourself and call the number listed there. Never use contact details from the offer letter.",
                "Compare the sender domain character by character with the official domain.",
                "Ask your college placement cell to confirm the offer and whether other students received the same letter.",
                "Never pay a registration, training, verification, deposit or processing fee.",
                "Never hand over original certificates, and always read a bond clause before signing.",
                "Check whether the same offer was reported by other students in the Campus Threat Network.",
            ]
        ),
        unsafe_allow_html=True,
    )

    st.markdown("### Reporting options in India")
    st.markdown(
        "- National Cyber Crime Reporting Portal: **https://cybercrime.gov.in/**\n"
        "- Cyber financial fraud helpline: **1930** (available 24x7)\n"
        "- Keep every message, email header and payment request safe as evidence."
    )
    st.markdown(
        f"<p class='og-muted og-small'>OfferGuard v{ui.esc(config.VERSION)} &middot; built for the CyberShield "
        "Secure, Trustworthy &amp; Quantum-Safe Technology track. OfferGuard does not claim quantum-safe "
        "cryptography or production-grade security certification.</p>",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main() -> None:
    initialise_state()
    active_theme = st.session_state.get("theme", "dark")
    palette = theme.apply_theme(active_theme)
    render_sidebar(palette)
    render_flash()

    page = st.session_state.get("page", "home")
    renderers = {
        "home": render_home,
        "verify": render_verify,
        "results": render_results,
        "threat": render_threat,
        "report": render_report,
        "history": render_history,
        "about": render_about,
    }
    renderer = renderers.get(page, render_home)
    renderer(palette)

    st.markdown("<hr class='og-divider'>", unsafe_allow_html=True)
    st.caption(
        "OfferGuard is a student safety project. It explains risk patterns and never certifies an offer as genuine "
        "or fraudulent. Report cyber financial fraud at https://cybercrime.gov.in/ or call 1930."
    )


if __name__ == "__main__":
    main()
