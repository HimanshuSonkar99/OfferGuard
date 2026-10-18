# OfferGuard Architecture

OfferGuard is a single-process Streamlit application with a clean separation between
UI, analysis services and persistence. Nothing in `services/` imports Streamlit, so the
whole analysis pipeline is reusable from tests, a CLI or a future API.

```
┌──────────────────────────────────────────────────────────────┐
│ app.py (Streamlit UI)                                         │
│  home · verify · results · threat network · report · history  │
└───────────────┬──────────────────────────────────────────────┘
                │ calls only
                ▼
┌──────────────────────────────────────────────────────────────┐
│ services/pipeline.py                                          │
│  run_analysis_from_bytes()  ·  run_analysis_from_text()       │
└───────────────┬──────────────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────────────────────────────┐
│ services/risk_engine.py  (orchestrator)                       │
│   facts → letter_check · company_check · threat_check         │
│   → dedupe → per-category caps → score → classify → summary   │
└───────┬───────────────┬───────────────────┬──────────────────┘
        │               │                   │
        ▼               ▼                   ▼
 letter_checker   company_checker      threat_checker
        │               │                   │
        └───────────────┴───────────────────┘
                        │ models + repository
                        ▼
              database/ (SQLite)  ·  data/ (seeded demo JSON)
```

## Layers

### 1. Presentation — `app.py`, `components/`
- `app.py` owns session state (`page`, `analysis`, `theme`, `flash`, verification
  settings) and renders one of seven pages. Navigation and page changes use small
  callback helpers (`go`, `start_new_analysis`, `clear_upload`).
- `components/theme.py` defines the dark/light palettes, builds the CSS (injected at
  app level because Streamlit cannot change `[theme]` at runtime) and persists the
  choice to `.offerguard_prefs.json`.
- `components/charts.py` renders the risk gauge and score-breakdown bars as **pure SVG**
  (no plotting dependency).
- `components/ui_components.py` holds reusable, HTML-escaped building blocks
  (hero, workflow indicator, module cards, finding cards, checks table, stat cards).

### 2. Analysis — `services/`
| Module | Responsibility |
| --- | --- |
| `normalizer.py` | Pure helpers: normalise company names, registrable domains, emails; validate; classify arbitrary input. |
| `document_parser.py` | Validate uploads, extract text from PDFs (PyMuPDF) or images (OCR), clean text, and extract structured facts (company, sender, amounts, deadlines, bond). Raises `DocumentError` for bad/unreadable input. |
| `ocr_service.py` | Thin pytesseract wrapper that detects a missing Tesseract binary and degrades gracefully with a clear warning. |
| `letter_checker.py` | Phrase-based rule engine with a negation guard; returns findings with rule id, severity, points and evidence snippet. |
| `company_checker.py` | Layered check: email/domain parsing → free-mail detection → official-domain comparison + lookalike detection → optional RDAP registration lookup. |
| `threat_checker.py` | Matches stored reports by exact domain (strong) or company name (weak) and applies conservative scoring. |
| `risk_engine.py` | Runs the three modules, de-duplicates findings, applies per-category caps, computes the score and classification, and assembles `AnalysisResult` + module payloads. |
| `recommendations.py` | Builds the plain-language summary and the next-steps list from the actual findings. |
| `report_builder.py` | Produces the downloadable HTML and TXT report (all dynamic text HTML-escaped). |
| `pipeline.py` | The single entry point the UI and tests share: extract → analyse → optionally persist. |

### 3. Persistence — `database/`
- `db.py`: SQLite schema and connection helpers. The path resolves from an explicit
  argument, then the `OFFERGUARD_DB` environment variable, then `config.DB_PATH`.
- `models.py`: dataclasses `Finding`, `AnalysisResult` with `to_dict` /
  `from_dict`, so a saved analysis round-trips exactly.
- `repository.py`: all queries (`save/get/list/delete` analyses, `add/list/find/count`
  reports, reference lookup, `seed_database`, `get_stats`). It seeds fictional demo data
  idempotently on every start.

### 4. Data — `data/`
- `demo_companies.json`: public corporate domain references used as comparison anchors.
- `demo_threat_reports.json`: six **clearly fictional** `.example` reports in different
  moderation states, so the Threat Network can be demonstrated safely.

## Data flow of one analysis

1. `app.py` reads the uploaded file (or pasted text) and optional corrections.
2. `pipeline.run_analysis_from_bytes/text` extracts text and structured facts.
3. If nothing readable was extracted, a `DocumentError` is raised: an unreadable
   document is **never** treated as safe.
4. `risk_engine.analyze` runs the three modules over the text/facts.
5. Findings are de-duplicated, capped per category, summed and classified.
6. A summary and recommendations are generated from the actual findings.
7. The result is stored (facts, findings, score — never the source file) and returned.

## Privacy & security decisions

- Documents are processed in memory; the original file is never written to disk.
- Uploads are validated for extension and size (PDF/PNG/JPG, 10 MB, max 20 pages).
- Links inside a document are never fetched or executed.
- The only outbound request is an RDAP lookup to an allow-listed host, with a short
  timeout, redirects disabled, and the option to turn it off (`EXTERNAL_LOOKUPS` or the
  in-app checkbox).
- All untrusted text is HTML-escaped before it reaches the UI or the exported report.

## Extension points

- **Add a rule**: append a dict to `RULES` in `letter_checker.py` (rule id, category,
  severity, points, patterns, explanation).
- **Add a company reference**: append to `data/demo_companies.json`.
- **Add a THREAT category/status**: update `config.REPORT_CATEGORIES` / `REPORT_STATUSES`.
- **Swap the scoring model**: everything flows through `risk_engine.build_score_breakdown`,
  so caps and bands can change in `config.py` without touching the modules.
