# OfferGuard

![Tests](https://img.shields.io/badge/tests-64%20passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Ruff](https://img.shields.io/badge/ruff-clean-C4A934?logo=ruff&logoColor=black)
![License](https://img.shields.io/badge/license-MIT-blue)

**AI Verifier for Fake Internship & Job Offers** — _Verify Before You Pay._

OfferGuard reads an internship or job offer letter, extracts the important details,
runs three independent verification layers, and returns an **explainable** risk score
from 0 to 100 with the exact evidence behind every point.

It is built for students and campus placement cells who want a fast, honest
second opinion before paying any fee or sharing documents.

> OfferGuard is a risk-indicator tool. It **never** certifies that an offer is genuine
> or fraudulent, and a score of 80 does **not** mean an 80% chance of fraud.

---

## What it does

1. **Letter Check** — rule-based detection of payment demands, urgency pressure,
   bond/penalty clauses and recruitment-process red flags. Each finding shows the
   exact snippet that triggered it. Simple negations such as
   _"no registration fee is required"_ are suppressed.
2. **Company Check** — parses the sender email/domain, compares it against
   independently sourced official domains, detects lookalike domains
   (`infosys-careers.com` vs `infosys.com`), and can optionally query a public
   **RDAP** service for the domain's registration date. Unavailable checks are
   reported honestly as _"not checked"_ rather than treated as safe.
3. **Campus Threat Network** — matches the offer against stored student reports.
   An exact sender-domain match counts more than a company-name match, corroborated
   reports count more than unverified ones, and rejected reports count for nothing.

Results are saved locally (SQLite) so students can review their analysis history and
download an HTML or TXT report.

## One-click demo

The Verify page ships **two built-in fictional sample letters**, so a full analysis can
be demonstrated in a single click (useful for demos and judge walkthroughs):

| Button | What it demonstrates | Typical result |
| ------ | --------------------- | -------------- |
| **Demo 1: fee scam + threat report** | Payment demands, urgency, bond, guaranteed selection, and a corroborated Campus Threat Network match | High (~80) |
| **Demo 2: lookalike sender domain** | `infosys-careers.com` vs `infosys.com` lookalike detection plus fee and pressure wording | High (~72) |

Both letters are clearly labelled as fictional sample data and are stored under
`data/samples/`.

## Quick start (Windows PowerShell)

```powershell
# from the project folder
python -m venv .venv                 # skip if you already have a virtual environment
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Then open the URL Streamlit prints (usually http://localhost:8501).

Optional environment variables: copy `.env.example` to `.env` and edit it — OfferGuard
loads the `.env` file automatically on startup (values already set in the shell always win).

| Variable             | Purpose                                                        |
| -------------------- | -------------------------------------------------------------- |
| `OFFERGUARD_DB`      | Override the SQLite database path.                             |
| `TESSERACT_CMD`      | Point to the Tesseract executable to enable OCR for scans.     |
| `OFFERGUARD_EXTERNAL_CHECKS` | Set to `0`/`false` to disable the RDAP domain lookup entirely. |

## Running the tests

```powershell
python -m pytest            # rapid, offline, no network access
python -m pytest -q         # quieter output
```

The suite runs against a throwaway database (via `OFFERGUARD_DB`) with all external
lookups disabled, so it is fast and deterministic.

## Project structure

```
OfferGuard/
├── app.py                     # Streamlit UI (home, verify, results, threat, report, history, about)
├── config.py                  # limits, score caps, bands, privacy notice, limitations
├── requirements.txt
├── pyproject.toml               # ruff lint configuration
├── LICENSE                      # MIT
├── components/                # theme, SVG charts and reusable HTML UI blocks
│   ├── theme.py
│   ├── charts.py
│   └── ui_components.py
├── services/                  # all analysis logic (no Streamlit imports)
│   ├── normalizer.py          # company/domain/email normalisation
│   ├── document_parser.py     # PDF/image/text extraction + structured facts
│   ├── ocr_service.py         # OCR wrapper with graceful fallback
│   ├── letter_checker.py      # rule engine for letter wording
│   ├── company_checker.py     # email/domain/reference/RDAP checks
│   ├── threat_checker.py      # Campus Threat Network matching
│   ├── risk_engine.py         # scoring, capping, dedupe, classification
│   ├── recommendations.py     # summary + next steps
│   ├── report_builder.py      # HTML/TXT report export
│   └── pipeline.py            # end-to-end run used by the UI and tests
├── database/                  # SQLite access layer
│   ├── db.py                  # schema + connections
│   ├── models.py              # Finding / AnalysisResult
│   └── repository.py          # high-level queries + seeding
├── data/                      # seeded fictional demo data
│   ├── demo_companies.json
│   ├── demo_threat_reports.json
│   └── samples/               # one-click demo letters
├── docs/                      # architecture, scoring, demo script, limitations
└── tests/                     # pytest suite
```

## How the score works (summary)

Points are awarded per finding and **capped per category**, then summed:

| Category                     | Max points |
| ---------------------------- | ---------- |
| Payment demands              | 30         |
| Urgency and pressure         | 15         |
| Bond and penalty clauses     | 10         |
| Recruitment-process concerns | 10         |
| Company and domain concerns  | 20         |
| Campus threat matches        | 15         |
| **Total**                    | **100**    |

Classification bands: **0–29 Low, 30–59 Caution, 60–100 High**.

A letter-only scam typically lands in **Caution**; reaching **High** normally requires
company/domain evidence or a campus-report match. Full detail, including every rule
weight and worked examples, is in [`docs/scoring_methodology.md`](docs/scoring_methodology.md).

## Privacy and safety

- Offer letters are parsed **in memory**; the original file is never written to disk.
- Files, macros and links inside a document are never executed, and OfferGuard never
  fetches URLs found in a letter.
- External network access is limited to an allow-listed RDAP service and can be turned off.
- Only extracted facts, findings and scores (plus reports you submit) are stored locally.

## Disclaimer

OfferGuard is an educational, hackathon project. It uses heuristic rules and
self-reported data, does not provide legal advice, and does not claim quantum-safe
cryptography or production-grade security certification. Always verify an offer
through the company's official channels and your college placement cell. Report cyber
financial fraud in India at <https://cybercrime.gov.in/> or by calling **1930**.

## License

OfferGuard is released under the [MIT License](LICENSE).
