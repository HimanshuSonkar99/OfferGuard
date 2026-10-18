# Limitations, Safety & Honest Claims

OfferGuard is a student safety project. Being clear about what it **cannot** do is part
of the design, not an afterthought.

## What OfferGuard can do

- Detect many common recruitment-fee fraud **patterns** in the wording of an offer letter.
- Compare a sender email/domain against a small set of independently sourced official
  domains and flag lookalike domains.
- Optionally check a domain's registration date through a public **RDAP** service.
- Match an offer against locally stored, student-reported records.
- Produce a reproducible, explainable score with the evidence for every point.

## What OfferGuard cannot do

- **It cannot prove an offer is genuine or fraudulent.** The score is a heuristic risk
  indicator, and a score of 80 does **not** mean an 80% probability of fraud.
- **It is not a company registry or a legal check.** Only a small set of public reference
  domains is bundled; unknown companies are reported as _"not checked"_, not as safe.
- **It does not verify images, logos, signatures or seals**, only text present in the
  document.
- **It does not execute or open links, attachments or macros**, and it never fetches URLs
  found in a letter.
- **It cannot detect a scam that avoids all known patterns.** A Low score is not a
  clearance.
- **The Campus Threat Network is self-reported.** It reflects student observations, not
  legal findings of fraud, and may contain mistakes. Unverified reports add only a small
  amount; rejected reports add nothing.

## Known technical limitations

- **OCR requires the Tesseract engine.** The Python package is installed, but the
  executable is not bundled. Without it, scanned images and image-only PDFs cannot be
  read and OfferGuard says so and asks you to paste the text (or set `TESSERACT_CMD`).
- **External checks can fail.** RDAP may be offline, rate-limited or blocked. When a check
  cannot run it is reported as _"not checked"_ and awards no points — never as "safe".
- **Reference coverage is small.** Only companies in `data/demo_companies.json` can be
  compared; everything else cannot be verified by domain.
- **Heuristic weights are tunable, not validated.** The point values in
  `docs/scoring_methodology.md` are informed by common scam patterns but are not derived
  from a labelled fraud dataset.
- **The demo threat reports are fictional** (`.example` domains) and clearly labelled;
  they exist only to demonstrate the matching logic.

## Privacy & security practices

- Offer letters are parsed **in memory**; the original file is never written to disk.
- Only extracted facts, findings and scores are stored, in a **local** SQLite database.
- Uploads are limited to PDF/PNG/JPG, 10 MB and 20 pages.
- The single outbound request (RDAP) is allow-listed, short-timeout, non-redirecting and
  can be disabled in the app or with `EXTERNAL_LOOKUPS=0`.
- All untrusted text is HTML-escaped before rendering and before export.
- Reports require explicit consent and must not contain private contact details or
  identity documents.

## Safety guidance to give students

- Find the company's official website yourself and call the number listed there; never use
  contact details from the offer letter.
- Never pay a registration, training, verification, deposit or processing fee.
- Never hand over original certificates; always read a bond clause before signing.
- Ask your college placement cell to confirm the offer before responding to any deadline.
- Keep every message, email header and payment request as evidence.

## Reporting (India)

- National Cyber Crime Reporting Portal: <https://cybercrime.gov.in/>
- Cyber financial-fraud helpline: **1930** (24×7)

## Honest position on security claims

OfferGuard does **not** claim quantum-safe cryptography, formal verification, or any
security certification. It is an educational project built to explain recruitment-fee
fraud risk clearly and responsibly.
