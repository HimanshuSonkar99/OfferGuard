# Demo Script (5–7 minutes)

A reliable, rehearsed walkthrough. Every screen and number below has been verified on
this build. Keep it to the three scenarios unless you have extra time.

## Before you start

1. Activate the environment and launch:
   ```powershell
   ..\.venv\Scripts\Activate.ps1
   streamlit run app.py
   ```
2. Open http://localhost:8501.
3. Leave the sidebar theme on dark (default). Internet is optional; the demo works
   offline because RDAP is the only external call.

> Opening line: _"One in four students we surveyed received an offer that asked for money.
> OfferGuard gives you an explainable second opinion before you pay."_

## Scenario 1 — The obvious scam (≈1.5 min)

1. Sidebar → **Verify an Offer**.
2. Open the **Paste text manually** tab and paste:

   ```
   Subject: Internship Offer Letter - Acme Technologies Pvt Ltd

   Congratulations! You have been selected for our Data Analyst internship program.
   To confirm your seat, a refundable registration fee of Rs 4,500 must be paid within 24 hours.
   This offer expires immediately after the deadline, so act fast and click here now.
   You must sign a 2 year bond with a penalty of Rs 200,000 if you leave early.
   Contact our HR team at hr@acme-hiring.example for payment details.
   ```

3. Click **Analyze pasted text**.

**Expected result: `Score 55/100 — Caution`.**
- Point at the gauge, then the three module chips.
- Expand **Detailed findings**: `PAY-REGISTRATION-FEE`, `PAY-CONFIRM-SEAT`,
  `URG-HOURS-DEADLINE`, `BOND-PENALTY-AMOUNT` — each with the exact snippet.

> Talking point: _"It is a clear scam, yet we still say Caution, not High. Wording alone
> is evidence, not proof — we reserve High for cases we can corroborate."_

## Scenario 2 — Corroboration pushes it to High (≈1.5 min)

1. Click **New analysis** → **Verify an Offer** → **Paste text manually** and paste:

   ```
   Company name: Infosys Limited

   You have been selected for the position of Data Analyst Intern.
   To confirm your seat, a registration fee of Rs 4,500 must be paid within 24 hours.
   This offer expires immediately, so act fast.
   You must sign a 2 year bond with a penalty of Rs 200,000 if you leave early.
   Contact hr@infosys-careers.com for payment details.
   ```

2. Click **Analyze pasted text**.

**Expected result: `Score 67/100 — High`.**
- Expand **Company Check verification status**: the sender domain
  `infosys-careers.com` is flagged as a **lookalike** of the official `infosys.com`.
- Show the checks table: email format ✅, corporate domain, reference comparison, RDAP
  reported honestly as _"not checked"_ when offline.

> Talking point: _"The same fee demand, but now the sender is impersonating a real
> company. That independent evidence is what moves it from Caution to High."_

## Scenario 3 — A clean-looking offer stays Low (≈1 min)

1. **New analysis** → paste:

   ```
   Dear Candidate, we are pleased to offer you an unpaid summer internship.
   Your mentor will share the schedule. Contact your placement coordinator with questions.
   ```

2. Analyze.

**Expected result: `Score 0/100 — Low`.**
- No findings; the recommendation still says to verify independently.

> Talking point: _"No fear-mongering. OfferGuard does not invent problems, and even at
> zero it never tells you the offer is genuine."_

## Scenario 4 (optional) — Campus Threat Network & reports (≈1.5 min)

1. Sidebar → **Campus Threat Network**. Six clearly-labelled **fictional** demo reports
   are listed across moderation states (corroborated / under review / submitted / rejected).
2. In **Search**, type `zenith` to show the corroborated demo report.
3. Sidebar → **Report a Suspicious Offer**: submit a short report (company + description +
   consent) and show the success message. Submitting the identical report again is
   de-duplicated.
4. Sidebar → **Analysis History**: reopen a previous analysis, then show the
   **Download report (HTML)** button.

## Closing (≈30 s)

1. Sidebar → **About & Safety**: show the scoring table, limitations and the India
   reporting links (<https://cybercrime.gov.in/>, helpline **1930**).
2. Mention the tests:
   ```powershell
   python -m pytest -q
   ```
   _"54 tests cover the rules, scoring caps, domain lookalikes, threat matching,
   persistence and report escaping — all offline and deterministic."_

> Final line: _"OfferGuard doesn't just flag an offer — it shows exactly why, tells you
> what to do next, and never pretends to be certain."_

## Recovery tips

- If extraction misses the company name, open **Optional: correct the extracted details**
  and type the company name and sender email, then analyze again.
- If a scanned image/PDF fails, OCR needs the Tesseract engine. Use the **Paste text**
  tab for the demo and mention that OCR engages automatically when Tesseract is installed.
- If Streamlit shows a stale screen, press **R** in the browser or restart the server.
