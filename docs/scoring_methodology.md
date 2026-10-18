# Scoring Methodology

OfferGuard produces a single **heuristic risk indicator** from 0 to 100. It is designed
to be transparent and reproducible: every point can be traced to a rule and an evidence
snippet, and the same input always yields the same score.

> A high score means _"this document contains many known fraud patterns"_, **not** a
> probability of fraud. The score is not a statistical likelihood and not a legal finding.

## 1. How a score is built

1. Each module emits **findings**. A finding has a `rule_id`, `category`, `severity`,
   `points`, `evidence` (the exact snippet) and a plain-language `explanation`.
2. Findings with identical `rule_id` **and** evidence are de-duplicated, so the same
   evidence is never counted twice.
3. Points are grouped into six **categories** and each category is **capped**.
4. The capped category scores are summed into the final 0–100 score.
5. The score is mapped to a band: **0–29 Low, 30–59 Caution, 60–100 High**.

Capping is what keeps the score honest: a document cannot reach 100 by repeating one
kind of red flag, and a single category can never dominate.

## 2. Category caps

| Category                     | Cap | Meaning |
| ---------------------------- | --- | --- |
| Payment demands              | 30  | Money requested from the candidate |
| Urgency and pressure         | 15  | Artificial deadlines and pressure language |
| Bond and penalty clauses     | 10  | Long bonds, penalties, held certificates |
| Recruitment-process concerns | 10  | Guaranteed selection, no interview, bait pay |
| Company and domain concerns  | 20  | Sender domain, references, domain age |
| Campus threat matches        | 15  | Matching student reports |
| **Total**                    | **100** | |

## 3. Letter Check rules

### Payment demands (cap 30)
| Rule | Points | Severity |
| --- | --- | --- |
| `PAY-REFUNDABLE-DEPOSIT` | 15 | high |
| `PAY-TRAINING-FEE` | 15 | high |
| `PAY-REGISTRATION-FEE` | 15 | high |
| `PAY-CONFIRM-SEAT` (pay to confirm/secure your seat) | 15 | high |
| `PAY-DOCUMENT-VERIFICATION` | 12 | high |
| `PAY-SECURITY-DEPOSIT` | 12 | high |
| `PAY-PROCESSING-FEE` | 10 | medium |
| `PAY-UPFRONT-DEMAND` (UPI/GPay/bank transfer) | 10 | medium |
| `PAY-DEPOSIT-OR-DOCS` | 9 | medium |

### Urgency and pressure (cap 15)
| Rule | Points | Severity |
| --- | --- | --- |
| `URG-PAY-IMMEDIATELY` | 10 | high |
| `URG-LOSE-SELECTION` | 9 | medium |
| `URG-OFFER-EXPIRES` | 8 | medium |
| `URG-HOURS-DEADLINE` | 8 | medium |
| `URG-LIMITED-SEATS` | 6 | low |
| `URG-PRESSURE-LANGUAGE` (act fast / click here / hurry) | 6 | medium |

### Bond and penalty clauses (cap 10)
| Rule | Points | Severity |
| --- | --- | --- |
| `BOND-ORIGINAL-DOCS-HELD` | 8 | high |
| `BOND-PENALTY-AMOUNT` | 7 | medium |
| `BOND-LONG-PERIOD` | 6 | medium |
| `BOND-RESTRICTIVE-TERMS` | 5 | low |

### Recruitment-process concerns (cap 10)
| Rule | Points | Severity |
| --- | --- | --- |
| `REC-GUARANTEED-SELECTION` | 8 | high |
| `REC-PAYMENT-BEFORE-JOINING` | 6 | medium |
| `REC-INCONSISTENT-CLAIMS` | 5 | medium |
| `REC-UNREALISTIC-SALARY` | 5 | low |
| `REC-NO-INTERVIEW` | 4 | low |

**Negation guard.** A phrase match is skipped when a negation such as _no_, _not_,
_never_, _without_, _waived_ or _free of_ appears immediately before it. So
_"no registration fee is required"_ produces **no** payment finding.

## 4. Company Check rules (cap 20)
| Rule | Points | Severity |
| --- | --- | --- |
| `COMPANY-LOOKALIKE-DOMAIN` | 12 | high |
| `COMPANY-FREE-MAIL-SENDER` | 10 | high |
| `COMPANY-NEW-DOMAIN` (registered ≤ 30 days ago via RDAP) | 10 | high |
| `COMPANY-DOMAIN-MISMATCH` | 8 | medium |
| `COMPANY-INVALID-EMAIL` | 6 | medium |
| `COMPANY-RECENT-DOMAIN` (≤ 180 days ago) | 5 | medium |
| `COMPANY-NO-SENDER-EMAIL` | 3 | low |

If the sender domain matches an independently sourced official domain, the module is
reported as **verified** and awards nothing. If a check cannot run (no reference data,
RDAP offline, external lookups disabled), it is reported as **not checked** — an unknown
is never silently treated as safe, and it never adds points.

## 5. Campus Threat Network rules (cap 15)
| Rule | Points | Severity |
| --- | --- | --- |
| `THREAT-DOMAIN-CORROBORATED` | 15 | high |
| `THREAT-DOMAIN-UNVERIFIED` (submitted / under review) | 6 | medium |
| `THREAT-COMPANY-NAME-MATCH` (weak, name only) | 4 | low |
| `THREAT-REJECTED-ONLY` | 0 | info |
| `THREAT-NO-REPORTS` | 0 | info |

Matches are graded: an **exact sender domain** counts far more than a company name;
**corroborated** reports count more than unverified ones; **rejected** reports count for
nothing. A company is never labelled fraudulent on the strength of one unverified report.

## 6. Worked examples

All three examples below are reproducible with `services.pipeline.run_analysis_from_text`.

### Example A — a letter-only scam → **55 / Caution**
> _"…selected for our Data Analyst internship program. To confirm your seat, a refundable
> registration fee of Rs 4,500 must be paid within 24 hours. This offer expires
> immediately… act fast and click here now. You must sign a 2 year bond with a penalty of
> Rs 200,000…"_

| Category | Awarded | Detail |
| --- | --- | --- |
| Payment | 30 (capped) | `PAY-REGISTRATION-FEE` 15 + `PAY-CONFIRM-SEAT` 15 |
| Urgency | 15 (capped) | expires 8 + 24h deadline 8 + pressure 6 |
| Bond | 10 (capped) | long period 6 + penalty 7 |
| **Total** | **55 → Caution** | |

### 5b. Same letter **plus** a lookalike sender domain
Sender `hr@infosys-careers.com` while claiming to be **Infosys** (`infosys.com`), with a
seeded reference: adds `COMPANY-LOOKALIKE-DOMAIN` (12).

| Category | Awarded |
| --- | --- |
| Letter (payment + urgency + bond) | 55 |
| Company | 12 |
| **Total** | **67 → High** |

### 5c. A clean offer
_"…we are pleased to offer you an unpaid summer internship. Your mentor will share the
schedule…"_ → **0 → Low** (no rule produces points).

### 5d. Legitimate letter that omits the sender email
Adds only `COMPANY-NO-SENDER-EMAIL` (3): **3 → Low**, with an explicit note that this is a
small concern, not proof of fraud.

## 7. Interpreting the bands

| Band | Score | What it means |
| --- | --- | --- |
| **Low** | 0–29 | No strong fraud patterns detected. Still verify independently before paying anything. |
| **Caution** | 30–59 | Real warning signs that need independent verification before you pay or share documents. |
| **High** | 60–100 | Multiple strong patterns, usually including company/domain or campus-report evidence. Treat as unsafe until proven otherwise. |

A letter-only scam typically reaches **Caution**. Reaching **High** requires corroborating
evidence from the Company Check or the Campus Threat Network, which is a deliberate design
choice: OfferGuard reserves its strongest verdict for cases backed by more than wording.
