"""High-level database operations used by the services and the UI."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

import config
from database.db import connection_scope, init_db
from database.models import AnalysisResult
from services.normalizer import normalize_company, registered_domain

REPORT_STATUSES = config.REPORT_STATUSES


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _dedupe_key(*parts: str) -> str:
    raw = "|".join((part or "").strip().lower() for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Analyses
# --------------------------------------------------------------------------- #
def save_analysis(result: AnalysisResult, db_path=None) -> str:
    """Persist an analysis and its findings. Returns the analysis id."""
    init_db(db_path)
    facts = result.extracted_facts or {}
    with connection_scope(db_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO analyses
                (id, created_at, company_name, sender_domain, score, risk_category,
                 summary, source_filename, extraction_method, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.analysis_id,
                result.created_at,
                facts.get("company_name") or "Unknown company",
                facts.get("sender_domain") or "",
                int(result.score),
                result.risk_category,
                result.summary,
                result.source_filename,
                (result.extraction or {}).get("method"),
                json.dumps(result.to_dict(), ensure_ascii=False),
            ),
        )
        connection.execute("DELETE FROM findings WHERE analysis_id = ?", (result.analysis_id,))
        for finding in result.findings:
            connection.execute(
                """
                INSERT INTO findings
                    (analysis_id, rule_id, module, category, severity, points, evidence, explanation, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.analysis_id,
                    finding.rule_id,
                    finding.module,
                    finding.category,
                    finding.severity,
                    int(finding.points),
                    finding.evidence,
                    finding.explanation,
                    finding.confidence,
                ),
            )
    return result.analysis_id


def get_analysis(analysis_id: str, db_path=None) -> AnalysisResult | None:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        row = connection.execute(
            "SELECT payload FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    if row is None:
        return None
    try:
        return AnalysisResult.from_dict(json.loads(row["payload"]))
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def list_analyses(limit: int = 50, db_path=None) -> list[dict[str, Any]]:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, company_name, sender_domain, score, risk_category, summary
            FROM analyses ORDER BY created_at DESC, rowid DESC LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [
        {
            "analysis_id": row["id"],
            "created_at": row["created_at"],
            "company_name": row["company_name"] or "Unknown company",
            "sender_domain": row["sender_domain"] or "",
            "score": row["score"],
            "risk_category": row["risk_category"],
            "summary": row["summary"] or "",
        }
        for row in rows
    ]


def count_analyses(db_path=None) -> int:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM analyses").fetchone()
    return int(row["total"]) if row else 0


def delete_analysis(analysis_id: str, db_path=None) -> bool:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        cursor = connection.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    return cursor.rowcount > 0


# --------------------------------------------------------------------------- #
# Threat reports
# --------------------------------------------------------------------------- #
def add_report(report: dict[str, Any], db_path=None, is_demo: bool = False) -> dict[str, Any]:
    """Insert a threat report, skipping exact duplicates."""
    init_db(db_path)
    company = (report.get("company_name") or "").strip()
    domain = registered_domain(report.get("sender_domain") or "")
    category = (report.get("category") or "Other").strip()
    description = (report.get("description") or "").strip()
    incident_date = (report.get("incident_date") or "").strip() or None
    status = (report.get("status") or "submitted").strip().lower().replace(" ", "_")
    if status not in REPORT_STATUSES:
        status = "submitted"

    key = _dedupe_key(company, domain, category, description)
    with connection_scope(db_path) as connection:
        existing = connection.execute(
            "SELECT id FROM threat_reports WHERE dedupe_key = ?", (key,)
        ).fetchone()
        if existing:
            return {"id": existing["id"], "created": False, "duplicate": True}
        cursor = connection.execute(
            """
            INSERT INTO threat_reports
                (company_name, normalized_company, sender_domain, normalized_domain,
                 category, description, incident_date, status, is_demo, created_at, dedupe_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                company,
                normalize_company(company),
                (report.get("sender_domain") or "").strip().lower() or None,
                domain or None,
                category,
                description,
                incident_date,
                status,
                1 if is_demo else 0,
                _utc_now(),
                key,
            ),
        )
    return {"id": cursor.lastrowid, "created": True, "duplicate": False}


def list_reports(
    search: str = "",
    category: str = "",
    status: str = "",
    include_demo: bool = True,
    limit: int = 200,
    db_path=None,
) -> list[dict[str, Any]]:
    init_db(db_path)
    clauses: list[str] = []
    params: list[Any] = []
    if search:
        term = f"%{search.strip().lower()}%"
        clauses.append(
            "(LOWER(company_name) LIKE ? OR LOWER(COALESCE(sender_domain, '')) LIKE ?)"
        )
        params.extend([term, term])
    if category:
        clauses.append("category = ?")
        params.append(category)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if not include_demo:
        clauses.append("is_demo = 0")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection_scope(db_path) as connection:
        rows = connection.execute(
            f"""
            SELECT id, company_name, sender_domain, normalized_domain, category,
                   description, incident_date, status, is_demo, created_at
            FROM threat_reports {where}
            ORDER BY created_at DESC, id DESC LIMIT ?
            """,
            (*params, int(limit)),
        ).fetchall()
    return [_row_to_report(row) for row in rows]


def _row_to_report(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "company_name": row["company_name"],
        "sender_domain": row["sender_domain"] or "",
        "registered_domain": row["normalized_domain"] or "",
        "category": row["category"],
        "description": row["description"],
        "incident_date": row["incident_date"] or "",
        "status": row["status"],
        "is_demo": bool(row["is_demo"]),
        "created_at": row["created_at"],
    }


def count_reports(db_path=None, include_demo: bool = True) -> int:
    init_db(db_path)
    condition = "" if include_demo else "WHERE is_demo = 0"
    with connection_scope(db_path) as connection:
        row = connection.execute(
            f"SELECT COUNT(*) AS total FROM threat_reports {condition}"
        ).fetchone()
    return int(row["total"]) if row else 0


def find_reports_for(company_name: str, sender_domain: str, db_path=None) -> dict[str, list[dict[str, Any]]]:
    """Return matching reports grouped by match confidence: domain (strong), company (weak)."""
    init_db(db_path)
    domain = registered_domain(sender_domain or "")
    normalized_company = normalize_company(company_name or "")
    matches: dict[str, list[dict[str, Any]]] = {"domain": [], "company": []}
    with connection_scope(db_path) as connection:
        if domain:
            rows = connection.execute(
                """
                SELECT id, company_name, sender_domain, normalized_domain, category,
                       description, incident_date, status, is_demo, created_at
                FROM threat_reports WHERE normalized_domain = ? ORDER BY created_at DESC
                """,
                (domain,),
            ).fetchall()
            matches["domain"] = [_row_to_report(row) for row in rows]
        if normalized_company:
            rows = connection.execute(
                """
                SELECT id, company_name, sender_domain, normalized_domain, category,
                       description, incident_date, status, is_demo, created_at
                FROM threat_reports WHERE normalized_company = ? ORDER BY created_at DESC
                """,
                (normalized_company,),
            ).fetchall()
            domain_ids = {item["id"] for item in matches["domain"]}
            matches["company"] = [
                _row_to_report(row) for row in rows if row["id"] not in domain_ids
            ]
    return matches


def delete_demo_reports(db_path=None) -> int:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        cursor = connection.execute("DELETE FROM threat_reports WHERE is_demo = 1")
    return cursor.rowcount


def delete_report(report_id: int, db_path=None) -> bool:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        cursor = connection.execute("DELETE FROM threat_reports WHERE id = ?", (int(report_id),))
    return cursor.rowcount > 0


# --------------------------------------------------------------------------- #
# Company references
# --------------------------------------------------------------------------- #
def upsert_reference(reference: dict[str, Any], db_path=None) -> None:
    init_db(db_path)
    company = (reference.get("company_name") or "").strip()
    domain = (reference.get("official_domain") or "").strip().lower()
    with connection_scope(db_path) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO company_references
                (company_name, normalized_company, official_domain, source, verified_at, reference_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                company,
                normalize_company(company),
                registered_domain(domain) or None,
                reference.get("source") or config.REFERENCE_DATA_SOURCE,
                reference.get("verified_at") or "",
                reference.get("reference_status") or "public-reference",
            ),
        )


def list_references(db_path=None) -> list[dict[str, Any]]:
    init_db(db_path)
    with connection_scope(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM company_references ORDER BY company_name, official_domain"
        ).fetchall()
    return [
        {
            "company_name": row["company_name"],
            "normalized_company": row["normalized_company"],
            "official_domain": row["official_domain"] or "",
            "source": row["source"],
            "verified_at": row["verified_at"] or "",
            "reference_status": row["reference_status"],
        }
        for row in rows
    ]


def get_references(company_name: str, db_path=None) -> list[dict[str, Any]]:
    """Return every official-domain reference stored for a company name."""
    normalized = normalize_company(company_name or "")
    if not normalized:
        return []
    init_db(db_path)
    with connection_scope(db_path) as connection:
        rows = connection.execute(
            """
            SELECT company_name, official_domain, source, verified_at, reference_status
            FROM company_references WHERE normalized_company = ? ORDER BY official_domain
            """,
            (normalized,),
        ).fetchall()
    return [
        {
            "company_name": row["company_name"],
            "official_domain": row["official_domain"] or "",
            "source": row["source"],
            "verified_at": row["verified_at"] or "",
            "reference_status": row["reference_status"],
        }
        for row in rows
    ]


def get_reference(company_name: str, db_path=None) -> dict[str, Any] | None:
    normalized = normalize_company(company_name or "")
    if not normalized:
        return None
    init_db(db_path)
    with connection_scope(db_path) as connection:
        row = connection.execute(
            """
            SELECT company_name, official_domain, source, verified_at, reference_status
            FROM company_references WHERE normalized_company = ? LIMIT 1
            """,
            (normalized,),
        ).fetchone()
    if row is None:
        return None
    return {
        "company_name": row["company_name"],
        "official_domain": row["official_domain"] or "",
        "source": row["source"],
        "verified_at": row["verified_at"] or "",
        "reference_status": row["reference_status"],
    }


# --------------------------------------------------------------------------- #
# Demo data and statistics
# --------------------------------------------------------------------------- #
def seed_database(db_path=None) -> dict[str, int]:
    """Seed fictional demo data. Safe to call on every start: never duplicates rows."""
    init_db(db_path)
    added_reports = 0
    added_references = 0

    reference_file = config.DATA_DIR / "demo_companies.json"
    if reference_file.exists():
        references = json.loads(reference_file.read_text(encoding="utf-8"))
        before = len(list_references(db_path))
        for reference in references:
            upsert_reference(reference, db_path)
        added_references = len(list_references(db_path)) - before

    reports_file = config.DATA_DIR / "demo_threat_reports.json"
    if reports_file.exists():
        payload = json.loads(reports_file.read_text(encoding="utf-8"))
        for report in payload.get("reports", []):
            outcome = add_report(report, db_path=db_path, is_demo=True)
            if outcome["created"]:
                added_reports += 1

    return {"reports": added_reports, "references": added_references}


def get_stats(db_path=None) -> dict[str, int]:
    return {
        "analyses": count_analyses(db_path),
        "reports": count_reports(db_path, include_demo=True),
        "user_reports": count_reports(db_path, include_demo=False),
    }
