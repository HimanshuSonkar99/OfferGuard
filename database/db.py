"""SQLite connection helpers and schema initialisation for OfferGuard."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    company_name TEXT,
    sender_domain TEXT,
    score INTEGER NOT NULL,
    risk_category TEXT NOT NULL,
    summary TEXT,
    source_filename TEXT,
    extraction_method TEXT,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    module TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    points INTEGER NOT NULL,
    evidence TEXT,
    explanation TEXT,
    confidence TEXT NOT NULL DEFAULT 'medium',
    FOREIGN KEY (analysis_id) REFERENCES analyses (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL,
    normalized_company TEXT NOT NULL,
    sender_domain TEXT,
    normalized_domain TEXT,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    incident_date TEXT,
    status TEXT NOT NULL DEFAULT 'submitted',
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS company_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL,
    normalized_company TEXT NOT NULL,
    official_domain TEXT,
    source TEXT NOT NULL,
    verified_at TEXT,
    reference_status TEXT NOT NULL,
    UNIQUE (normalized_company, official_domain)
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings (analysis_id);
CREATE INDEX IF NOT EXISTS idx_reports_company ON threat_reports (normalized_company);
CREATE INDEX IF NOT EXISTS idx_reports_domain ON threat_reports (normalized_domain);
"""


def resolve_db_path(db_path: os.PathLike | str | None = None) -> Path:
    """Return the database path, honouring an explicit override or environment variable."""
    if db_path is not None:
        return Path(db_path)
    env_path = os.environ.get("OFFERGUARD_DB")
    if env_path:
        return Path(env_path)
    return config.DB_PATH


def get_connection(db_path: os.PathLike | str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection with row access by column name and foreign keys on."""
    path = resolve_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def connection_scope(db_path: os.PathLike | str | None = None) -> Iterator[sqlite3.Connection]:
    """Context manager that commits on success, rolls back on error and always closes."""
    connection = get_connection(db_path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db(db_path: os.PathLike | str | None = None) -> Path:
    """Create all tables if they do not exist and return the database path used."""
    path = resolve_db_path(db_path)
    with connection_scope(path) as connection:
        connection.executescript(SCHEMA)
        _migrate(connection)
    return path


def _migrate(connection: sqlite3.Connection) -> None:
    """Apply additive migrations for databases created by older builds."""
    finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}
    if finding_columns and "confidence" not in finding_columns:
        connection.execute(
            "ALTER TABLE findings ADD COLUMN confidence TEXT NOT NULL DEFAULT 'medium'"
        )
