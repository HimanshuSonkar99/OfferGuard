"""Shared pytest fixtures.

Every test runs against a throwaway SQLite database and with external network
lookups disabled, so the suite is fast, deterministic and offline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Point the whole application at a temporary database for one test."""
    db_file = tmp_path / "offerguard_test.db"
    monkeypatch.setenv("OFFERGUARD_DB", str(db_file))
    return db_file


@pytest.fixture(autouse=True)
def no_external_lookups(monkeypatch):
    """Never touch the network during tests."""
    import config

    monkeypatch.setattr(config, "EXTERNAL_LOOKUPS_ENABLED", False)
    yield


@pytest.fixture
def seeded_db(isolated_db):
    """Seed the fictional demo references and reports."""
    from database import repository

    repository.seed_database()
    return isolated_db
