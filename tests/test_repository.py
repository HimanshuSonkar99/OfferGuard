from database import repository
from services.pipeline import run_analysis_from_text

SCAM_LETTER = (
    "Company name: Acme Technologies Pvt Ltd\n"
    "You have been selected for the position of Data Analyst Intern.\n"
    "A registration fee of Rs 4,500 must be paid within 24 hours to confirm your seat.\n"
    "Contact hr@acme-hiring.example for payment details.\n"
)


def test_seeding_is_idempotent(isolated_db):
    first = repository.seed_database()
    second = repository.seed_database()

    assert first["reports"] > 0
    assert first["references"] > 0
    assert second["reports"] == 0
    assert second["references"] == 0
    assert repository.count_reports(include_demo=True) == repository.count_reports(include_demo=True)


def test_analysis_round_trip(isolated_db):
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False)
    analysis_id = result.analysis_id

    assert repository.count_analyses() == 1
    listed = repository.list_analyses()
    assert listed[0]["analysis_id"] == analysis_id

    loaded = repository.get_analysis(analysis_id)
    assert loaded is not None
    assert loaded.score == result.score
    assert loaded.risk_category == result.risk_category
    assert loaded.analysis_id == analysis_id

    assert repository.delete_analysis(analysis_id) is True
    assert repository.count_analyses() == 0
    assert repository.get_analysis(analysis_id) is None


def test_delete_missing_analysis_returns_false(isolated_db):
    assert repository.delete_analysis("OG-DOES-NOT-EXIST") is False


def test_add_report_skips_exact_duplicates(isolated_db):
    report = {
        "company_name": "Duplicate Test Co",
        "sender_domain": "hr@duplicate-test.example",
        "category": "Fee fraud",
        "description": "They demanded a registration fee before joining the internship.",
        "status": "submitted",
    }

    first = repository.add_report(report)
    second = repository.add_report(report)

    assert first["created"] is True
    assert second["created"] is False
    assert repository.count_reports(include_demo=False) == 1


def test_find_reports_for_groups_domain_and_company(seeded_db):
    matches = repository.find_reports_for("Zenith Global Technologies", "zenithglobaltechnologies.example")

    assert matches["domain"]
    assert matches["domain"][0]["status"] == "corroborated"


def test_get_stats_shape(seeded_db):
    stats = repository.get_stats()

    assert set(stats) == {"analyses", "reports", "user_reports"}
    assert stats["reports"] >= stats["user_reports"]
    assert stats["analyses"] == 0


def test_findings_table_stores_confidence(isolated_db):
    result = run_analysis_from_text(SCAM_LETTER, allow_external=False)
    repository.save_analysis(result)

    from database import db as db_module

    connection = db_module.get_connection(isolated_db)
    try:
        rows = connection.execute(
            "SELECT rule_id, confidence FROM findings WHERE analysis_id = ?",
            (result.analysis_id,),
        ).fetchall()
    finally:
        connection.close()

    assert rows
    assert all(row["confidence"] in ("high", "medium", "low") for row in rows)


def test_migration_adds_confidence_column_to_legacy_findings(tmp_path):
    import sqlite3

    from database import db as db_module

    legacy = tmp_path / "legacy.db"
    connection = sqlite3.connect(legacy)
    connection.execute(
        """
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            module TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            points INTEGER NOT NULL,
            evidence TEXT,
            explanation TEXT
        )
        """
    )
    connection.commit()
    connection.close()

    db_module.init_db(legacy)

    connection = sqlite3.connect(legacy)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}
    connection.close()
    assert "confidence" in columns
