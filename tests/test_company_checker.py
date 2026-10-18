import config
from services import company_checker
from services.company_checker import detect_lookalike, run_company_check


def _rule_ids(result):
    return {finding.rule_id for finding in result["findings"]}


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _enable_external(monkeypatch, addresses=None):
    """Turn external lookups back on for one test, with DNS and HTTP faked out."""
    monkeypatch.setattr(config, "EXTERNAL_LOOKUPS_ENABLED", True)
    monkeypatch.setattr(company_checker, "_RDAP_CACHE", {})
    resolved = addresses or [("93.184.216.34", 0)]
    monkeypatch.setattr(
        company_checker.socket,
        "getaddrinfo",
        lambda host, port: [(2, 1, 6, "", entry) for entry in resolved],
    )


def _registration_payload():
    return {
        "events": [{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"}],
        "entities": [],
    }


def test_detect_lookalike_flags_similar_domains():
    result = detect_lookalike("infosys-careers.com", "infosys.com")
    assert result["is_lookalike"] is True

    unrelated = detect_lookalike("random-unrelated-name.com", "infosys.com")
    assert unrelated["is_lookalike"] is False


def test_free_mail_sender_is_flagged():
    result = run_company_check(company_name="Infosys", sender_email="hr@gmail.com", allow_external=False)

    assert "COMPANY-FREE-MAIL-SENDER" in _rule_ids(result)
    assert result["status"] == "concerns"


def test_lookalike_domain_against_reference_is_flagged(seeded_db):
    result = run_company_check(
        company_name="Infosys",
        sender_email="hr@infosys-careers.com",
        allow_external=False,
    )

    assert "COMPANY-LOOKALIKE-DOMAIN" in _rule_ids(result)
    assert result["status"] == "concerns"


def test_domain_mismatch_against_reference(seeded_db):
    result = run_company_check(
        company_name="Infosys",
        sender_email="hr@unrelated-employment.com",
        allow_external=False,
    )

    ids = _rule_ids(result)
    assert "COMPANY-DOMAIN-MISMATCH" in ids
    assert "COMPANY-LOOKALIKE-DOMAIN" not in ids


def test_official_domain_match_is_verified(seeded_db):
    result = run_company_check(
        company_name="Infosys",
        sender_email="hr@infosys.com",
        allow_external=False,
    )

    assert result["status"] == "verified"
    assert all(finding.points == 0 for finding in result["findings"])


def test_company_without_sender_email_is_a_minor_concern():
    result = run_company_check(company_name="Some Company", sender_email="", allow_external=False)

    assert "COMPANY-NO-SENDER-EMAIL" in _rule_ids(result)


def test_unknown_company_leaves_status_unknown():
    result = run_company_check(
        company_name="Completely Unknown Ventures",
        sender_email="hr@unknown-ventures.com",
        allow_external=False,
    )

    assert result["status"] == "unknown"


def test_external_check_reports_that_it_was_disabled():
    result = run_company_check(
        company_name="Infosys",
        sender_email="hr@infosys.com",
        allow_external=False,
    )

    assert "disabled" in result["registration"]["message"].lower()
    assert result["registration"]["checked"] is False


def test_external_registration_path_completes_without_crashing(monkeypatch):
    """Regression test: the external branch used to raise NameError before any request."""
    _enable_external(monkeypatch)
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _FakeResponse(200, _registration_payload())

    monkeypatch.setattr(company_checker.requests, "get", fake_get)

    result = run_company_check(
        company_name="Some Unknown Firm",
        sender_email="hr@unrelated-employment.com",
        allow_external=True,
    )

    registration = result["registration"]
    assert registration["status"] == "ok"
    assert registration["checked"] is True
    assert calls, "the RDAP endpoint should have been requested"
    host = calls[0].split("/")[2]
    assert host in config.APPROVED_LOOKUP_HOSTS


def test_private_destination_is_blocked(monkeypatch):
    _enable_external(monkeypatch, addresses=[("10.0.0.5", 0)])

    outcome = company_checker.check_domain_registration("example.com", allow_external=True)

    assert outcome["status"] == "blocked"
    assert outcome["checked"] is False


def test_rdap_transient_failure_is_not_cached(monkeypatch):
    _enable_external(monkeypatch)
    attempts = {"count": 0}

    def flaky_get(url, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise company_checker.requests.exceptions.Timeout()
        return _FakeResponse(200, _registration_payload())

    monkeypatch.setattr(company_checker.requests, "get", flaky_get)

    first = company_checker.check_domain_registration("example.com", allow_external=True)
    second = company_checker.check_domain_registration("example.com", allow_external=True)

    assert first["status"] == "timeout"
    assert second["status"] == "ok"
    assert second.get("cached") is not True


def test_rdap_success_is_cached(monkeypatch):
    _enable_external(monkeypatch)
    calls = {"count": 0}

    def fake_get(url, **kwargs):
        calls["count"] += 1
        return _FakeResponse(200, _registration_payload())

    monkeypatch.setattr(company_checker.requests, "get", fake_get)

    first = company_checker.check_domain_registration("example.com", allow_external=True)
    second = company_checker.check_domain_registration("example.com", allow_external=True)

    assert first["status"] == "ok"
    assert second.get("cached") is True
    assert calls["count"] == 1
