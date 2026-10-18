from services import normalizer


def test_normalize_company_strips_legal_suffixes_and_punctuation():
    assert normalizer.normalize_company("Infosys Ltd.") == "infosys"
    assert normalizer.normalize_company("Tata Consultancy Services Private Limited") == "tata consultancy services"
    assert normalizer.normalize_company("Acme Technologies Pvt. Ltd.") == "acme technologies"


def test_normalize_company_handles_empty_values():
    assert normalizer.normalize_company("") == ""
    assert normalizer.normalize_company(None) == ""


def test_registered_domain_handles_subdomains_and_multi_part_suffixes():
    assert normalizer.registered_domain("hr@infosys-careers.com") == "infosys-careers.com"
    assert normalizer.registered_domain("https://www.tcs.com/careers/apply") == "tcs.com"
    assert normalizer.registered_domain("mail.tcs.co.in") == "tcs.co.in"
    assert normalizer.registered_domain("careers.wipro.com") == "wipro.com"
    assert normalizer.registered_domain("") == ""


def test_email_and_domain_validation():
    assert normalizer.is_valid_email("hr@acme.com") is True
    assert normalizer.is_valid_email("hr@acme") is False
    assert normalizer.is_valid_email("hr at acme.com") is False
    assert normalizer.is_valid_email(None) is False

    assert normalizer.is_valid_domain("acme.com") is True
    assert normalizer.is_valid_domain("not a domain") is False
    assert normalizer.is_valid_domain("localhost") is False


def test_describe_domain_input_classifies_values():
    assert normalizer.describe_domain_input("")["kind"] == "empty"
    assert normalizer.describe_domain_input("https://acme.com/apply")["kind"] == "url"
    assert normalizer.describe_domain_input("hr@acme.com")["kind"] == "email"
    assert normalizer.describe_domain_input("acme.com")["kind"] == "domain"
    assert normalizer.describe_domain_input("hr@acme.com")["registered_domain"] == "acme.com"


def test_extract_emails_and_urls_are_lowercased_and_deduplicated():
    emails = normalizer.extract_emails("Contact HR@Acme.com or hr@acme.com today.")
    assert emails == ["hr@acme.com"]

    urls = normalizer.extract_urls("Visit https://Acme.com/apply and https://acme.com again.")
    assert urls == ["acme.com"]
