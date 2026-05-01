"""Feature 2 — PII scanner."""
from ai_firewall.engine.pii_scan import _luhn_valid, scan


# --- Empty / clean ---


def test_empty_returns_clean():
    r = scan("")
    assert r.findings == ()
    assert r.severity == "none"


def test_lorem_ipsum_returns_clean():
    r = scan("just some lorem ipsum text without any secrets")
    assert r.findings == ()


# --- Email ---


def test_email_detected():
    r = scan("contact me at john.doe@example.com please")
    assert r.severity == "major"
    assert any("email" in f for f in r.findings)


def test_email_count():
    r = scan("emails: a@b.co, c@d.io, e@f.net")
    finding = next(f for f in r.findings if "email" in f)
    assert "(3 found)" in finding


# --- SSN ---


def test_ssn_detected():
    r = scan("my SSN is 123-45-6789")
    assert r.severity == "critical"
    assert any("SSN" in f for f in r.findings)


def test_invalid_ssn_areas_skipped():
    """000-XX-XXXX, 666-XX-XXXX, 9XX-XX-XXXX are publicly-known invalid blocks."""
    for ssn in ("000-12-3456", "666-12-3456", "987-12-3456"):
        r = scan(f"id: {ssn}")
        assert all("SSN" not in f for f in r.findings), f"unexpected match on {ssn}"


# --- Credit cards ---


def test_luhn_valid_visa_test_card():
    """4242 4242 4242 4242 is the canonical Stripe test Visa — valid Luhn."""
    r = scan("card: 4242 4242 4242 4242")
    assert r.severity == "critical"
    assert any("credit-card" in f for f in r.findings)


def test_luhn_invalid_random_digits_skipped():
    r = scan("not a card: 1234 5678 9012 3456")  # Luhn sum != 0
    assert all("credit-card" not in f for f in r.findings)


def test_luhn_helper():
    assert _luhn_valid("4242424242424242") is True
    assert _luhn_valid("1234567890123456") is False


# --- Phone ---


def test_us_phone_detected():
    r = scan("call 555-123-4567")
    assert any("phone" in f for f in r.findings)


def test_e164_phone_detected():
    r = scan("reach me at +91 9876543210")
    assert any("phone" in f for f in r.findings)


def test_random_digit_string_not_flagged_as_phone():
    r = scan("error code: 12 345 678")
    assert all("phone" not in f for f in r.findings)


# --- IBAN ---


def test_german_iban_detected():
    r = scan("IBAN: DE89370400440532013000")
    assert r.severity == "critical"
    assert any("IBAN" in f for f in r.findings)


def test_random_22char_blob_not_iban():
    """SHA-1ish blob starting with letters+digits should NOT trigger IBAN."""
    r = scan("hash: ZZ12abcdefghij1234567890")
    assert all("IBAN" not in f for f in r.findings)


# --- High-entropy fallback ---


def test_high_entropy_fallback_when_nothing_else_fired():
    r = scan("token: dGhpcy1pcy1hLXJlYWxseS1sb25nLWJhc2U2NC1zdHJpbmc")
    assert r.severity == "minor"


def test_high_entropy_does_not_overshadow_real_findings():
    r = scan("email: x@y.com and token: dGhpcyBpcyBhIHJlYWxseSBsb25nIHRva2Vu")
    # Real finding (email) takes precedence; high-entropy is suppressed
    assert all("high-entropy" not in f for f in r.findings)
    assert any("email" in f for f in r.findings)


# --- Mixed ---


def test_multiple_pii_types_all_surface():
    r = scan("email john@x.com, ssn 123-45-6789, card 4242424242424242")
    kinds = [f for f in r.findings if "PII" in f]
    assert any("email" in f for f in kinds)
    assert any("SSN" in f for f in kinds)
    assert any("credit-card" in f for f in kinds)
    assert r.severity == "critical"
