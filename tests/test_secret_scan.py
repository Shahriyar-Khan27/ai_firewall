from ai_firewall.engine import secret_scan


def test_empty_text_no_findings():
    r = secret_scan.scan("")
    assert r.findings == ()
    assert r.severity == "none"


def test_prose_mentioning_password_does_not_trigger():
    r = secret_scan.scan("the password we used last week was different")
    assert r.findings == ()


def test_aws_access_key_critical():
    r = secret_scan.scan('{"key": "AKIAIOSFODNN7EXAMPLE"}')
    assert r.severity == "critical"
    assert any("high-confidence secret leak" in f and "AWS access key id" in f for f in r.findings)


def test_github_pat_critical():
    r = secret_scan.scan("Authorization: Bearer ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901")
    assert r.severity == "critical"
    assert any("GitHub PAT" in f for f in r.findings)


def test_anthropic_key_critical():
    r = secret_scan.scan("sk-ant-api03-" + "a" * 40)
    assert r.severity == "critical"
    assert any("Anthropic API key" in f for f in r.findings)


def test_google_api_key_critical():
    r = secret_scan.scan("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI")
    assert r.severity == "critical"


def test_stripe_live_key_critical():
    r = secret_scan.scan("sk_live_" + "x" * 30)
    assert r.severity == "critical"


def test_pem_private_key_critical():
    r = secret_scan.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert r.severity == "critical"


def test_jwt_only_major():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    r = secret_scan.scan(jwt)
    assert r.severity == "major"
    assert any("possible secret in payload" in f and "JWT" in f for f in r.findings)


def test_password_assignment_with_quoted_value():
    r = secret_scan.scan('password = "correct horse battery staple"')
    assert r.severity == "major"
    assert any("sensitive field assignment" in f and "password" in f for f in r.findings)


def test_json_password_field():
    r = secret_scan.scan('{"password": "hunter2!"}')
    assert r.severity == "major"


def test_json_api_key_field():
    r = secret_scan.scan('{"api_key": "abc123def456"}')
    assert r.severity == "major"


def test_multiple_secrets_dedupe_by_label():
    r = secret_scan.scan(
        "AKIAIOSFODNN7EXAMPLE\nAKIAIOSFODNN7EXAMPLZ\nghp_" + "A" * 36
    )
    # AWS detected once (label dedup), GitHub PAT detected once.
    aws = [f for f in r.findings if "AWS access key id" in f]
    github = [f for f in r.findings if "GitHub PAT" in f]
    assert len(aws) == 1 and len(github) == 1
    assert r.severity == "critical"
