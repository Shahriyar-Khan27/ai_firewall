from ai_firewall.engine import url_analysis


def test_plain_get_is_clean():
    a = url_analysis.analyze("GET", "https://api.example.com/users")
    assert a.parse_ok
    assert a.findings == ()
    assert a.severity == "none"
    assert url_analysis.primary_intent("GET") == "API_READ"


def test_post_classified_as_write():
    assert url_analysis.primary_intent("POST") == "API_WRITE"
    assert url_analysis.primary_intent("PUT") == "API_WRITE"
    assert url_analysis.primary_intent("PATCH") == "API_WRITE"


def test_delete_classified_as_destructive():
    assert url_analysis.primary_intent("DELETE") == "API_DESTRUCTIVE"


def test_unknown_method_treated_conservatively():
    assert url_analysis.primary_intent("FOO") == "API_WRITE"


def test_metadata_endpoint_is_critical():
    a = url_analysis.analyze("GET", "http://169.254.169.254/latest/meta-data/")
    assert a.severity == "critical"
    assert a.is_metadata_host
    assert any("metadata" in f for f in a.findings)


def test_private_ip_is_major():
    a = url_analysis.analyze("GET", "http://10.0.0.5/internal")
    assert a.severity == "major"
    assert a.is_private_ip


def test_localhost_is_private():
    a = url_analysis.analyze("GET", "http://localhost:8080/api")
    assert a.is_private_ip
    assert a.severity == "major"


def test_creds_in_userinfo_flagged():
    a = url_analysis.analyze("POST", "https://user:pass@api.example.com/login")
    assert a.has_userinfo
    assert any("userinfo" in f for f in a.findings)


def test_secrets_in_query_flagged():
    a = url_analysis.analyze("GET", "https://api.example.com/x?api_key=abc&page=1")
    assert "api_key" in a.secret_query_params
    assert any("secrets in query string" in f for f in a.findings)


def test_file_scheme_flagged():
    a = url_analysis.analyze("GET", "file:///etc/passwd")
    assert a.is_unsafe_scheme
    assert a.severity == "major"


def test_destructive_path_for_post_flagged():
    a = url_analysis.analyze("POST", "https://api.example.com/admin/delete-all")
    assert a.destructive_path
    assert any("destructive-sounding" in f for f in a.findings)


def test_destructive_path_only_for_write_methods():
    # Same path with GET should NOT be flagged — reading /admin/delete is informational.
    a = url_analysis.analyze("GET", "https://api.example.com/admin/delete-all")
    assert all("destructive-sounding" not in f for f in a.findings)


def test_empty_url_is_major():
    a = url_analysis.analyze("GET", "")
    assert not a.parse_ok
    assert a.severity == "major"


def test_no_scheme_is_minor():
    a = url_analysis.analyze("GET", "api.example.com/users")
    # "api.example.com/users" parses but has no scheme.
    assert a.severity == "minor"
    assert any("no scheme" in f for f in a.findings)
