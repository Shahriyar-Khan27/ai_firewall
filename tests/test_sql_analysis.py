from ai_firewall.engine import sql_analysis


def test_select_is_clean():
    a = sql_analysis.analyze("SELECT * FROM users")
    assert a.parse_ok
    assert a.statements == ("SELECT",)
    assert a.tables == ("users",)
    assert a.findings == ()
    assert sql_analysis.primary_intent(a.statements) == "DB_READ"


def test_delete_without_where_is_critical():
    a = sql_analysis.analyze("DELETE FROM users")
    assert any("without WHERE" in f for f in a.findings)
    assert a.severity == "critical"
    assert sql_analysis.primary_intent(a.statements) == "DB_DESTRUCTIVE"


def test_delete_with_where_is_major():
    a = sql_analysis.analyze("DELETE FROM users WHERE id = 1")
    assert a.severity == "major"
    assert all("without WHERE" not in f for f in a.findings)


def test_update_without_where_is_critical():
    a = sql_analysis.analyze("UPDATE users SET name='x'")
    assert a.severity == "critical"
    assert any("UPDATE without WHERE" in f for f in a.findings)


def test_update_with_where_is_minor():
    a = sql_analysis.analyze("UPDATE users SET name='x' WHERE id=1")
    assert a.severity in ("none", "minor")
    assert sql_analysis.primary_intent(a.statements) == "DB_WRITE"


def test_drop_table_is_major():
    a = sql_analysis.analyze("DROP TABLE users")
    assert a.severity == "major"
    assert any("DROP TABLE" in f for f in a.findings)


def test_drop_database_is_critical():
    a = sql_analysis.analyze("DROP DATABASE prod")
    assert a.severity == "critical"
    assert any("DROP DATABASE" in f for f in a.findings)


def test_truncate_is_major():
    a = sql_analysis.analyze("TRUNCATE users")
    assert a.statements == ("TRUNCATE",)
    assert a.severity == "major"
    assert sql_analysis.primary_intent(a.statements) == "DB_DESTRUCTIVE"


def test_grant_is_destructive():
    a = sql_analysis.analyze("GRANT ALL ON db.* TO 'bob'@'%'")
    assert any("privilege change" in f for f in a.findings)
    assert sql_analysis.primary_intent(a.statements) == "DB_DESTRUCTIVE"


def test_multiple_statements_flagged():
    a = sql_analysis.analyze("SELECT 1; DROP TABLE x")
    assert any("multiple statements" in f for f in a.findings)
    assert sql_analysis.primary_intent(a.statements) == "DB_DESTRUCTIVE"


def test_unparseable_sql_is_major():
    a = sql_analysis.analyze("not valid sql at all >>><<<")
    assert not a.parse_ok
    assert a.severity == "major"


def test_empty_sql_is_safe_but_useless():
    a = sql_analysis.analyze("")
    assert not a.parse_ok
    assert a.severity == "none"
