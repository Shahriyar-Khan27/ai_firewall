from pathlib import Path

from ai_firewall.engine import code_analysis


def test_no_changes_no_findings():
    src = "def foo():\n    return 1\n"
    res = code_analysis.analyze(Path("a.py"), src, src)
    assert res.findings == ()
    assert res.severity == "none"


def test_removed_function_flagged():
    old = "def foo():\n    return 1\n\ndef bar():\n    return 2\n"
    new = "def foo():\n    return 1\n"
    res = code_analysis.analyze(Path("mod.py"), old, new)
    assert any("removes function" in f for f in res.findings)
    assert res.severity == "major"


def test_removed_test_function_flagged():
    old = "def test_one():\n    assert True\n\ndef test_two():\n    assert True\n"
    new = "def test_one():\n    assert True\n"
    res = code_analysis.analyze(Path("test_x.py"), old, new)
    assert any("test function" in f for f in res.findings)
    assert any("test file" in f for f in res.findings)
    assert res.severity == "major"


def test_auth_keyword_flagged():
    old = "x = 1\n"
    new = "password = 'hunter2'\n"
    res = code_analysis.analyze(Path("c.py"), old, new)
    assert any("sensitive identifiers" in f for f in res.findings)
    assert res.severity == "major"


def test_syntax_error_flagged():
    old = "def foo(): return 1\n"
    new = "def foo(:\n"
    res = code_analysis.analyze(Path("c.py"), old, new)
    assert any("syntax error" in f for f in res.findings)
    assert res.severity == "major"


def test_empty_replacement_flagged():
    old = "def foo():\n    return 1\n"
    res = code_analysis.analyze(Path("c.py"), old, "")
    assert any("empty content" in f for f in res.findings)


def test_test_file_path_detection():
    src = "x = 1\n"
    res = code_analysis.analyze(Path("tests/test_app.py"), src, src + "y = 2\n")
    assert any("test file" in f for f in res.findings)


def test_non_python_files_skip_ast():
    old = "function foo() { return 1; }\n"
    new = "// gone\n"
    res = code_analysis.analyze(Path("a.js"), old, new)
    # No AST findings for JS, but no crash either.
    assert all("function" not in f or "test" in f or "sensitive" in f for f in res.findings)
