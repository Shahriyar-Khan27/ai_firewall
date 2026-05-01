"""Tests for the MCP server tool functions.

Tests call the tool functions directly (bypassing the MCP transport) since
that's what FastMCP routes them to anyway. The transport layer is exercised
by `mcp` SDK's own tests.
"""
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from ai_firewall.mcp_server import (  # noqa: E402
    firewall_evaluate_shell,
    firewall_run_api,
    firewall_run_file,
    firewall_run_shell,
    firewall_run_sql,
    firewall_show_policy,
)


def test_run_shell_allows_safe_command():
    res = firewall_run_shell("echo hello")
    assert res["blocked"] is False
    assert res["executed"] is True
    assert res["exit_code"] == 0
    assert "hello" in res["stdout"]


def test_run_shell_blocks_rm_rf_root():
    res = firewall_run_shell("rm -rf /")
    assert res["blocked"] is True
    assert res["decision"]["decision"] == "BLOCK"
    assert res["decision"]["risk"] == "CRITICAL"


def test_run_shell_blocks_require_approval_by_default():
    res = firewall_run_shell("rm tmp.txt")
    assert res["blocked"] is True
    assert "REQUIRE_APPROVAL" in res["reason"]


def test_run_shell_approval_approve_lets_through():
    # File doesn't exist → adapter would error, but at least it won't be blocked at policy stage
    res = firewall_run_shell("echo approved!", approval="approve")
    assert res["blocked"] is False


def test_evaluate_shell_returns_decision():
    decision = firewall_evaluate_shell("rm -rf /")
    assert decision["decision"] == "BLOCK"
    assert decision["intent"] == "FILE_DELETE"
    assert decision["risk"] == "CRITICAL"


def test_run_sql_blocks_drop_database():
    res = firewall_run_sql("DROP DATABASE prod")
    assert res["blocked"] is True
    assert res["decision"]["decision"] == "BLOCK"


def test_run_sql_blocks_delete_without_where():
    res = firewall_run_sql("DELETE FROM users")
    assert res["blocked"] is True
    assert res["decision"]["risk"] == "CRITICAL"


def test_run_sql_allows_select():
    res = firewall_run_sql("SELECT * FROM users")
    assert res["blocked"] is False
    assert res["executed"] is False  # analyze-only without connection
    assert "approved (analyze-only)" in res["stdout"]


def test_run_sql_with_connection_actually_executes(tmp_path: Path):
    db = tmp_path / "test.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1), (2);")
    conn.commit()
    conn.close()

    res = firewall_run_sql("SELECT x FROM t ORDER BY x", connection=str(db))
    assert res["blocked"] is False
    assert res["executed"] is True
    assert "x\n1\n2" in res["stdout"]


def test_run_api_blocks_metadata_endpoint():
    res = firewall_run_api("GET", "http://169.254.169.254/latest/meta-data/")
    assert res["blocked"] is True
    assert res["decision"]["risk"] == "CRITICAL"


def test_run_api_blocks_aws_key_in_body():
    res = firewall_run_api(
        "POST", "https://api.example.com/log",
        body='{"key": "AKIAIOSFODNN7EXAMPLE"}',
    )
    assert res["blocked"] is True
    assert res["decision"]["risk"] == "CRITICAL"


def test_run_api_analyze_only_by_default():
    res = firewall_run_api("GET", "https://api.example.com/users")
    assert res["blocked"] is False
    assert res["executed"] is False


def test_run_file_blocks_etc_passwd_write():
    res = firewall_run_file("write", "/etc/passwd", content="root::0:0::/:/bin/sh")
    assert res["blocked"] is True
    assert res["decision"]["decision"] == "BLOCK"


def test_show_policy_returns_yaml():
    yaml_text = firewall_show_policy()
    assert "shell_exec" in yaml_text
    assert "db_destructive" in yaml_text
    assert "api_destructive" in yaml_text
