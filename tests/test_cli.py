import json
from pathlib import Path

from typer.testing import CliRunner

from ai_firewall.cli.main import cli

runner = CliRunner()


def test_eval_outputs_decision_json(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(cli, ["eval", "echo hello", "--audit", str(audit)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["decision"] == "ALLOW"
    assert payload["intent"] == "SHELL_EXEC"


def test_eval_block_returns_block_decision():
    result = runner.invoke(cli, ["eval", "rm -rf /"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["decision"] == "BLOCK"


def test_run_blocks_dangerous_command(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(cli, ["run", "rm -rf /", "--audit", str(audit)])
    assert result.exit_code == 126
    assert "BLOCK" in result.output or "BLOCK" in (result.stderr or "")
    lines = audit.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["decision"] == "BLOCK"
    assert rec["executed"] is False


def test_policy_show_runs():
    result = runner.invoke(cli, ["policy", "show"])
    assert result.exit_code == 0
    assert "shell_exec" in result.output


def test_policy_lint_valid(tmp_path: Path):
    f = tmp_path / "rules.yaml"
    f.write_text("shell_exec:\n  blocked: ['foo']\n", encoding="utf-8")
    result = runner.invoke(cli, ["policy", "lint", str(f)])
    assert result.exit_code == 0
    assert "ok" in result.output


def test_policy_lint_invalid(tmp_path: Path):
    f = tmp_path / "bad.yaml"
    f.write_text("- not a mapping\n", encoding="utf-8")
    result = runner.invoke(cli, ["policy", "lint", str(f)])
    assert result.exit_code == 1


def test_run_auto_approve_executes_file_delete(tmp_path: Path):
    target = tmp_path / "x.txt"
    target.write_text("data", encoding="utf-8")
    audit = tmp_path / "audit.jsonl"
    # FILE_DELETE always requires approval per default rules; --auto-approve should execute it.
    result = runner.invoke(
        cli,
        ["run", f"rm {target}", "--auto-approve", "--audit", str(audit)],
    )
    assert result.exit_code == 0, result.output
    assert not target.exists()


def test_run_auto_deny_blocks_without_prompt(tmp_path: Path):
    target = tmp_path / "x.txt"
    target.write_text("data", encoding="utf-8")
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        cli,
        ["run", f"rm {target}", "--auto-deny", "--audit", str(audit)],
    )
    assert result.exit_code == 126
    assert target.exists()


def test_auto_approve_and_deny_conflict():
    result = runner.invoke(cli, ["run", "echo hi", "--auto-approve", "--auto-deny"])
    assert result.exit_code == 2


def test_sql_evaluate_only_outputs_decision():
    result = runner.invoke(cli, ["sql", "SELECT * FROM users", "--evaluate-only"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["decision"] == "ALLOW"
    assert payload["intent"] == "DB_READ"


def test_sql_drop_database_blocked():
    result = runner.invoke(cli, ["sql", "DROP DATABASE prod", "--evaluate-only"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["decision"] == "BLOCK"


def test_sql_auto_approve_executes_analyze_only(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        cli,
        ["sql", "DELETE FROM users WHERE id=1", "--auto-approve", "--audit", str(audit)],
    )
    assert result.exit_code == 0, result.output
    assert "approved (analyze-only)" in result.output
    rec = json.loads(audit.read_text(encoding="utf-8").strip())
    assert rec["intent"] == "DB_DESTRUCTIVE"
    assert rec["executed"] is False


def test_api_evaluate_only_outputs_decision(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        cli,
        ["api", "GET", "https://api.example.com/users", "--evaluate-only", "--audit", str(audit)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["intent"] == "API_READ"
    assert payload["decision"] == "ALLOW"


def test_scan_argument_clean():
    result = runner.invoke(cli, ["scan", "nothing to see here", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []


def test_scan_argument_finds_ssn():
    result = runner.invoke(cli, ["scan", "my SSN is 123-45-6789", "--json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert any("SSN" in f for f in payload["findings"])
    assert payload["severity"] == "critical"


def test_scan_reads_from_stdin_when_dash():
    """v0.4.1: `guard scan -` reads the text from stdin."""
    result = runner.invoke(cli, ["scan", "-", "--json"], input="leak: AKIAIOSFODNN7EXAMPLE\n")
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert any("AWS" in f or "aws" in f.lower() for f in payload["findings"])


def test_scan_reads_from_stdin_when_no_arg():
    """v0.4.1: `guard scan` (no arg) also reads stdin."""
    result = runner.invoke(cli, ["scan", "--json"], input="boring text\n")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["findings"] == []


def test_scan_empty_input_errors():
    """No arg, empty stdin → exit 2 with helpful message."""
    result = runner.invoke(cli, ["scan", "--json"], input="")
    assert result.exit_code == 2, result.output


def test_api_metadata_endpoint_high_severity():
    result = runner.invoke(
        cli, ["api", "GET", "http://169.254.169.254/latest/meta-data/", "--evaluate-only"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["risk"] == "CRITICAL"
    assert payload["decision"] == "REQUIRE_APPROVAL"


def test_api_auto_approve_executes_analyze_only(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    result = runner.invoke(
        cli,
        ["api", "DELETE", "https://api.example.com/users/42", "--auto-approve", "--audit", str(audit)],
    )
    assert result.exit_code == 0, result.output
    assert "approved (analyze-only)" in result.output
    rec = json.loads(audit.read_text(encoding="utf-8").strip())
    assert rec["intent"] == "API_DESTRUCTIVE"
    assert rec["executed"] is False


def test_sql_execute_requires_connection():
    result = runner.invoke(cli, ["sql", "SELECT 1", "--execute", "--auto-approve"])
    assert result.exit_code == 2


def test_sql_execute_runs_against_sqlite(tmp_path: Path):
    import sqlite3
    db = tmp_path / "demo.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1), (2);")
    conn.commit()
    conn.close()
    audit = tmp_path / "audit.jsonl"

    result = runner.invoke(
        cli,
        [
            "sql", "SELECT x FROM t ORDER BY x",
            "--execute", "--connection", str(db),
            "--auto-approve", "--audit", str(audit),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "x\n1\n2" in result.output
    rec = json.loads(audit.read_text(encoding="utf-8").strip())
    assert rec["executed"] is True
    assert rec["exit_code"] == 0


def test_api_execute_with_auto_deny_does_not_send_request(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    # CRITICAL metadata host → REQUIRE_APPROVAL → auto-deny → blocked.
    # No real request goes out (auto-deny short-circuits before the adapter runs).
    result = runner.invoke(
        cli,
        [
            "api", "GET", "http://169.254.169.254/latest/meta-data/",
            "--execute", "--auto-deny", "--audit", str(audit),
        ],
    )
    assert result.exit_code == 126
    rec = json.loads(audit.read_text(encoding="utf-8").strip())
    assert rec["intent"] == "API_READ"
    assert rec["risk"] == "CRITICAL"
    assert rec["executed"] is False  # rejected before the adapter could fire
