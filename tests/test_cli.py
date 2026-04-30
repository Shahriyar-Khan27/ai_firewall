import json
from pathlib import Path

from typer.testing import CliRunner

from ai_firewall.cli.main import cli

runner = CliRunner()


def test_eval_outputs_decision_json(tmp_path: Path):
    result = runner.invoke(cli, ["eval", "echo hello"])
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
