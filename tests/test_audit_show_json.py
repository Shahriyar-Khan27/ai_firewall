"""v0.5.0 — `guard audit show --json` / `--limit` for the extension status sidebar."""
from __future__ import annotations

import json
import time
from pathlib import Path

from typer.testing import CliRunner

from ai_firewall.cli.main import cli

runner = CliRunner()


def _seed_audit(path: Path, n: int = 5) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with path.open("w", encoding="utf-8") as fh:
        for i in range(n):
            rec = {
                "ts": now - (n - i),
                "type": "shell",
                "intent": "SHELL_EXEC",
                "risk": "LOW",
                "decision": "ALLOW",
                "reason": "no matching block or approval rule",
                "rendered": f"echo {i}",
                "approved": True,
                "executed": True,
                "exit_code": 0,
            }
            fh.write(json.dumps(rec) + "\n")


def test_audit_show_json_returns_array(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _seed_audit(log, n=3)
    result = runner.invoke(cli, ["audit", "show", str(log), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 3
    assert payload[0]["intent"] == "SHELL_EXEC"
    assert payload[0]["rendered"] == "echo 0"


def test_audit_show_json_limit_returns_most_recent(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    _seed_audit(log, n=10)
    result = runner.invoke(cli, ["audit", "show", str(log), "--json", "--limit", "3"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    # Last-3 slice — most recent timestamps
    assert len(payload) == 3
    assert [r["rendered"] for r in payload] == ["echo 7", "echo 8", "echo 9"]


def test_audit_show_json_missing_file_returns_empty_array(tmp_path: Path):
    """Extension polling shouldn't error when the user has no audit log yet."""
    result = runner.invoke(cli, ["audit", "show", str(tmp_path / "absent.jsonl"), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == []


def test_audit_show_json_skips_init_header(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with log.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"event": "init", "ts": now, "key_fingerprint": "abc"}) + "\n")
        fh.write(json.dumps({"ts": now, "type": "shell", "intent": "SHELL_EXEC", "decision": "ALLOW"}) + "\n")
    result = runner.invoke(cli, ["audit", "show", str(log), "--json"])
    assert result.exit_code == 0
    records = json.loads(result.output)
    assert len(records) == 1  # init header stripped
    assert records[0]["intent"] == "SHELL_EXEC"


def test_audit_show_text_mode_unchanged(tmp_path: Path):
    """Existing human-readable output still works (regression guard)."""
    log = tmp_path / "audit.jsonl"
    _seed_audit(log, n=2)
    result = runner.invoke(cli, ["audit", "show", str(log)])
    assert result.exit_code == 0
    assert "SHELL_EXEC" not in result.output  # text mode shows intent abbreviation? no — type column
    assert "ALLOW" in result.output
    assert "echo 0" in result.output
    assert "echo 1" in result.output
