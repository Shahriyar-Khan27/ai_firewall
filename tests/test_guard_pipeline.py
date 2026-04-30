import json
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard


def _guard(tmp_path: Path, approval_fn=auto_deny) -> Guard:
    return Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=approval_fn)


def test_block_path_does_not_execute(tmp_path: Path):
    g = _guard(tmp_path)
    target = tmp_path / "should_not_be_touched.txt"
    target.write_text("safe")
    with pytest.raises(Blocked) as ei:
        g.execute(Action.shell("rm -rf /"))
    assert ei.value.decision.decision == "BLOCK"
    assert target.exists()
    assert (tmp_path / "audit.jsonl").exists()


def test_allow_path_executes(tmp_path: Path):
    g = _guard(tmp_path)
    res = g.execute(Action.shell("echo hello", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"
    assert res.execution.exit_code == 0
    assert "hello" in res.execution.stdout


def test_approval_denied_blocks_execution(tmp_path: Path):
    g = _guard(tmp_path, approval_fn=auto_deny)
    target = tmp_path / "x.txt"
    target.write_text("data")
    with pytest.raises(Blocked):
        g.execute(Action.file("delete", str(target)))
    assert target.exists()


def test_approval_granted_executes(tmp_path: Path):
    g = _guard(tmp_path, approval_fn=auto_approve)
    target = tmp_path / "x.txt"
    target.write_text("data")
    res = g.execute(Action.file("delete", str(target)))
    assert res.decision.decision == "REQUIRE_APPROVAL"
    assert res.execution.exit_code == 0
    assert not target.exists()


def test_audit_log_is_jsonl(tmp_path: Path):
    g = _guard(tmp_path, approval_fn=auto_approve)
    g.execute(Action.shell("echo a", cwd=str(tmp_path)))
    g.execute(Action.shell("echo b", cwd=str(tmp_path)))
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        rec = json.loads(line)
        assert rec["decision"] == "ALLOW"
        assert rec["executed"] is True
