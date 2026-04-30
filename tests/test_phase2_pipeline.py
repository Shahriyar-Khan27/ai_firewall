"""Phase 2 integration tests: code-aware risk + git findings flow into Decision."""
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve
from ai_firewall.core.action import Action, RiskLevel
from ai_firewall.core.guard import Blocked, Guard


def _guard(tmp_path: Path) -> Guard:
    return Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_approve)


def test_diff_attached_to_decision(tmp_path: Path):
    target = tmp_path / "notes.txt"
    target.write_text("old line\n", encoding="utf-8")
    g = _guard(tmp_path)
    decision = g.evaluate(
        Action(
            type="file",
            payload={"op": "write", "path": str(target), "content": "new line\n"},
            context={"cwd": str(tmp_path)},
        )
    )
    assert decision.impact.lines_added == 1
    assert decision.impact.lines_removed == 1
    assert "-old line" in decision.impact.diff
    assert "+new line" in decision.impact.diff


def test_removing_function_bumps_risk_to_high(tmp_path: Path):
    src = tmp_path / "mod.py"
    src.write_text("def keep():\n    return 1\n\ndef gone():\n    return 2\n", encoding="utf-8")
    g = _guard(tmp_path)
    decision = g.evaluate(
        Action(
            type="file",
            payload={"op": "write", "path": str(src), "content": "def keep():\n    return 1\n"},
            context={"cwd": str(tmp_path)},
        )
    )
    assert decision.risk >= RiskLevel.HIGH
    assert any("removes function" in f for f in decision.impact.code_findings)


def test_auth_keyword_bumps_risk(tmp_path: Path):
    src = tmp_path / "auth.py"
    src.write_text("x = 1\n", encoding="utf-8")
    g = _guard(tmp_path)
    decision = g.evaluate(
        Action(
            type="file",
            payload={"op": "write", "path": str(src), "content": "password = 'hunter2'\n"},
            context={"cwd": str(tmp_path)},
        )
    )
    assert decision.risk >= RiskLevel.HIGH
    assert any("sensitive" in f for f in decision.impact.code_findings)


def test_safe_text_edit_stays_low_risk(tmp_path: Path):
    src = tmp_path / "notes.md"
    src.write_text("# old\n", encoding="utf-8")
    g = _guard(tmp_path)
    decision = g.evaluate(
        Action(
            type="file",
            payload={"op": "write", "path": str(src), "content": "# new\n"},
            context={"cwd": str(tmp_path)},
        )
    )
    assert decision.risk <= RiskLevel.MEDIUM
    assert decision.impact.code_findings == ()
