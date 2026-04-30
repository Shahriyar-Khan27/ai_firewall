"""Phase 3 integration tests: DB intent classification, risk scoring, policy, end-to-end."""
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine import risk as risk_mod


def _evaluate(action: Action, tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_deny)
    return g.evaluate(action)


def test_select_classified_as_db_read():
    a = Action.db("SELECT * FROM users")
    assert intent_mod.classify(a) is IntentType.DB_READ


def test_insert_classified_as_db_write():
    a = Action.db("INSERT INTO users(name) VALUES ('x')")
    assert intent_mod.classify(a) is IntentType.DB_WRITE


def test_drop_classified_as_db_destructive():
    a = Action.db("DROP TABLE users")
    assert intent_mod.classify(a) is IntentType.DB_DESTRUCTIVE


def test_db_read_low_risk(tmp_path: Path):
    decision = _evaluate(Action.db("SELECT * FROM users"), tmp_path)
    assert decision.risk == RiskLevel.LOW
    assert decision.decision == "ALLOW"


def test_db_write_baseline_medium(tmp_path: Path):
    decision = _evaluate(Action.db("INSERT INTO users(id) VALUES (1)"), tmp_path)
    assert decision.risk == RiskLevel.MEDIUM


def test_delete_without_where_bumps_to_critical(tmp_path: Path):
    decision = _evaluate(Action.db("DELETE FROM users"), tmp_path)
    assert decision.risk == RiskLevel.CRITICAL
    # Default rules block via require_approval:true on db_destructive.
    assert decision.decision == "REQUIRE_APPROVAL"


def test_delete_with_where_still_requires_approval(tmp_path: Path):
    decision = _evaluate(Action.db("DELETE FROM users WHERE id = 1"), tmp_path)
    assert decision.decision == "REQUIRE_APPROVAL"


def test_drop_database_blocked(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_deny)
    with pytest.raises(Blocked) as ei:
        g.execute(Action.db("DROP DATABASE prod"))
    assert ei.value.decision.decision == "BLOCK"


def test_drop_table_requires_approval(tmp_path: Path):
    decision = _evaluate(Action.db("DROP TABLE users"), tmp_path)
    assert decision.decision == "REQUIRE_APPROVAL"
    assert decision.intent is IntentType.DB_DESTRUCTIVE


def test_truncate_requires_approval(tmp_path: Path):
    decision = _evaluate(Action.db("TRUNCATE users"), tmp_path)
    assert decision.decision == "REQUIRE_APPROVAL"
    assert decision.intent is IntentType.DB_DESTRUCTIVE


def test_approved_destructive_runs_through_analyze_adapter(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_approve)
    res = g.execute(Action.db("DELETE FROM users WHERE id = 1"))
    assert res.decision.decision == "REQUIRE_APPROVAL"
    # Analyze-only adapter never executes; returns exit 0 with executed=False.
    assert res.execution.exit_code == 0
    assert res.execution.executed is False
    assert "approved (analyze-only)" in res.execution.stdout


def test_audit_records_db_action(tmp_path: Path):
    g = Guard(audit_path=tmp_path / "audit.jsonl", approval_fn=auto_approve)
    g.execute(Action.db("SELECT 1"))
    import json
    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    rec = json.loads(line)
    assert rec["type"] == "db"
    assert rec["intent"] == "DB_READ"
    assert rec["rendered"] == "SELECT 1"
    assert rec["executed"] is False  # analyze-only


def test_apply_impact_picks_critical_for_delete_without_where():
    a = Action.db("DELETE FROM users")
    intent = intent_mod.classify(a)
    base = risk_mod.score(a, intent, intent_mod.feature_flags(a))
    from ai_firewall.engine import impact as impact_mod
    impact = impact_mod.estimate(a, intent)
    final = risk_mod.apply_impact(base, impact)
    assert final == RiskLevel.CRITICAL
