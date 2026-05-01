"""End-to-end tests for v0.3.0 smart-flow: memory + inheritance integration."""
import time
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.approval.pattern_memory import PatternMemory
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine.inheritance import InheritanceMatch


def _guard(tmp_path: Path, **kwargs) -> Guard:
    """Helper: Guard scoped to tmp_path, defaults memory + audit there too."""
    kwargs.setdefault("audit_path", tmp_path / "audit.jsonl")
    kwargs.setdefault("memory_db_path", tmp_path / "memory.db")
    return Guard(**kwargs)


# --- Memory integration ---


def test_memory_auto_approves_repeat(tmp_path: Path, monkeypatch):
    """A second `rm tmp.txt` after the user approved one should silently ALLOW."""
    # First run: user approves manually
    g = _guard(tmp_path, approval_fn=auto_approve)
    target = tmp_path / "tmp.txt"
    target.write_text("data")
    g.execute(Action.file("delete", str(target)))

    # Set up another file at a similar path
    target2 = tmp_path / "tmp.txt"  # same path, recreate
    target2.write_text("data")

    # Second run with auto_deny — should still ALLOW silently because memory matched
    g2 = _guard(tmp_path, approval_fn=auto_deny)
    decision = g2.evaluate(Action.file("delete", str(target2)))
    assert decision.decision == "ALLOW"
    assert "memory match" in decision.reason


def test_memory_does_not_auto_approve_higher_risk(tmp_path: Path, monkeypatch):
    """Approving at MEDIUM doesn't auto-approve a CRITICAL re-occurrence."""
    # Pre-populate memory with a low-risk approval
    mem = PatternMemory(tmp_path / "memory.db")
    from ai_firewall.engine.decision import Decision
    from ai_firewall.engine.impact import Impact
    fake_low = Decision(
        decision="REQUIRE_APPROVAL",
        reason="seed",
        intent=IntentType.SHELL_EXEC,
        risk=RiskLevel.LOW,
        impact=Impact(notes=""),
    )
    seed_action = Action.shell("custom-cmd safe arg")
    mem.record(seed_action, fake_low)
    mem.close()

    # New evaluation: same command, but Guard would normally score it MEDIUM (or higher).
    # Memory match is gated by historical_risk >= current_risk, so MEDIUM > LOW → no match.
    g = _guard(tmp_path, approval_fn=auto_deny)
    decision = g.evaluate(Action.shell("custom-cmd safe arg"))
    # Either it's ALLOW because policy said so, or REQUIRE_APPROVAL because it was risky enough.
    # The key invariant: it must NOT cite memory_match in the reason.
    assert "memory match" not in decision.reason


def test_memory_disabled_via_constructor(tmp_path: Path):
    g = _guard(tmp_path, approval_fn=auto_approve, enable_memory=False)
    target = tmp_path / "x.txt"
    target.write_text("data")
    g.execute(Action.file("delete", str(target)))

    # Even after the explicit approval, no memory was recorded
    assert g.memory is None


def test_memory_records_after_approval_only(tmp_path: Path):
    """We don't add to memory when the user rejects."""
    target = tmp_path / "tmp.txt"
    target.write_text("data")

    g = _guard(tmp_path, approval_fn=auto_deny)
    with pytest.raises(Blocked):
        g.execute(Action.file("delete", str(target)))

    # Re-evaluating now should still REQUIRE_APPROVAL (memory empty)
    decision = g.evaluate(Action.file("delete", str(target)))
    assert decision.decision == "REQUIRE_APPROVAL"
    assert "memory match" not in decision.reason


# --- Inheritance integration ---


def test_inheritance_auto_approves_when_user_just_ran_it(tmp_path: Path, monkeypatch):
    """Mock recent shell history so the AI's identical command is auto-approved."""
    fake_match = InheritanceMatch(
        cmd="rm /tmp/scratch",
        age_seconds=12.0,
        similarity=1.0,
        source="zsh",
    )
    monkeypatch.setattr(
        "ai_firewall.core.guard.check_inheritance",
        lambda action, decision, **kwargs: fake_match,
    )

    g = _guard(tmp_path, approval_fn=auto_deny)
    target = tmp_path / "scratch"
    target.write_text("x")
    decision = g.evaluate(Action.file("delete", str(target)))
    # Inheritance only kicks in for shell actions; file action gets normal flow.
    # So this file action should NOT be inheritance-allowed.
    assert "inheritance" not in decision.reason

    # But a shell action of an equivalent command should be:
    decision2 = g.evaluate(Action.shell("rm /tmp/scratch"))
    assert decision2.decision == "ALLOW"
    assert "inheritance" in decision2.reason


def test_inheritance_disabled(tmp_path: Path, monkeypatch):
    fake_match = InheritanceMatch(cmd="rm /tmp/x", age_seconds=5.0, similarity=1.0, source="zsh")
    monkeypatch.setattr(
        "ai_firewall.core.guard.check_inheritance",
        lambda action, decision, **kwargs: fake_match,
    )

    g = _guard(tmp_path, approval_fn=auto_deny, enable_inheritance=False)
    decision = g.evaluate(Action.shell("rm /tmp/x"))
    assert "inheritance" not in decision.reason


def test_inheritance_only_applies_to_shell(tmp_path: Path, monkeypatch):
    """File / SQL / API actions don't get inheritance even if check_inheritance returns a match."""
    fake_match = InheritanceMatch(cmd="anything", age_seconds=1.0, similarity=1.0, source="zsh")
    monkeypatch.setattr(
        "ai_firewall.core.guard.check_inheritance",
        lambda action, decision, **kwargs: fake_match,
    )

    g = _guard(tmp_path, approval_fn=auto_deny)
    target = tmp_path / "f.txt"
    target.write_text("x")
    decision = g.evaluate(Action.file("delete", str(target)))
    assert "inheritance" not in decision.reason


# --- BLOCK never gets downgraded ---


def test_block_decisions_never_downgraded(tmp_path: Path):
    """Even if memory has a record matching `rm -rf /`, BLOCK still wins."""
    # Pre-seed memory at high risk
    mem = PatternMemory(tmp_path / "memory.db")
    from ai_firewall.engine.decision import Decision
    from ai_firewall.engine.impact import Impact
    seed = Decision(
        decision="REQUIRE_APPROVAL",
        reason="seed",
        intent=IntentType.FILE_DELETE,
        risk=RiskLevel.CRITICAL,
        impact=Impact(notes=""),
    )
    mem.record(Action.shell("rm -rf /"), seed)
    mem.close()

    g = _guard(tmp_path, approval_fn=auto_approve)
    decision = g.evaluate(Action.shell("rm -rf /"))
    assert decision.decision == "BLOCK"


# --- Audit log captures the silent approval ---


def test_silent_approval_is_audited(tmp_path: Path):
    """When memory or inheritance auto-approves, the audit row reflects ALLOW + the reason."""
    g = _guard(tmp_path, approval_fn=auto_approve)
    target = tmp_path / "x.txt"
    target.write_text("data")
    g.execute(Action.file("delete", str(target)))  # records into memory
    target.write_text("data")  # recreate for the next run

    g2 = _guard(tmp_path, approval_fn=auto_deny)
    g2.execute(Action.file("delete", str(target)))

    import json
    audit_lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    last = json.loads(audit_lines[-1])
    assert last["decision"] == "ALLOW"
    assert "memory match" in last["reason"]
