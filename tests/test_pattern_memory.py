"""Feature C — approved-pattern memory."""
import time
from pathlib import Path

import pytest

from ai_firewall.approval.pattern_memory import PatternMemory, _jaccard, _tokens
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine.decision import Decision
from ai_firewall.engine.impact import Impact


def _decision(intent: IntentType = IntentType.SHELL_EXEC, *, risk: RiskLevel = RiskLevel.MEDIUM) -> Decision:
    return Decision(
        decision="REQUIRE_APPROVAL",
        reason="test",
        intent=intent,
        risk=risk,
        impact=Impact(notes=""),
    )


def _shell(cmd: str, cwd: str | None = None) -> Action:
    if cwd is None:
        return Action.shell(cmd)
    a = Action.shell(cmd)
    return Action(type="shell", payload=a.payload, context={"cwd": cwd}, id=a.id)


# --- Token / Jaccard primitives ---


def test_tokens_lowercases_and_strips():
    assert _tokens("npm  run BUILD") == ["npm", "run", "build"]


def test_jaccard_full_overlap():
    assert _jaccard(["a", "b"], ["a", "b"]) == 1.0


def test_jaccard_no_overlap():
    assert _jaccard(["a"], ["b"]) == 0.0


def test_jaccard_partial():
    assert _jaccard(["a", "b", "c"], ["a", "b", "d"]) == pytest.approx(2 / 4)


# --- Recording + lookup ---


def test_record_and_lookup_exact_match(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    action = _shell("npm run build", cwd=str(tmp_path))
    decision = _decision()

    assert mem.lookup(action, decision) is None
    mem.record(action, decision)

    match = mem.lookup(action, decision)
    assert match is not None
    assert match.similarity == 1.0
    assert match.historical_risk == RiskLevel.MEDIUM
    assert match.seen_count == 1


def test_lookup_finds_whitespace_variant(tmp_path: Path):
    """`npm  run   build` should match a previously-approved `npm run build`."""
    mem = PatternMemory(tmp_path / "memory.db")
    mem.record(_shell("npm run build", cwd=str(tmp_path)), _decision())
    match = mem.lookup(_shell("npm  run   build", cwd=str(tmp_path)), _decision())
    assert match is not None
    assert match.similarity == 1.0  # tokens are identical after normalization


def test_lookup_finds_jaccard_partial_match(tmp_path: Path):
    """A 4-of-5 token match crosses the default 0.8 threshold."""
    mem = PatternMemory(tmp_path / "memory.db", threshold=0.6)
    mem.record(_shell("git push origin main", cwd=str(tmp_path)), _decision())
    # 3 of 4 tokens overlap → Jaccard = 3/5 = 0.6
    match = mem.lookup(_shell("git push origin develop", cwd=str(tmp_path)), _decision())
    assert match is not None


def test_lookup_below_threshold_returns_none(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")  # default threshold 0.8
    mem.record(_shell("npm run build", cwd=str(tmp_path)), _decision())
    # Different command entirely
    assert mem.lookup(_shell("git push", cwd=str(tmp_path)), _decision()) is None


def test_lookup_intent_must_match(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    mem.record(_shell("rm tmp.txt", cwd=str(tmp_path)), _decision(intent=IntentType.FILE_DELETE))
    # Same exact tokens but a different intent → no match
    fake_write = _decision(intent=IntentType.FILE_WRITE)
    assert mem.lookup(_shell("rm tmp.txt", cwd=str(tmp_path)), fake_write) is None


def test_lookup_project_must_match(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    mem.record(_shell("npm run build", cwd=str(tmp_path / "proj_a")), _decision())
    # Same command, different project root
    assert mem.lookup(_shell("npm run build", cwd=str(tmp_path / "proj_b")), _decision()) is None


def test_lookup_does_not_escalate_trust(tmp_path: Path):
    """Approving at MEDIUM does not auto-approve a CRITICAL re-occurrence."""
    mem = PatternMemory(tmp_path / "memory.db")
    mem.record(_shell("rm something", cwd=str(tmp_path)), _decision(risk=RiskLevel.MEDIUM))
    # Same command but the firewall now scores it CRITICAL — must NOT auto-approve.
    assert mem.lookup(_shell("rm something", cwd=str(tmp_path)), _decision(risk=RiskLevel.CRITICAL)) is None


def test_lookup_allows_lower_risk(tmp_path: Path):
    """Approving at HIGH covers a future MEDIUM occurrence."""
    mem = PatternMemory(tmp_path / "memory.db")
    mem.record(_shell("rm something", cwd=str(tmp_path)), _decision(risk=RiskLevel.HIGH))
    match = mem.lookup(_shell("rm something", cwd=str(tmp_path)), _decision(risk=RiskLevel.MEDIUM))
    assert match is not None


def test_record_increments_count(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    action = _shell("npm test", cwd=str(tmp_path))
    decision = _decision()
    mem.record(action, decision)
    mem.record(action, decision)
    mem.record(action, decision)

    match = mem.lookup(action, decision)
    assert match is not None
    assert match.seen_count == 3


def test_clear_project_removes_only_that_project(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    mem.record(_shell("npm run build", cwd=str(tmp_path / "a")), _decision())
    mem.record(_shell("npm run build", cwd=str(tmp_path / "b")), _decision())

    deleted = mem.clear_project(str(tmp_path / "a"))
    assert deleted == 1
    assert mem.lookup(_shell("npm run build", cwd=str(tmp_path / "a")), _decision()) is None
    assert mem.lookup(_shell("npm run build", cwd=str(tmp_path / "b")), _decision()) is not None


def test_db_action_persists_normalized_sql(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    a = Action.db("SELECT * FROM users", connection=str(tmp_path / "x.db"))
    mem.record(a, _decision(intent=IntentType.DB_READ, risk=RiskLevel.LOW))
    match = mem.lookup(a, _decision(intent=IntentType.DB_READ, risk=RiskLevel.LOW))
    assert match is not None


def test_api_action_persists(tmp_path: Path):
    mem = PatternMemory(tmp_path / "memory.db")
    a = Action.api("GET", "https://example.com/health")
    mem.record(a, _decision(intent=IntentType.API_READ, risk=RiskLevel.LOW))
    match = mem.lookup(a, _decision(intent=IntentType.API_READ, risk=RiskLevel.LOW))
    assert match is not None


def test_safe_to_open_twice_concurrently(tmp_path: Path):
    """Two PatternMemory instances pointing at the same DB should coexist."""
    db = tmp_path / "memory.db"
    a = PatternMemory(db)
    b = PatternMemory(db)
    a.record(_shell("npm test", cwd=str(tmp_path)), _decision())
    match = b.lookup(_shell("npm test", cwd=str(tmp_path)), _decision())
    assert match is not None
    a.close()
    b.close()
