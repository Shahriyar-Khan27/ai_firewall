"""Feature 7 — Cost & resource governance.

Three enforcements all run from `governance.check()` and read the audit log
through `RollingCounter`:

  1. rate_limit per intent
  2. loop_detection (same normalized command repeated)
  3. budget (api bytes per 24h)
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from ai_firewall.approval.cli_prompt import auto_approve
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine import governance as gov_mod
from ai_firewall.engine.governance import (
    GovernanceConfig,
    RollingCounter,
    check,
)


# ---------------------------------------------------------------------------
# GovernanceConfig.from_rules_dict
# ---------------------------------------------------------------------------


def test_config_defaults_when_no_governance_section():
    cfg = GovernanceConfig.from_rules_dict({})
    assert cfg.enabled is True
    assert cfg.rate_limits == {}
    assert cfg.loop_window_seconds == 10
    assert cfg.loop_max_repeats == 5
    assert cfg.api_bytes_per_day is None


def test_config_parses_rate_limits_with_unit_strings():
    rules = {
        "governance": {
            "rate_limit": {
                "file_delete": {"window": "60s", "max": 20},
                "shell_exec": {"window": "5m", "max": 200},
            },
            "loop_detection": {"same_command_within": "10s", "max": 5},
            "budget": {"api_bytes_per_day": 1_000_000},
        }
    }
    cfg = GovernanceConfig.from_rules_dict(rules)
    assert cfg.rate_limits["file_delete"]["window"] == 60
    assert cfg.rate_limits["file_delete"]["max"] == 20
    assert cfg.rate_limits["shell_exec"]["window"] == 300
    assert cfg.api_bytes_per_day == 1_000_000


def test_config_disabled_flag():
    cfg = GovernanceConfig.from_rules_dict({"governance": {"enabled": False}})
    assert cfg.enabled is False


# ---------------------------------------------------------------------------
# RollingCounter
# ---------------------------------------------------------------------------


def _write_records(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


def test_rolling_counter_returns_zero_when_no_log(tmp_path: Path):
    rc = RollingCounter(tmp_path / "missing.jsonl")
    assert rc.count_intent("FILE_DELETE", 60) == 0
    assert rc.count_command("rm foo", 10) == 0
    assert rc.sum_bytes_today("api") == 0


def test_rolling_counter_counts_intent_within_window(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - 5, "intent": "FILE_DELETE", "type": "file"},
        {"ts": now - 30, "intent": "FILE_DELETE", "type": "file"},
        {"ts": now - 120, "intent": "FILE_DELETE", "type": "file"},  # outside 60s
        {"ts": now - 1, "intent": "SHELL_EXEC", "type": "shell"},
    ])
    rc = RollingCounter(log)
    assert rc.count_intent("FILE_DELETE", 60) == 2
    assert rc.count_intent("SHELL_EXEC", 60) == 1


def test_rolling_counter_counts_command_repeats(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    cmd = "echo hi"
    _write_records(log, [
        {"ts": now - 1, "rendered": cmd},
        {"ts": now - 2, "rendered": cmd},
        {"ts": now - 3, "rendered": cmd},
        {"ts": now - 4, "rendered": "echo bye"},
        {"ts": now - 30, "rendered": cmd},  # outside 10s
    ])
    rc = RollingCounter(log)
    assert rc.count_command(cmd, 10) == 3
    assert rc.count_command("echo bye", 10) == 1
    assert rc.count_command("never seen", 10) == 0


def test_rolling_counter_sum_bytes_today(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - 100, "type": "api", "impact": {"bytes_affected": 500}},
        {"ts": now - 200, "type": "api", "impact": {"bytes_affected": 1500}},
        {"ts": now - 300, "type": "shell", "impact": {"bytes_affected": 99}},
        {"ts": now - 90000, "type": "api", "impact": {"bytes_affected": 9999}},  # > 24h
    ])
    rc = RollingCounter(log)
    assert rc.sum_bytes_today("api") == 2000
    assert rc.sum_bytes_today("shell") == 99


def test_rolling_counter_skips_init_header(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now, "event": "init", "intent": "FILE_DELETE"},  # header — should not count
        {"ts": now, "intent": "FILE_DELETE", "type": "file"},
    ])
    rc = RollingCounter(log)
    assert rc.count_intent("FILE_DELETE", 60) == 1


def test_rolling_counter_handles_corrupt_lines(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    with log.open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
        fh.write(json.dumps({"ts": now, "intent": "FILE_DELETE", "type": "file"}) + "\n")
        fh.write("\n")  # blank line
    rc = RollingCounter(log)
    assert rc.count_intent("FILE_DELETE", 60) == 1


def test_rolling_counter_caches_briefly(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now, "intent": "FILE_DELETE", "type": "file"},
    ])
    rc = RollingCounter(log)
    assert rc.count_intent("FILE_DELETE", 60) == 1
    # Append after the cache is warm — should NOT be visible until cache expires.
    _write_records(log, [{"ts": now, "intent": "FILE_DELETE", "type": "file"}])
    assert rc.count_intent("FILE_DELETE", 60) == 1
    # Force cache expiry — now the second record is visible.
    rc._cached_at = 0
    assert rc.count_intent("FILE_DELETE", 60) == 2


# ---------------------------------------------------------------------------
# governance.check()
# ---------------------------------------------------------------------------


def _action_shell(cmd: str) -> Action:
    return Action.shell(cmd)


def _action_file_delete(path: str) -> Action:
    return Action.file("delete", path)


def _action_api(method: str, url: str) -> Action:
    return Action.api(method=method, url=url)


def test_check_returns_none_when_disabled(tmp_path: Path):
    cfg = GovernanceConfig(enabled=False)
    rc = RollingCounter(tmp_path / "audit.jsonl")
    assert check(_action_shell("echo a"), counter=rc, config=cfg) is None


def test_check_loop_detection_blocks_repeat(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    cmd = "echo loop"
    _write_records(log, [{"ts": now - i, "rendered": cmd} for i in range(5)])
    cfg = GovernanceConfig(loop_window_seconds=10, loop_max_repeats=5)
    rc = RollingCounter(log)
    verdict = check(_action_shell(cmd), counter=rc, config=cfg)
    assert verdict is not None
    assert verdict.decision == "BLOCK"
    assert verdict.rule == "loop_detection"
    assert "5 times" in verdict.reason


def test_check_loop_detection_below_threshold_passes(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    cmd = "echo loop"
    _write_records(log, [{"ts": now - i, "rendered": cmd} for i in range(3)])
    cfg = GovernanceConfig(loop_window_seconds=10, loop_max_repeats=5)
    rc = RollingCounter(log)
    assert check(_action_shell(cmd), counter=rc, config=cfg) is None


def test_check_rate_limit_blocks_burst(tmp_path: Path):
    """20 file deletes in 60s → 21st check trips the limit."""
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - i, "intent": "FILE_DELETE", "type": "file",
         "rendered": f"delete f{i}"}
        for i in range(20)
    ])
    cfg = GovernanceConfig(
        rate_limits={"file_delete": {"window": 60, "max": 20}},
        loop_max_repeats=999,  # disable loop check for this test
    )
    rc = RollingCounter(log)
    verdict = check(
        _action_file_delete("/tmp/f-new.txt"), counter=rc, config=cfg,
    )
    assert verdict is not None
    assert verdict.rule == "rate_limit"
    assert "20 file_delete" in verdict.reason


def test_check_budget_blocks_when_exceeded(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - 100, "type": "api", "impact": {"bytes_affected": 600_000}},
        {"ts": now - 200, "type": "api", "impact": {"bytes_affected": 500_000}},
    ])
    cfg = GovernanceConfig(api_bytes_per_day=1_000_000, loop_max_repeats=999)
    rc = RollingCounter(log)
    verdict = check(
        _action_api("GET", "https://api.example.com/v1/x"),
        counter=rc, config=cfg,
    )
    assert verdict is not None
    assert verdict.rule == "budget"
    assert "1100000" in verdict.reason


def test_check_budget_allows_when_under_cap(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - 100, "type": "api", "impact": {"bytes_affected": 100}},
    ])
    cfg = GovernanceConfig(api_bytes_per_day=1_000_000, loop_max_repeats=999)
    rc = RollingCounter(log)
    assert check(
        _action_api("GET", "https://api.example.com/x"),
        counter=rc, config=cfg,
    ) is None


def test_check_budget_only_applies_to_api_actions(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - 1, "type": "api", "impact": {"bytes_affected": 9_999_999}},
    ])
    cfg = GovernanceConfig(api_bytes_per_day=1_000_000, loop_max_repeats=999)
    rc = RollingCounter(log)
    # Shell / file actions don't trip the API budget
    assert check(_action_shell("echo a"), counter=rc, config=cfg) is None


# ---------------------------------------------------------------------------
# Guard integration — end-to-end through evaluate()
# ---------------------------------------------------------------------------


def _guard(tmp_path: Path, **kw) -> Guard:
    return Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_approve,
        enable_memory=False,
        enable_inheritance=False,
        **kw,
    )


def test_guard_governance_can_be_disabled(tmp_path: Path):
    """With governance off, even a saturated rate-limit log should not block."""
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - i, "intent": "FILE_DELETE", "type": "file"}
        for i in range(50)
    ])
    g = _guard(tmp_path, enable_governance=False)
    target = tmp_path / "x.txt"
    target.write_text("data")
    res = g.execute(Action.file("delete", str(target)))
    assert res.decision.decision == "REQUIRE_APPROVAL"
    assert res.execution.exit_code == 0


def test_guard_governance_loop_detection_blocks(tmp_path: Path, monkeypatch):
    """Run the same `echo loop` command repeatedly; loop detection trips on the 6th."""
    g = _guard(tmp_path)
    cmd = "echo loop-detect-me"
    # 5 successful runs.
    for _ in range(5):
        # bypass the rolling-counter cache so each run re-reads the log
        g.governance_counter._cached_at = 0
        g.execute(Action.shell(cmd, cwd=str(tmp_path)))
    # 6th: governance should block before the adapter is invoked.
    g.governance_counter._cached_at = 0
    try:
        g.execute(Action.shell(cmd, cwd=str(tmp_path)))
    except Blocked as exc:
        assert exc.decision.decision == "BLOCK"
        assert "loop_detection" in exc.decision.reason
        return
    raise AssertionError("expected Blocked on 6th identical command")


def test_guard_governance_rate_limit_blocks_file_delete_burst(tmp_path: Path):
    """Pre-seed 20 FILE_DELETE records; the 21st must be blocked at the gate."""
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - (i * 0.1), "intent": "FILE_DELETE", "type": "file",
         "rendered": f"delete /tmp/seed{i}"}
        for i in range(20)
    ])
    g = _guard(tmp_path)
    target = tmp_path / "trigger.txt"
    target.write_text("data")
    try:
        g.execute(Action.file("delete", str(target)))
    except Blocked as exc:
        assert exc.decision.decision == "BLOCK"
        assert "rate_limit" in exc.decision.reason
        # The file must NOT have been deleted
        assert target.exists()
        return
    raise AssertionError("expected Blocked due to rate_limit")


def test_guard_normal_action_passes_governance(tmp_path: Path):
    """Sanity: a fresh project with no audit history runs cleanly."""
    g = _guard(tmp_path)
    res = g.execute(Action.shell("echo all-good", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"
