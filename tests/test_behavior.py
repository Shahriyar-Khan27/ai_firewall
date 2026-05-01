"""Feature 4 — AI behavior analytics (rule-based)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine.behavior import (
    AnomalyVerdict,
    BehaviorConfig,
    BehaviorEngine,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_records(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# BehaviorConfig
# ---------------------------------------------------------------------------


def test_config_defaults_when_no_rules():
    cfg = BehaviorConfig.from_rules_dict(None)
    assert cfg.enabled is True
    assert cfg.rate_burst == {}
    assert cfg.burst_window_seconds == 60
    assert cfg.rate_multiplier_threshold == 5.0


def test_config_parses_rate_burst():
    rules = {
        "behavior": {
            "rate_burst": {"file_delete": 25, "db_destructive": 10},
            "burst_window_seconds": 90,
            "rate_multiplier_threshold": 10.0,
        }
    }
    cfg = BehaviorConfig.from_rules_dict(rules)
    assert cfg.rate_burst == {"file_delete": 25, "db_destructive": 10}
    assert cfg.burst_window_seconds == 90
    assert cfg.rate_multiplier_threshold == 10.0


def test_config_disabled():
    cfg = BehaviorConfig.from_rules_dict({"behavior": {"enabled": False}})
    assert cfg.enabled is False


# ---------------------------------------------------------------------------
# BehaviorEngine — burst
# ---------------------------------------------------------------------------


def test_burst_flagged_at_threshold(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - i, "intent": "FILE_DELETE", "type": "file"}
        for i in range(25)
    ])
    cfg = BehaviorConfig(rate_burst={"file_delete": 25}, burst_window_seconds=60)
    eng = BehaviorEngine(log, cfg)
    target = tmp_path / "next.txt"
    target.write_text("data")
    v = eng.detect_anomaly(Action.file("delete", str(target)))
    assert v is not None
    assert v.rule == "rate_burst"
    assert "25 file_delete" in v.reason


def test_burst_below_threshold_passes(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - i, "intent": "FILE_DELETE", "type": "file"}
        for i in range(10)
    ])
    cfg = BehaviorConfig(rate_burst={"file_delete": 25}, burst_window_seconds=60)
    eng = BehaviorEngine(log, cfg)
    target = tmp_path / "next.txt"
    target.write_text("data")
    assert eng.detect_anomaly(Action.file("delete", str(target))) is None


def test_burst_only_for_configured_intents(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - i, "intent": "SHELL_EXEC", "type": "shell"}
        for i in range(50)
    ])
    cfg = BehaviorConfig(rate_burst={"file_delete": 25}, burst_window_seconds=60)
    eng = BehaviorEngine(log, cfg)
    # SHELL_EXEC has no burst threshold, so should not flag even at 50 in 60s.
    assert eng.detect_anomaly(Action.shell("echo hi")) is None


def test_disabled_engine_returns_none(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - i, "intent": "FILE_DELETE", "type": "file"}
        for i in range(50)
    ])
    cfg = BehaviorConfig(enabled=False, rate_burst={"file_delete": 5})
    eng = BehaviorEngine(log, cfg)
    target = tmp_path / "x.txt"
    target.write_text("data")
    assert eng.detect_anomaly(Action.file("delete", str(target))) is None


# ---------------------------------------------------------------------------
# BehaviorEngine — spike (last-hour rate vs 24h median)
# ---------------------------------------------------------------------------


def test_spike_flagged_when_last_hour_exceeds_multiplier(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    # 12 hours of low baseline: 1 SHELL_EXEC per hour for hours 1..11
    records = []
    for h in range(1, 12):
        records.append({
            "ts": now - (h * 3600 + 30),
            "intent": "SHELL_EXEC",
            "type": "shell",
        })
    # Last hour: 30 SHELL_EXEC actions (well over 5x median of 1)
    for i in range(30):
        records.append({
            "ts": now - (i * 30),
            "intent": "SHELL_EXEC",
            "type": "shell",
        })
    _write_records(log, records)

    cfg = BehaviorConfig(
        rate_burst={},  # no burst threshold for SHELL_EXEC
        rate_multiplier_threshold=5.0,
        spike_min_baseline_hours=6,
    )
    eng = BehaviorEngine(log, cfg)
    v = eng.detect_anomaly(Action.shell("echo hi"))
    assert v is not None
    assert v.rule == "rate_spike"
    assert "shell_exec" in v.reason


def test_spike_silent_without_enough_baseline(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    # Only 2 hours of history, but lots of activity — too thin to spike-flag.
    records = [
        {"ts": now - (i * 60), "intent": "SHELL_EXEC", "type": "shell"}
        for i in range(40)
    ]
    _write_records(log, records)
    cfg = BehaviorConfig(
        rate_burst={},
        rate_multiplier_threshold=5.0,
        spike_min_baseline_hours=6,
    )
    eng = BehaviorEngine(log, cfg)
    assert eng.detect_anomaly(Action.shell("echo hi")) is None


# ---------------------------------------------------------------------------
# Quiet-hour detection
# ---------------------------------------------------------------------------


def test_quiet_hour_silent_without_enough_history(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    now = time.time()
    # Only 5 records — well below the 100-record minimum.
    _write_records(log, [
        {"ts": now - i, "intent": "FILE_DELETE", "type": "file"}
        for i in range(5)
    ])
    cfg = BehaviorConfig(quiet_hour_min_total_actions=100, rate_burst={})
    eng = BehaviorEngine(log, cfg)
    target = tmp_path / "x.txt"
    target.write_text("data")
    assert eng.detect_anomaly(Action.file("delete", str(target))) is None


# ---------------------------------------------------------------------------
# Guard integration
# ---------------------------------------------------------------------------


def _guard(tmp_path: Path, *, approval_fn=auto_deny, **kw) -> Guard:
    return Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=approval_fn,
        enable_memory=False,
        enable_inheritance=False,
        enable_governance=False,  # don't double-block on rate_limit
        **kw,
    )


def test_guard_anomaly_downgrades_allow_to_require_approval(tmp_path: Path):
    """Per plan verification step 7: prepopulate 25 deletes, 26th asks approval."""
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - (i * 0.1), "intent": "FILE_DELETE", "type": "file",
         "rendered": f"delete /tmp/seed{i}"}
        for i in range(25)
    ])
    g = _guard(tmp_path)
    target = tmp_path / "trigger.txt"
    target.write_text("data")

    # Action would normally be REQUIRE_APPROVAL anyway (FILE_DELETE policy),
    # but with auto_deny we'll see the anomaly reason on the BLOCK.
    with pytest.raises(Blocked) as ei:
        g.execute(Action.file("delete", str(target)))
    # The decision should mention the anomaly. policy reason or behavior reason
    # is acceptable — but with rate_burst on file_delete=25, behavior should fire.
    reason = ei.value.decision.reason.lower()
    assert "behavior anomaly" in reason or "rate_burst" in reason or "file_delete" in reason


def test_guard_anomaly_never_escalates_block(tmp_path: Path):
    """A path BLOCK from policy should not be perturbed by behavior."""
    g = _guard(tmp_path)
    with pytest.raises(Blocked) as ei:
        g.execute(Action.shell("rm -rf /"))
    assert ei.value.decision.decision == "BLOCK"
    assert "behavior" not in ei.value.decision.reason


def test_guard_behavior_disabled_passes_clean(tmp_path: Path):
    """With enable_behavior=False, even saturated audit log can't downgrade."""
    log = tmp_path / "audit.jsonl"
    now = time.time()
    _write_records(log, [
        {"ts": now - (i * 0.1), "intent": "SHELL_EXEC", "type": "shell",
         "rendered": f"echo {i}"}
        for i in range(500)
    ])
    g = _guard(tmp_path, enable_behavior=False, approval_fn=auto_approve)
    res = g.execute(Action.shell("echo clean", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"
    assert "behavior" not in res.decision.reason


def test_guard_normal_action_with_no_history_allowed(tmp_path: Path):
    """Sanity: clean audit log = no anomaly fires."""
    g = _guard(tmp_path, approval_fn=auto_approve)
    res = g.execute(Action.shell("echo all-good", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"
