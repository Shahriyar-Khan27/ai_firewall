"""Shared pytest fixtures.

Auto-isolates persistent state so tests don't pollute ~/.ai-firewall/ on
the dev machine and don't bleed approvals/history between tests:
  - PatternMemory's SQLite DB         (v0.3.0)
  - Audit HMAC key file               (v0.3.0)
  - guard.toml user config            (v0.4.0 RBAC)
  - MCP server default audit log      (v0.4.0 governance + behavior)
"""
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_smart_flow_state(tmp_path: Path, monkeypatch):
    """Per-test: redirect every default state path into the test's tmp_path.

    Tests that explicitly pass their own paths/keys are unaffected.
    """
    # Pattern memory DB
    monkeypatch.setattr(
        "ai_firewall.approval.pattern_memory._DEFAULT_DB_PATH",
        tmp_path / "memory.db",
    )
    # Audit HMAC key
    monkeypatch.setattr(
        "ai_firewall.audit.logger._DEFAULT_KEY_PATH",
        tmp_path / "audit.key",
    )
    # User-level guard.toml (so RBAC tests don't see the dev's real config)
    monkeypatch.setattr(
        "ai_firewall.config.guard_toml._USER_PATH",
        tmp_path / "guard.toml.absent",
    )
    # MCP server's default audit log: divert to a per-test fresh file so
    # behavior anomalies don't fire on accumulated cross-test state.
    monkeypatch.setenv("AI_FIREWALL_AUDIT_PATH", str(tmp_path / "mcp-audit.jsonl"))
    # Make sure no env var leaks signing into tests that don't expect it
    monkeypatch.delenv("AI_FIREWALL_AUDIT_KEY", raising=False)
    yield
