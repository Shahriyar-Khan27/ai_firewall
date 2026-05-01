"""Shared pytest fixtures.

Auto-isolates the v0.3.0 smart-flow state files so tests don't pollute
~/.ai-firewall/ on the dev machine and don't bleed approvals between tests:
  - PatternMemory's SQLite DB
  - Audit HMAC key file
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
    # Make sure no env var leaks signing into tests that don't expect it
    monkeypatch.delenv("AI_FIREWALL_AUDIT_KEY", raising=False)
    yield
