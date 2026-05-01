"""Feature D — permission inheritance from shell history."""
import os
import time
from pathlib import Path

import pytest

from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine.decision import Decision
from ai_firewall.engine.impact import Impact
from ai_firewall.engine.inheritance import InheritanceMatch, check_inheritance, _jaccard
from ai_firewall.history.shell_reader import RecentCommand, read_recent


def _decision() -> Decision:
    return Decision(
        decision="REQUIRE_APPROVAL",
        reason="test",
        intent=IntentType.SHELL_EXEC,
        risk=RiskLevel.MEDIUM,
        impact=Impact(notes=""),
    )


# --- Inheritance match logic ---


def test_no_history_no_match():
    action = Action.shell("npm test")
    assert check_inheritance(action, _decision(), history=[]) is None


def test_exact_match_within_window():
    action = Action.shell("npm test")
    now = time.time()
    history = [RecentCommand(cmd="npm test", ts=now - 30, source="zsh")]
    match = check_inheritance(action, _decision(), history=history, now=now)
    assert match is not None
    assert match.similarity == 1.0
    assert 25 <= match.age_seconds <= 35


def test_match_outside_window_rejected():
    action = Action.shell("npm test")
    now = time.time()
    history = [RecentCommand(cmd="npm test", ts=now - 600, source="zsh")]  # 10 min ago
    match = check_inheritance(action, _decision(), history=history, now=now, window_seconds=300)
    assert match is None


def test_fuzzy_match_above_threshold():
    """`git push origin develop` should fuzzy-match `git push origin main`."""
    action = Action.shell("git push origin develop")
    now = time.time()
    history = [RecentCommand(cmd="git push origin main", ts=now - 60, source="zsh")]
    match = check_inheritance(action, _decision(), history=history, now=now, threshold=0.5)
    assert match is not None
    assert 0.5 <= match.similarity < 1.0


def test_match_below_threshold_rejected():
    action = Action.shell("rm -rf /tmp/scratch")
    now = time.time()
    history = [RecentCommand(cmd="ls -la", ts=now - 10, source="zsh")]
    match = check_inheritance(action, _decision(), history=history, now=now)
    assert match is None


def test_only_shell_actions_inherit():
    """File / SQL / API actions don't get inheritance — no shell-history analogue."""
    file_action = Action.file("delete", "/tmp/x")
    assert check_inheritance(file_action, _decision(), history=[], now=time.time()) is None


def test_picks_best_similarity_when_multiple_match():
    action = Action.shell("git status -s")
    now = time.time()
    history = [
        RecentCommand(cmd="git status", ts=now - 60, source="zsh"),
        RecentCommand(cmd="git status -s", ts=now - 120, source="zsh"),
    ]
    match = check_inheritance(action, _decision(), history=history, now=now, threshold=0.5)
    assert match is not None
    assert match.similarity == 1.0  # the exact match wins


def test_jaccard_helper():
    assert _jaccard(["a", "b"], ["a", "b"]) == 1.0
    assert _jaccard(["a"], ["b"]) == 0.0
    assert _jaccard(["a", "b", "c"], ["a", "b"]) == pytest.approx(2 / 3)


# --- shell_reader file parsing ---


def test_read_recent_handles_missing_files(monkeypatch, tmp_path: Path):
    """When the user has no history files, return an empty list — not raise."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    assert read_recent() == []


def test_read_recent_parses_zsh(monkeypatch, tmp_path: Path):
    """zsh extended_history format: `: <ts>:0;<cmd>`."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    (tmp_path / ".zsh_history").write_text(
        ": 1700000001:0;ls -la\n: 1700000010:0;npm test\n",
        encoding="utf-8",
    )
    entries = read_recent()
    assert len(entries) == 2
    # Newest first
    assert entries[0].cmd == "npm test"
    assert entries[0].ts == 1700000010.0
    assert entries[0].source == "zsh"


def test_read_recent_parses_bash_with_mtime_fill(monkeypatch, tmp_path: Path):
    """bash history without HISTTIMEFORMAT — every line gets ts = mtime."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    bash_path = tmp_path / ".bash_history"
    bash_path.write_text("ls\nnpm test\n", encoding="utf-8")
    entries = read_recent()
    assert len(entries) == 2
    assert all(e.source == "bash" for e in entries)
    assert all(e.ts > 0 for e in entries)


def test_read_recent_handles_powershell(monkeypatch, tmp_path: Path):
    """PowerShell history file path comes from %APPDATA%."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    appdata = tmp_path / "appdata"
    ps_dir = appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    ps_dir.mkdir(parents=True)
    (ps_dir / "ConsoleHost_history.txt").write_text("Get-Process\nls\n", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(appdata))

    entries = read_recent()
    cmds = [e.cmd for e in entries]
    assert "Get-Process" in cmds
    assert "ls" in cmds
    assert all(e.source == "powershell" for e in entries)


def test_oversized_history_file_skipped(monkeypatch, tmp_path: Path):
    """Don't try to read a 100 MB history file — return empty for that source."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    big = tmp_path / ".bash_history"
    big.write_bytes(b"a\n" * (3 * 1024 * 1024))  # ~6 MB > limit
    entries = read_recent()
    assert entries == []
