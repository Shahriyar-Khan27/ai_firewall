import os
import subprocess
from pathlib import Path

import pytest

from ai_firewall.engine import git_check


def _have_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=2, check=False)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(not _have_git(), reason="git CLI not available")


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=path, check=True)


def test_returns_empty_when_no_enclosing_repo(tmp_path: Path, monkeypatch):
    # Force "outside repo" regardless of where tmp_path actually lives.
    monkeypatch.setattr(git_check, "_repo_root", lambda cwd: None)
    res = git_check.inspect([tmp_path / "a.txt"], tmp_path)
    assert res == {}


def test_returns_empty_when_git_unavailable(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(git_check, "_git_available", lambda: False)
    res = git_check.inspect([tmp_path / "a.txt"], tmp_path)
    assert res == {}


def test_uncommitted_changes_detected(tmp_path: Path):
    _init_repo(tmp_path)
    f = tmp_path / "tracked.txt"
    f.write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    f.write_text("v2 — modified\n", encoding="utf-8")

    res = git_check.inspect([f], tmp_path)
    assert res.get("in_repo") is True
    assert "tracked.txt" in (res.get("uncommitted_changes") or [])


def test_untracked_file_detected(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / "seed").write_text("x", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)

    new_file = tmp_path / "new.txt"
    new_file.write_text("hi\n", encoding="utf-8")
    res = git_check.inspect([new_file], tmp_path)
    assert "new.txt" in (res.get("untracked") or [])


def test_gitignored_file_detected(tmp_path: Path):
    _init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text("secrets/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    secret_file = secret_dir / "api.key"
    secret_file.write_text("abc", encoding="utf-8")

    res = git_check.inspect([secret_file], tmp_path)
    ignored = res.get("gitignored") or []
    assert any("secrets" in p for p in ignored)
