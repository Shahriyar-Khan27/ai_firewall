"""Feature F — Docker sandbox replay adapter.

Most tests run without docker and just exercise the diff/snapshot helpers
plus the graceful-fallback path. The full round-trip test is skipped when
docker isn't available.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_firewall.adapters.sandbox import (
    DockerSandboxAdapter,
    FileChange,
    _diff_states,
    _docker_available,
    _hash_dir_state,
)
from ai_firewall.core.action import Action


def _docker_running() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


# --- _hash_dir_state + _diff_states ---


def test_hash_dir_state_captures_files(tmp_path: Path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("world")
    state = _hash_dir_state(tmp_path)
    assert "a.txt" in state
    assert "sub/b.txt" in state
    assert state["a.txt"][0] == 5  # size of "hello"
    assert len(state["a.txt"][1]) == 64  # sha256 hex


def test_diff_states_reports_added(tmp_path: Path):
    before = {}
    after = {"a.txt": (5, "hash_a")}
    changes = _diff_states(before, after)
    assert changes == [FileChange(path="a.txt", kind="added", size_after=5)]


def test_diff_states_reports_modified(tmp_path: Path):
    before = {"a.txt": (5, "hash_a")}
    after = {"a.txt": (7, "hash_b")}
    changes = _diff_states(before, after)
    assert len(changes) == 1
    assert changes[0].kind == "modified"
    assert changes[0].size_after == 7


def test_diff_states_reports_deleted(tmp_path: Path):
    before = {"a.txt": (5, "h")}
    after = {}
    changes = _diff_states(before, after)
    assert changes == [FileChange(path="a.txt", kind="deleted")]


# --- Adapter graceful-fallback when docker is missing ---


def test_returns_clean_error_when_docker_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    adapter = DockerSandboxAdapter()
    res = adapter.run(Action.shell("echo hi", cwd=str(tmp_path)))
    assert res.executed is False
    assert res.exit_code == 2
    assert "Docker unavailable" in res.stderr


def test_only_supports_shell_actions(tmp_path: Path):
    adapter = DockerSandboxAdapter()
    res = adapter.run(Action.file("write", str(tmp_path / "x"), content="hi"))
    assert res.exit_code == 2
    assert "shell" in res.stderr.lower()


def test_oversized_workdir_refused(tmp_path: Path, monkeypatch):
    # Fake docker as available so we get past the docker check.
    monkeypatch.setattr("ai_firewall.adapters.sandbox._docker_available", lambda cmd: (True, ""))
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB

    adapter = DockerSandboxAdapter(max_workdir_bytes=1024)  # 1 KB cap
    res = adapter.run(Action.shell("ls", cwd=str(tmp_path)))
    assert res.executed is False
    assert "too large" in res.stderr


def test_missing_cwd_returns_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("ai_firewall.adapters.sandbox._docker_available", lambda cmd: (True, ""))
    adapter = DockerSandboxAdapter()
    res = adapter.run(Action.shell("ls", cwd=str(tmp_path / "does_not_exist")))
    assert res.executed is False
    assert "does not exist" in res.stderr


# --- Real Docker round-trip (only runs if Docker is installed and reachable) ---


@pytest.mark.skipif(not _docker_running(), reason="Docker not available")
def test_full_dryrun_against_real_docker(tmp_path: Path):
    (tmp_path / "before.txt").write_text("before")

    adapter = DockerSandboxAdapter(image="alpine:latest", timeout_s=30.0)
    res = adapter.run(Action.shell("rm before.txt && echo deleted > after.txt", cwd=str(tmp_path)))

    assert res.executed is False  # dry-run never touches the real disk
    # Real disk untouched
    assert (tmp_path / "before.txt").exists()
    assert not (tmp_path / "after.txt").exists()
    # Sandbox saw the change
    assert "before.txt" in res.stdout
    assert "after.txt" in res.stdout
    assert "deleted" in res.stdout or "added" in res.stdout
