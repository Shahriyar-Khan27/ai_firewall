"""Docker-backed sandbox replay adapter.

Runs a shell command inside a disposable container against a snapshot of the
user's working directory, then surfaces the diff (which files appeared / were
modified / were deleted) so the user can see exactly what the command would
do before they let it touch their real disk.

Cross-platform via the standard `docker` CLI. If `docker` isn't on PATH or
the daemon isn't running, returns an ExecutionResult with exit_code=2 and a
clear error message rather than failing-open silently.

Image: `alpine:latest` by default (small, busybox userland is enough for the
common shell verbs we need to dry-run).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


@dataclass(frozen=True)
class FileChange:
    path: str           # path relative to the sandboxed workdir
    kind: str           # "added" / "modified" / "deleted"
    size_after: int = 0  # 0 for deletes


@dataclass(frozen=True)
class DryRunReport:
    exit_code: int
    stdout: str
    stderr: str
    changes: tuple[FileChange, ...]
    elapsed_s: float

    def summary(self) -> str:
        n_add = sum(1 for c in self.changes if c.kind == "added")
        n_mod = sum(1 for c in self.changes if c.kind == "modified")
        n_del = sum(1 for c in self.changes if c.kind == "deleted")
        return f"{n_add} added, {n_mod} modified, {n_del} deleted (exit {self.exit_code})"


class DockerSandboxAdapter(ExecutionAdapter):
    """ExecutionAdapter that runs the action in a throwaway Docker container.

    Returns an ExecutionResult with `executed=False` (we never touched the
    real disk) and `note` containing a serialized DryRunReport in JSON.
    """

    def __init__(
        self,
        image: str = "alpine:latest",
        *,
        timeout_s: float = 60.0,
        max_workdir_bytes: int = 50 * 1024 * 1024,
        docker_cmd: str = "docker",
    ):
        self.image = image
        self.timeout_s = timeout_s
        self.max_workdir_bytes = max_workdir_bytes
        self.docker_cmd = docker_cmd

    def run(self, action: Action) -> ExecutionResult:
        if action.type != "shell":
            return ExecutionResult(
                exit_code=2,
                stderr=f"sandbox adapter only supports shell actions (got {action.type!r})",
                executed=False,
            )

        # Verify Docker is reachable before copying any files.
        ok, why = _docker_available(self.docker_cmd)
        if not ok:
            return ExecutionResult(
                exit_code=2,
                stderr=f"Docker unavailable: {why}",
                executed=False,
                note="sandbox skipped",
            )

        cmd = (action.payload.get("cmd") or "").strip()
        if not cmd:
            return ExecutionResult(exit_code=2, stderr="empty command", executed=False)

        cwd_raw = (action.context or {}).get("cwd") or os.getcwd()
        cwd = Path(cwd_raw)
        if not cwd.exists():
            return ExecutionResult(
                exit_code=2,
                stderr=f"cwd does not exist: {cwd}",
                executed=False,
            )

        # Refuse if the working dir is huge — copying to a tmpdir would be slow
        # and the sandbox isn't meant for whole-disk replays.
        try:
            total = _dir_size(cwd, ceiling=self.max_workdir_bytes + 1)
        except OSError as e:
            return ExecutionResult(exit_code=2, stderr=f"could not stat cwd: {e}", executed=False)
        if total > self.max_workdir_bytes:
            return ExecutionResult(
                exit_code=2,
                stderr=(
                    f"workdir is too large for sandbox replay "
                    f"({total / 1024 / 1024:.0f} MB > {self.max_workdir_bytes / 1024 / 1024:.0f} MB cap)"
                ),
                executed=False,
            )

        report = _run_in_container(
            cmd=cmd,
            workdir=cwd,
            image=self.image,
            timeout_s=self.timeout_s,
            docker_cmd=self.docker_cmd,
        )
        report_json = json.dumps({
            "image": self.image,
            "exit_code": report.exit_code,
            "elapsed_s": report.elapsed_s,
            "summary": report.summary(),
            "changes": [
                {"path": c.path, "kind": c.kind, "size_after": c.size_after}
                for c in report.changes[:200]
            ],
        }, indent=2)
        return ExecutionResult(
            exit_code=report.exit_code,
            stdout=report.stdout + "\n--- sandbox dry-run report ---\n" + report_json,
            stderr=report.stderr,
            executed=False,
            note=f"dry-run: {report.summary()}",
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _docker_available(docker_cmd: str) -> tuple[bool, str]:
    if not shutil.which(docker_cmd):
        return False, f"`{docker_cmd}` not found on PATH"
    try:
        proc = subprocess.run(
            [docker_cmd, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "docker info failed").strip().splitlines()[0]
    return True, ""


def _dir_size(p: Path, *, ceiling: int) -> int:
    total = 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
            if total >= ceiling:
                return total
    return total


def _hash_dir_state(p: Path) -> dict[str, tuple[int, str]]:
    """Snapshot every file's (size, sha256) keyed by relpath."""
    state: dict[str, tuple[int, str]] = {}
    for root, _dirs, files in os.walk(p):
        for f in files:
            full = Path(root) / f
            try:
                rel = str(full.relative_to(p)).replace("\\", "/")
                size = full.stat().st_size
                h = hashlib.sha256()
                with full.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(64 * 1024), b""):
                        h.update(chunk)
                state[rel] = (size, h.hexdigest())
            except OSError:
                continue
    return state


def _diff_states(before: dict, after: dict) -> list[FileChange]:
    out: list[FileChange] = []
    before_keys = set(before)
    after_keys = set(after)
    for k in sorted(after_keys - before_keys):
        out.append(FileChange(path=k, kind="added", size_after=after[k][0]))
    for k in sorted(before_keys - after_keys):
        out.append(FileChange(path=k, kind="deleted"))
    for k in sorted(before_keys & after_keys):
        if before[k][1] != after[k][1]:
            out.append(FileChange(path=k, kind="modified", size_after=after[k][0]))
    return out


def _run_in_container(
    cmd: str,
    workdir: Path,
    image: str,
    timeout_s: float,
    docker_cmd: str,
) -> DryRunReport:
    """Copy workdir into a tmpdir, mount it into a container, run cmd, diff."""
    import time

    started = time.time()

    with tempfile.TemporaryDirectory(prefix="firewall-sandbox-") as tmp:
        scratch = Path(tmp) / "workdir"
        # copytree with dirs_exist_ok=False (default) — scratch shouldn't exist yet
        shutil.copytree(workdir, scratch, dirs_exist_ok=True, symlinks=True, ignore_dangling_symlinks=True)

        before = _hash_dir_state(scratch)

        # Run the command inside the container
        container_args = [
            docker_cmd, "run", "--rm",
            "-v", f"{scratch}:/work",
            "-w", "/work",
            "--network", "none",
            image,
            "sh", "-lc", cmd,
        ]
        try:
            proc = subprocess.run(
                container_args,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            stdout = (e.stdout or b"").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = f"sandbox run timed out after {timeout_s}s"
            exit_code = 124
        except (OSError, subprocess.SubprocessError) as e:
            stdout = ""
            stderr = f"sandbox run failed: {e}"
            exit_code = 2

        after = _hash_dir_state(scratch)
        changes = _diff_states(before, after)
        elapsed = time.time() - started

        return DryRunReport(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            changes=tuple(changes),
            elapsed_s=elapsed,
        )
