from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable


def inspect(paths: Iterable[Path], cwd: Path) -> dict:
    """Return git-aware findings for a set of paths.

    Best-effort: returns {} when git is missing, when cwd isn't inside a repo,
    or when subprocess calls fail. Does not raise.
    """
    paths = [p for p in paths if p is not None]
    if not paths or not _git_available():
        return {}
    repo_root = _repo_root(cwd)
    if repo_root is None:
        return {}

    rel_paths = []
    for p in paths:
        try:
            rel_paths.append(p.resolve().relative_to(repo_root).as_posix())
        except (ValueError, OSError):
            continue
    if not rel_paths:
        return {"in_repo": False}

    findings: dict = {"in_repo": True, "repo_root": str(repo_root)}

    ignored = _check_ignore(repo_root, rel_paths)
    if ignored:
        findings["gitignored"] = ignored

    untracked, modified = _status_buckets(repo_root, rel_paths)
    if untracked:
        findings["untracked"] = untracked
    if modified:
        findings["uncommitted_changes"] = modified

    return findings


def _git_available() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, timeout=2, check=False)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _repo_root(cwd: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    if not out:
        return None
    return Path(out)


def _check_ignore(repo_root: Path, rel_paths: list[str]) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", "--", *rel_paths],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode not in (0, 1):
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def _status_buckets(repo_root: Path, rel_paths: list[str]) -> tuple[list[str], list[str]]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain", "--", *rel_paths],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return [], []
    if proc.returncode != 0:
        return [], []
    untracked: list[str] = []
    modified: list[str] = []
    for line in proc.stdout.splitlines():
        if len(line) < 3:
            continue
        code = line[:2]
        path = line[3:].strip().strip('"')
        if code == "??":
            untracked.append(path)
        elif code.strip():
            modified.append(path)
    return untracked, modified
