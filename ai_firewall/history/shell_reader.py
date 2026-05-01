"""Read recent shell-history entries to power permission-inheritance.

The idea: if the user just typed `npm test` in their own terminal, an AI
agent's request to run `npm test` immediately afterwards is auto-approved —
the AI is "inheriting" what the user already did manually.

Best-effort, cross-platform, and always defensive: if no history file is
available or parsing fails, we return an empty list. We never block on
history reading; the firewall keeps working with or without inheritance.

Sources we know about:
    bash:        ~/.bash_history (no timestamps unless HISTTIMEFORMAT set)
    zsh:         ~/.zsh_history  (lines look like ": <ts>:0;<cmd>" with `extended_history`)
    fish:        ~/.local/share/fish/fish_history (YAML-ish)
    PowerShell:  $env:APPDATA/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
                 (no timestamps; we use file-mtime as a coarse upper bound)
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_DEFAULT_LIMIT = 200
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB ceiling on each history file


@dataclass(frozen=True)
class RecentCommand:
    cmd: str
    ts: float          # 0.0 if the source has no per-entry timestamps
    source: str        # "bash" / "zsh" / "powershell" / "fish"


def read_recent(*, limit: int = _DEFAULT_LIMIT) -> list[RecentCommand]:
    """Return the most-recent N commands from any reachable shell history.

    Sorted newest first. Entries with no timestamp are interpolated using
    file mtime as an upper bound (so they don't all appear at t=0).
    """
    out: list[RecentCommand] = []

    for source, path, parser in _candidate_sources():
        if not path.exists():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_size > _MAX_FILE_SIZE:
            continue
        try:
            entries = list(parser(path))
        except Exception:
            continue  # never let history parsing crash the firewall
        # Fill in zero timestamps with mtime as a coarse newest-first floor
        if entries and any(e.ts == 0.0 for e in entries):
            mtime = stat.st_mtime
            entries = [
                RecentCommand(cmd=e.cmd, ts=e.ts or mtime, source=source)
                for e in entries
            ]
        out.extend(entries)

    out.sort(key=lambda e: e.ts, reverse=True)
    return out[:limit]


# ---------------------------------------------------------------------------
# Candidate sources + parsers
# ---------------------------------------------------------------------------

def _candidate_sources() -> Iterable[tuple[str, Path, callable]]:
    home = Path.home()
    yield ("bash", home / ".bash_history", _parse_bash)
    yield ("zsh", home / ".zsh_history", _parse_zsh)
    yield ("fish", home / ".local" / "share" / "fish" / "fish_history", _parse_fish)

    appdata = os.environ.get("APPDATA")
    if appdata:
        ps = Path(appdata) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
        yield ("powershell", ps, _parse_powershell)


# Shells that have no per-entry timestamps: we yield ts=0.0 and let the caller
# interpolate from file mtime. Newer entries are at the bottom of the file.

def _parse_bash(path: Path) -> Iterable[RecentCommand]:
    text = _read_text(path)
    if text is None:
        return
    # `HISTTIMEFORMAT` puts timestamp lines starting with `#` before each entry.
    # We don't try to parse those — too dialect-dependent. Just take command lines.
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        yield RecentCommand(cmd=s, ts=0.0, source="bash")


_ZSH_LINE = re.compile(r"^:\s*(\d+):\d+;(.+)$")


def _parse_zsh(path: Path) -> Iterable[RecentCommand]:
    text = _read_text(path)
    if text is None:
        return
    for line in text.splitlines():
        m = _ZSH_LINE.match(line.strip())
        if m:
            yield RecentCommand(cmd=m.group(2), ts=float(m.group(1)), source="zsh")
        elif line.strip():
            # Plain history (extended_history disabled)
            yield RecentCommand(cmd=line.strip(), ts=0.0, source="zsh")


def _parse_fish(path: Path) -> Iterable[RecentCommand]:
    """Fish history is YAML-ish: pairs of `- cmd: ...` and `  when: 1234`."""
    text = _read_text(path)
    if text is None:
        return
    cmd: str | None = None
    when: float = 0.0
    for line in text.splitlines():
        s = line.rstrip()
        if s.startswith("- cmd:"):
            if cmd is not None:
                yield RecentCommand(cmd=cmd, ts=when, source="fish")
            cmd = s.split(":", 1)[1].strip()
            when = 0.0
        elif s.lstrip().startswith("when:") and cmd is not None:
            try:
                when = float(s.split(":", 1)[1].strip())
            except ValueError:
                pass
    if cmd is not None:
        yield RecentCommand(cmd=cmd, ts=when, source="fish")


def _parse_powershell(path: Path) -> Iterable[RecentCommand]:
    text = _read_text(path)
    if text is None:
        return
    for line in text.splitlines():
        s = line.strip()
        if s:
            yield RecentCommand(cmd=s, ts=0.0, source="powershell")


def _read_text(path: Path) -> str | None:
    """Read a history file with permissive encoding handling. None on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
