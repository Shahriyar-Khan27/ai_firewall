from __future__ import annotations

import os
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ai_firewall.core.action import Action, IntentType
from ai_firewall.engine import code_analysis, diff as diff_mod, git_check, sql_analysis

_POSIX_SHLEX = os.name != "nt"


@dataclass(frozen=True)
class Impact:
    files_affected: int = 0
    bytes_affected: int = 0
    paths: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""
    diff: str = ""
    lines_added: int = 0
    lines_removed: int = 0
    code_findings: tuple[str, ...] = field(default_factory=tuple)
    git: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["paths"] = list(self.paths)
        d["code_findings"] = list(self.code_findings)
        return d

    def summary(self) -> str:
        if self.files_affected == 0 and not self.notes and not self.code_findings and not self.git:
            return "no measurable impact"
        parts = []
        if self.files_affected:
            parts.append(f"{self.files_affected} file(s)")
        if self.bytes_affected:
            parts.append(_human_bytes(self.bytes_affected))
        if self.lines_added or self.lines_removed:
            parts.append(f"+{self.lines_added}/-{self.lines_removed} lines")
        if self.notes:
            parts.append(self.notes)
        return ", ".join(parts) if parts else "no measurable impact"


def estimate(action: Action, intent: IntentType, *, base_cwd: Path | None = None) -> Impact:
    """Best-effort dry-run. Never executes the action."""
    cwd = base_cwd or Path(action.context.get("cwd") or Path.cwd())

    if intent is IntentType.FILE_DELETE:
        targets = _delete_targets(action, cwd)
        base = _walk_impact(targets)
        git = git_check.inspect(targets, cwd) if targets else {}
        if git:
            return _replace(base, git=git)
        return base

    if intent in (IntentType.FILE_WRITE, IntentType.CODE_MODIFY):
        return _write_impact(action, cwd)

    if intent is IntentType.FILE_READ:
        path = _resolve(action.payload.get("path"), cwd)
        if path and path.exists() and path.is_file():
            return Impact(files_affected=1, bytes_affected=path.stat().st_size, paths=(str(path),))
        return Impact(notes="reads a file")

    if intent in (IntentType.DB_READ, IntentType.DB_WRITE, IntentType.DB_DESTRUCTIVE):
        return _db_impact(action)

    return Impact(notes="impact not modelled for this intent")


def _db_impact(action: Action) -> Impact:
    sql = action.payload.get("sql") or ""
    dialect = action.payload.get("dialect", "generic")
    a = sql_analysis.analyze(sql, dialect=dialect)
    notes = (
        f"{', '.join(a.statements)} on {', '.join(a.tables) or 'no tables resolved'}"
        if a.parse_ok
        else "SQL did not parse"
    )
    # We reuse code_findings as the generic "structured findings" channel,
    # so the existing risk/prompt/audit plumbing surfaces SQL findings too.
    return Impact(
        files_affected=0,
        bytes_affected=0,
        paths=tuple(a.tables[:8]),
        notes=notes,
        code_findings=a.findings,
    )


def _write_impact(action: Action, cwd: Path) -> Impact:
    path = _resolve(action.payload.get("path"), cwd)
    if path is None:
        return Impact(notes="path unknown")

    new_content = action.payload.get("content") or ""
    new_bytes = len(new_content.encode("utf-8"))
    exists = path.exists() and path.is_file()
    notes = "overwrites existing file" if exists else "creates new file"

    diff_res = diff_mod.compute(path, new_content)

    old_text = ""
    if exists:
        try:
            old_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            old_text = ""
    findings = code_analysis.analyze(path, old_text, new_content)

    git = git_check.inspect([path], cwd)

    return Impact(
        files_affected=1,
        bytes_affected=max(new_bytes, path.stat().st_size) if exists else new_bytes,
        paths=(str(path),),
        notes=notes,
        diff=diff_res.diff,
        lines_added=diff_res.lines_added,
        lines_removed=diff_res.lines_removed,
        code_findings=findings.findings,
        git=git,
    )


def _replace(base: Impact, **changes) -> Impact:
    data = {
        "files_affected": base.files_affected,
        "bytes_affected": base.bytes_affected,
        "paths": base.paths,
        "notes": base.notes,
        "diff": base.diff,
        "lines_added": base.lines_added,
        "lines_removed": base.lines_removed,
        "code_findings": base.code_findings,
        "git": base.git,
    }
    data.update(changes)
    return Impact(**data)


def _delete_targets(action: Action, cwd: Path) -> list[Path]:
    if action.type == "file":
        p = _resolve(action.payload.get("path"), cwd)
        return [p] if p else []

    cmd = action.payload.get("cmd") or ""
    try:
        tokens = shlex.split(cmd, posix=_POSIX_SHLEX)
    except ValueError:
        tokens = cmd.split()
    # drop the leading verb(s) and flags
    targets: list[Path] = []
    seen_verb = False
    for tok in tokens:
        if not seen_verb:
            if tok.lower() in {"sudo", "doas"}:
                continue
            seen_verb = True
            continue
        if tok.startswith("-"):
            continue
        # expand globs relative to cwd
        if any(ch in tok for ch in "*?[]"):
            try:
                matches = list(cwd.glob(tok))
            except (OSError, ValueError):
                matches = []
            targets.extend(matches)
        else:
            p = _resolve(tok, cwd)
            if p is not None:
                targets.append(p)
    return targets


def _walk_impact(paths: list[Path]) -> Impact:
    files = 0
    total = 0
    seen: list[str] = []
    for p in paths:
        if not p.exists():
            seen.append(str(p))
            continue
        seen.append(str(p))
        if p.is_file():
            files += 1
            try:
                total += p.stat().st_size
            except OSError:
                pass
        elif p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file():
                    files += 1
                    try:
                        total += sub.stat().st_size
                    except OSError:
                        pass
    return Impact(files_affected=files, bytes_affected=total, paths=tuple(seen[:8]))


def _resolve(raw: str | None, cwd: Path) -> Path | None:
    if not raw:
        return None
    p = Path(raw)
    if not p.is_absolute():
        p = cwd / p
    return p


def _human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"
