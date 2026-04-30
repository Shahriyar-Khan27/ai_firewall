from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

_MAX_DIFF_LINES = 200
_MAX_LINE_LEN = 500


@dataclass(frozen=True)
class DiffResult:
    diff: str
    lines_added: int
    lines_removed: int


def compute(path: Path | None, new_content: str) -> DiffResult:
    """Render a unified diff between the file at `path` (if any) and `new_content`.

    Truncated to keep prompts readable. Returns empty diff for new files but
    still reports line counts.
    """
    new_lines = new_content.splitlines(keepends=True)
    if path and path.exists() and path.is_file():
        try:
            old_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return DiffResult(diff="<binary or unreadable file>", lines_added=0, lines_removed=0)
        old_lines = old_text.splitlines(keepends=True)
        from_label = str(path)
        to_label = str(path) + " (proposed)"
    else:
        old_lines = []
        from_label = "/dev/null"
        to_label = str(path) if path else "(new file)"

    raw_diff = list(
        difflib.unified_diff(old_lines, new_lines, fromfile=from_label, tofile=to_label, n=3)
    )
    added = sum(1 for ln in raw_diff if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in raw_diff if ln.startswith("-") and not ln.startswith("---"))

    truncated = raw_diff[:_MAX_DIFF_LINES]
    rendered = "".join(_clip(ln) for ln in truncated)
    if len(raw_diff) > _MAX_DIFF_LINES:
        rendered += f"\n... ({len(raw_diff) - _MAX_DIFF_LINES} more diff lines truncated)\n"
    return DiffResult(diff=rendered, lines_added=added, lines_removed=removed)


def _clip(line: str) -> str:
    if len(line) <= _MAX_LINE_LEN:
        return line
    return line[: _MAX_LINE_LEN - 3] + "...\n"
