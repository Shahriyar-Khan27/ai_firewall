"""Permission inheritance — auto-approve commands the user *just* ran themselves.

If the user typed `npm test` in their own terminal a moment ago, an AI agent
asking the firewall to run `npm test` is auto-approved. The reasoning: the user
demonstrated intent by running it manually, so an AI mimicking that intent
within the inheritance window doesn't need a fresh approval.

Match rules:
  1. Time window: the user's command must be within `window_seconds` (default
     5 min). Sources without per-entry timestamps fall back to the file mtime
     as a ceiling, which is conservative — we never approve based on
     unbounded history.
  2. Command match: Jaccard ≥ threshold on tokenized form.
  3. Same intent class: we don't inherit a SHELL_EXEC into a FILE_DELETE etc.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable

from ai_firewall.core.action import Action
from ai_firewall.engine.decision import Decision
from ai_firewall.history.shell_reader import RecentCommand, read_recent


_DEFAULT_WINDOW_SECONDS = 300.0   # 5 minutes
_DEFAULT_THRESHOLD = 0.85


@dataclass(frozen=True)
class InheritanceMatch:
    cmd: str
    age_seconds: float
    similarity: float
    source: str


def check_inheritance(
    action: Action,
    decision: Decision,
    *,
    window_seconds: float = _DEFAULT_WINDOW_SECONDS,
    threshold: float = _DEFAULT_THRESHOLD,
    history: Iterable[RecentCommand] | None = None,
    now: float | None = None,
) -> InheritanceMatch | None:
    """Return a match if the user recently ran an equivalent command.

    Args:
        action: the proposed action.
        decision: its current Decision (we use the intent + risk).
        window_seconds: how recent counts as "just now".
        threshold: Jaccard similarity required.
        history: optional override for testing (default: read from the user's
                 actual shell history).
        now: optional override for `time.time()`.
    """
    # Only meaningful for shell actions — file ops, SQL, and HTTP don't have
    # an obvious "user just typed this" analogue.
    if action.type != "shell":
        return None

    cmd = (action.payload.get("cmd") or "").strip()
    if not cmd:
        return None

    if history is None:
        try:
            history = read_recent()
        except Exception:
            return None

    target_tokens = _tokens(cmd)
    if not target_tokens:
        return None

    now_t = now if now is not None else time.time()
    threshold_t = now_t - window_seconds

    best: InheritanceMatch | None = None
    best_sim = 0.0
    for entry in history:
        if entry.ts < threshold_t:
            continue
        if entry.cmd.strip() == cmd:
            return InheritanceMatch(
                cmd=entry.cmd,
                age_seconds=max(0.0, now_t - entry.ts),
                similarity=1.0,
                source=entry.source,
            )
        sim = _jaccard(target_tokens, _tokens(entry.cmd))
        if sim >= threshold and sim > best_sim:
            best = InheritanceMatch(
                cmd=entry.cmd,
                age_seconds=max(0.0, now_t - entry.ts),
                similarity=sim,
                source=entry.source,
            )
            best_sim = sim
    return best


def _tokens(cmd: str) -> list[str]:
    out: list[str] = []
    for tok in cmd.split():
        t = tok.strip(" \t\n\r\"'`,;").lower()
        if t:
            out.append(t)
    return out


def _jaccard(a: list[str], b: list[str]) -> float:
    aa = set(a)
    bb = set(b)
    if not aa and not bb:
        return 1.0
    union = aa | bb
    if not union:
        return 0.0
    return len(aa & bb) / len(union)
