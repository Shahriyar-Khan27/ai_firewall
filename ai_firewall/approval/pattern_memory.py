"""Approved-pattern memory.

Local SQLite store of "the user already approved this kind of thing here
before, with this risk level — don't ask again". Used to silently auto-approve
routine REQUIRE_APPROVAL actions so the firewall fades into the background
once it's learned the user's habits.

Match rules (all must hold):
  1. Same project path (resolved from action.context.cwd).
  2. Same IntentType.
  3. Current risk ≤ historical risk at approval (never escalate trust).
  4. Fuzzy match on normalized command tokens (Jaccard ≥ threshold).

Storage at ~/.ai-firewall/memory.db. Schema is auto-created on first use.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine.decision import Decision


_DEFAULT_DB_PATH = Path.home() / ".ai-firewall" / "memory.db"
_DEFAULT_THRESHOLD = 0.8


@dataclass(frozen=True)
class MatchResult:
    """Returned from `lookup` when an approved-pattern match is found."""

    similarity: float                  # Jaccard on token bags
    historical_risk: RiskLevel         # the risk at the time of original approval
    seen_count: int                    # how many times we've matched this
    first_at: float
    last_at: float


class PatternMemory:
    """SQLite-backed memory of previously-approved actions per project."""

    def __init__(self, db_path: Path | str | None = None, *, threshold: float = _DEFAULT_THRESHOLD):
        self.db_path = Path(db_path) if db_path is not None else _DEFAULT_DB_PATH
        self.threshold = threshold
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                pattern_hash    TEXT PRIMARY KEY,
                project_path    TEXT NOT NULL,
                intent          TEXT NOT NULL,
                normalized_cmd  TEXT NOT NULL,
                token_bag       TEXT NOT NULL,
                risk_at_approval INTEGER NOT NULL,
                count           INTEGER NOT NULL DEFAULT 1,
                first_at        REAL NOT NULL,
                last_at         REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_project_intent
                ON approvals (project_path, intent);
            """
        )
        self._conn.commit()

    # --- Public API --------------------------------------------------------

    def lookup(self, action: Action, decision: Decision) -> MatchResult | None:
        """Find the best match for `action` in the memory.

        Returns a MatchResult only if (a) project + intent match, (b) similarity
        ≥ threshold, (c) historical risk ≥ current risk. Otherwise returns None.
        """
        normalized = _normalize(action)
        if not normalized:
            return None
        project = _project_path(action)
        token_bag = frozenset(_tokens(normalized))
        if not token_bag:
            return None

        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE project_path = ? AND intent = ?",
            (project, decision.intent.value),
        ).fetchall()

        best: MatchResult | None = None
        best_sim = 0.0
        current_risk = int(decision.risk)
        for row in rows:
            historical_risk = int(row["risk_at_approval"])
            if current_risk > historical_risk:
                continue  # Never auto-approve a higher-risk action than was historically OK
            saved_bag = frozenset((row["token_bag"] or "").split())
            sim = _jaccard(token_bag, saved_bag)
            if sim >= self.threshold and sim > best_sim:
                best = MatchResult(
                    similarity=sim,
                    historical_risk=RiskLevel(historical_risk),
                    seen_count=row["count"],
                    first_at=row["first_at"],
                    last_at=row["last_at"],
                )
                best_sim = sim
        return best

    def record(self, action: Action, decision: Decision) -> None:
        """Record (or refresh) an approval for this action.

        Called after the user approves an action — either via the terminal
        prompt or the VS Code button. Updates count/last_at on collisions.
        """
        normalized = _normalize(action)
        if not normalized:
            return
        project = _project_path(action)
        bag = " ".join(sorted(set(_tokens(normalized))))
        if not bag:
            return

        h = _hash(normalized, decision.intent, project)
        now = time.time()
        self._conn.execute(
            """
            INSERT INTO approvals (
                pattern_hash, project_path, intent, normalized_cmd,
                token_bag, risk_at_approval, count, first_at, last_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(pattern_hash) DO UPDATE SET
                count = count + 1,
                last_at = excluded.last_at,
                risk_at_approval = MAX(risk_at_approval, excluded.risk_at_approval)
            """,
            (h, project, decision.intent.value, normalized, bag, int(decision.risk), now, now),
        )
        self._conn.commit()

    def clear_project(self, project_path: str) -> int:
        """Forget everything for one project. Returns rows deleted."""
        cur = self._conn.execute("DELETE FROM approvals WHERE project_path = ?", (project_path,))
        self._conn.commit()
        return cur.rowcount

    def all_for_project(self, project_path: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM approvals WHERE project_path = ? ORDER BY last_at DESC",
                (project_path,),
            )
        )

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "PatternMemory":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _normalize(action: Action) -> str:
    """Canonical text form of an action — collapses insignificant whitespace.

    For shell actions, we use the AST's full text (with substitutions
    resolved) so `npm  run   build` and `npm run build` collide.
    """
    if action.type == "shell":
        from ai_firewall.parser.shell_ast import parse
        cmd = (action.payload.get("cmd") or "").strip()
        parsed = parse(cmd)
        if parsed.commands:
            return " ; ".join(ec.full_text for ec in parsed.commands)
        return cmd
    if action.type == "file":
        op = action.payload.get("op") or ""
        path = action.payload.get("path") or ""
        return f"{op} {path}".strip()
    if action.type == "db":
        return (action.payload.get("sql") or "").strip()
    if action.type == "api":
        method = action.payload.get("method") or "GET"
        url = action.payload.get("url") or ""
        return f"{method} {url}".strip()
    return ""


def _tokens(s: str) -> list[str]:
    """Whitespace-split tokens, lowercased, de-stripped of trivial wrappers."""
    out: list[str] = []
    for tok in s.split():
        t = tok.strip(" \t\n\r\"'`,;")
        if t:
            out.append(t.lower())
    return out


def _hash(normalized: str, intent: IntentType, project: str) -> str:
    h = hashlib.sha256()
    h.update(intent.value.encode("utf-8"))
    h.update(b"\x00")
    h.update(project.encode("utf-8"))
    h.update(b"\x00")
    h.update(normalized.encode("utf-8"))
    return h.hexdigest()


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    aa = set(a)
    bb = set(b)
    if not aa and not bb:
        return 1.0
    union = aa | bb
    if not union:
        return 0.0
    return len(aa & bb) / len(union)


def _project_path(action: Action) -> str:
    """Resolve the project root for an action.

    Walks up from action.context['cwd'] to find a `.git` directory, but stops
    at the user's home directory — having `.git` at $HOME is common (personal
    dotfiles repo) and shouldn't make every action across all subdirectories
    share one project bucket.
    """
    cwd_raw = (action.context or {}).get("cwd") or os.getcwd()
    cwd = Path(cwd_raw).expanduser()
    try:
        cwd = cwd.resolve()
    except OSError:
        return str(cwd)

    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None

    here = cwd
    for _ in range(20):  # don't walk forever
        if home is not None and here == home:
            return str(cwd)
        if (here / ".git").exists():
            return str(here)
        if here.parent == here:
            break
        here = here.parent
    return str(cwd)
