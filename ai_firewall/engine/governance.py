"""Cost & resource governance.

Three concrete enforcements, all reading from the audit log as the source
of truth (so memory + inheritance + the existing pipeline don't have to
double-count):

  1. **Rate limit** — refuse if more than N actions of a given intent in
     the last T seconds. Caps runaway agent loops.
  2. **Loop detection** — same normalized command repeated >N times in
     <T seconds. Catches stuck-in-a-loop agents independent of intent.
  3. **Spend ceiling** — reject API actions when the running token-cost
     for the project exceeds the configured per-day budget. The token
     count is taken from the audit log's `impact.bytes_affected` for API
     actions (a coarse proxy — better than nothing, doesn't require an
     LLM-vendor SDK integration).

Default config lives in `default_rules.yaml` under a new `governance:`
section. Disabled per-Guard via `enable_governance=False`.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ai_firewall.core.action import Action, IntentType


@dataclass(frozen=True)
class GovernanceVerdict:
    decision: str         # "BLOCK"
    reason: str
    rule: str             # "rate_limit" | "loop_detection" | "budget"


@dataclass(frozen=True)
class GovernanceConfig:
    """Knobs read from the YAML rules file's `governance:` section."""

    enabled: bool = True

    # rate_limit: per-intent { window_seconds: int, max: int }
    rate_limits: dict[str, dict[str, int]] = field(default_factory=dict)

    # loop_detection: same normalized command repeated >N times in <T seconds
    loop_window_seconds: int = 10
    loop_max_repeats: int = 5

    # budget: max API "tokens" (proxied by request body bytes) per day
    api_bytes_per_day: int | None = None  # None = no budget

    @classmethod
    def from_rules_dict(cls, rules: dict | None) -> "GovernanceConfig":
        if not rules:
            return cls()
        cfg = (rules.get("governance") or {})
        if not cfg:
            return cls(enabled=True)
        rl = cfg.get("rate_limit") or {}
        rate_limits: dict[str, dict[str, int]] = {}
        for intent_key, spec in rl.items():
            if isinstance(spec, dict):
                rate_limits[intent_key.lower()] = {
                    "window": int(_as_seconds(spec.get("window", 60))),
                    "max": int(spec.get("max", 100)),
                }
        loop = cfg.get("loop_detection") or {}
        budget = cfg.get("budget") or {}
        return cls(
            enabled=bool(cfg.get("enabled", True)),
            rate_limits=rate_limits,
            loop_window_seconds=int(_as_seconds(loop.get("same_command_within", 10))),
            loop_max_repeats=int(loop.get("max", 5)),
            api_bytes_per_day=int(budget["api_bytes_per_day"]) if "api_bytes_per_day" in budget else None,
        )


def _as_seconds(value) -> int:
    """Accept ints, floats, or '60s' / '5m' / '2h' / '1d' strings."""
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        v = value.strip().lower()
        for suffix, mult in (("s", 1), ("m", 60), ("h", 3600), ("d", 86400)):
            if v.endswith(suffix):
                try:
                    return int(float(v[:-1]) * mult)
                except ValueError:
                    break
        try:
            return int(v)
        except ValueError:
            pass
    return 60


# ---------------------------------------------------------------------------
# Rolling counter (reads the JSONL audit log tail)
# ---------------------------------------------------------------------------

class RollingCounter:
    """Counts records in the audit log within a sliding time window.

    Reads the JSONL log tail-up — for governance window checks (last 60s
    of file_delete actions, last 10s of identical commands), we don't need
    the full history; we just walk the file backwards until we cross the
    window boundary, then stop.

    Caches the last scan for ~10ms so back-to-back checks don't re-read.
    """

    def __init__(self, audit_path: Path | str):
        self.audit_path = Path(audit_path)
        self._cached_records: list[dict] | None = None
        self._cached_at: float = 0.0
        self._cache_ttl_s: float = 0.01  # 10ms

    def _load_recent(self) -> list[dict]:
        """Return all records within the last 24h. Cached briefly.

        We always load the full 24h window so callers with different
        per-check windows (10s loop detection, 60s rate limit, 24h budget)
        can share a single read of the log. Each caller filters by its
        own cutoff afterwards.
        """
        now = time.time()
        if self._cached_records is not None and (now - self._cached_at) < self._cache_ttl_s:
            return self._cached_records

        if not self.audit_path.exists():
            self._cached_records = []
            self._cached_at = now
            return []

        cutoff = now - 86400
        records: list[dict] = []
        try:
            with self.audit_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("event") == "init":  # signature-header row
                        continue
                    ts = rec.get("ts", 0)
                    if ts >= cutoff:
                        records.append(rec)
        except OSError:
            return []

        self._cached_records = records
        self._cached_at = now
        return records

    def count_intent(self, intent: str, window_seconds: int) -> int:
        recs = self._load_recent()
        cutoff = time.time() - window_seconds
        return sum(
            1 for r in recs
            if r.get("ts", 0) >= cutoff and r.get("intent") == intent
        )

    def count_command(self, normalized_cmd: str, window_seconds: int) -> int:
        if not normalized_cmd:
            return 0
        recs = self._load_recent()
        cutoff = time.time() - window_seconds
        return sum(
            1 for r in recs
            if r.get("ts", 0) >= cutoff and (r.get("rendered") or "").strip() == normalized_cmd
        )

    def sum_bytes_today(self, action_type: str = "api") -> int:
        """Total `bytes_affected` for `type=action_type` records in the last 24h."""
        recs = self._load_recent()
        cutoff = time.time() - 86400
        total = 0
        for r in recs:
            if r.get("ts", 0) < cutoff:
                continue
            if r.get("type") != action_type:
                continue
            impact = r.get("impact") or {}
            total += int(impact.get("bytes_affected") or 0)
        return total


# ---------------------------------------------------------------------------
# Public check
# ---------------------------------------------------------------------------

def check(
    action: Action,
    *,
    counter: RollingCounter,
    config: GovernanceConfig,
) -> GovernanceVerdict | None:
    """Run all governance checks. Return BLOCK verdict on first violation, else None."""
    if not config.enabled:
        return None

    # 1. Loop detection — same normalized command repeated too fast
    rendered = _render(action)
    if rendered:
        n = counter.count_command(rendered, config.loop_window_seconds)
        if n >= config.loop_max_repeats:
            return GovernanceVerdict(
                decision="BLOCK",
                reason=(
                    f"loop detection: same command run {n} times in last "
                    f"{config.loop_window_seconds}s (max {config.loop_max_repeats})"
                ),
                rule="loop_detection",
            )

    # 2. Rate limit per intent
    intent_key = _intent_key_for(action)
    if intent_key and intent_key in config.rate_limits:
        spec = config.rate_limits[intent_key]
        n = counter.count_intent(intent_key.upper(), spec["window"])
        if n >= spec["max"]:
            return GovernanceVerdict(
                decision="BLOCK",
                reason=(
                    f"rate limit: {n} {intent_key} actions in last "
                    f"{spec['window']}s (max {spec['max']})"
                ),
                rule="rate_limit",
            )

    # 3. Spend ceiling for API actions
    if action.type == "api" and config.api_bytes_per_day is not None:
        used = counter.sum_bytes_today("api")
        if used >= config.api_bytes_per_day:
            return GovernanceVerdict(
                decision="BLOCK",
                reason=(
                    f"budget: {used} api bytes consumed today "
                    f"(cap {config.api_bytes_per_day})"
                ),
                rule="budget",
            )

    return None


def _render(action: Action) -> str:
    if action.type == "shell":
        return str(action.payload.get("cmd", "") or "").strip()
    if action.type == "file":
        return f"{action.payload.get('op', '')} {action.payload.get('path', '')}".strip()
    if action.type == "db":
        return str(action.payload.get("sql", "") or "").strip()
    if action.type == "api":
        return f"{action.payload.get('method', 'GET')} {action.payload.get('url', '')}".strip()
    return ""


def _intent_key_for(action: Action) -> str | None:
    """Pre-classify just enough to route rate_limit lookups.

    For shell, this is a coarse approximation — the real classifier may end
    up with a different intent (FILE_DELETE vs SHELL_EXEC), but the rate
    limit only needs to know "what bucket". We use IntentType.SHELL_EXEC
    as the catch-all bucket for non-file shell.
    """
    from ai_firewall.engine.intent import classify
    try:
        intent = classify(action)
    except Exception:
        return None
    return intent.value.lower() if isinstance(intent, IntentType) else None
