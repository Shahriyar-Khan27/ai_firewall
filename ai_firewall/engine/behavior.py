"""Rule-based behavior analytics.

Three anomaly heuristics, all read from the audit log via `RollingCounter`:

  1. **rate_burst** — too many actions of one intent in a short window
     (e.g. >20 FILE_DELETE in 60s). Per-intent thresholds configurable.
  2. **rate_spike** — the last-hour intent rate is >Nx the project's
     24h median per-hour rate. Catches sudden volume jumps even when
     the per-minute burst threshold isn't tripped.
  3. **quiet_hour** — action issued during an hour-of-day window that
     historically has zero observed activity. Needs at least 24h of
     history before it ever fires.

Behavior runs LAST in `Guard.evaluate()`. An anomaly only ever
*downgrades* an ALLOW into REQUIRE_APPROVAL — it never escalates a
BLOCK or upgrades an existing approval.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from ai_firewall.core.action import Action, IntentType
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine.governance import RollingCounter


@dataclass(frozen=True)
class AnomalyVerdict:
    rule: str  # "rate_burst" | "rate_spike" | "quiet_hour"
    reason: str


@dataclass(frozen=True)
class BehaviorConfig:
    enabled: bool = True

    # rate_burst — per-intent count threshold within `burst_window_seconds`
    rate_burst: dict[str, int] = field(default_factory=dict)
    burst_window_seconds: int = 60

    # rate_spike — last hour rate vs 24h median (per-hour)
    rate_multiplier_threshold: float = 5.0
    spike_min_baseline_hours: int = 6  # need at least 6h of history

    # quiet_hour
    quiet_hour_min_total_actions: int = 100  # enough history before flagging
    quiet_hour_min_distinct_hours: int = 12  # how many hours-of-day must be observed

    @classmethod
    def from_rules_dict(cls, rules: dict | None) -> "BehaviorConfig":
        if not rules:
            return cls()
        cfg = (rules.get("behavior") or {})
        if not cfg:
            return cls()
        rb = cfg.get("rate_burst") or {}
        return cls(
            enabled=bool(cfg.get("enabled", True)),
            rate_burst={str(k).lower(): int(v) for k, v in rb.items()},
            burst_window_seconds=int(cfg.get("burst_window_seconds", 60)),
            rate_multiplier_threshold=float(cfg.get("rate_multiplier_threshold", 5.0)),
            spike_min_baseline_hours=int(cfg.get("spike_min_baseline_hours", 6)),
            quiet_hour_min_total_actions=int(cfg.get("quiet_hour_min_total_actions", 100)),
            quiet_hour_min_distinct_hours=int(cfg.get("quiet_hour_min_distinct_hours", 12)),
        )


class BehaviorEngine:
    """Runs the three anomaly heuristics against a fresh action."""

    def __init__(self, audit_path: Path | str, config: BehaviorConfig | None = None):
        self.audit_path = Path(audit_path)
        self.config = config or BehaviorConfig()
        self.counter = RollingCounter(self.audit_path)

    def detect_anomaly(self, action: Action) -> AnomalyVerdict | None:
        if not self.config.enabled:
            return None

        intent_key = self._intent_key(action)
        if intent_key is None:
            return None

        # 1. Burst: too many of this intent recently.
        burst = self._check_burst(intent_key)
        if burst is not None:
            return burst

        # 2. Spike: last hour rate vs 24h baseline.
        spike = self._check_spike(intent_key)
        if spike is not None:
            return spike

        # 3. Quiet hour: action in a historically-zero hour-of-day window.
        quiet = self._check_quiet_hour(intent_key)
        if quiet is not None:
            return quiet

        return None

    # --- heuristics --------------------------------------------------------

    def _check_burst(self, intent_key: str) -> AnomalyVerdict | None:
        threshold = self.config.rate_burst.get(intent_key)
        if not threshold:
            return None
        n = self.counter.count_intent(intent_key.upper(), self.config.burst_window_seconds)
        if n >= threshold:
            return AnomalyVerdict(
                rule="rate_burst",
                reason=(
                    f"{n} {intent_key} actions in last "
                    f"{self.config.burst_window_seconds}s "
                    f"(threshold {threshold})"
                ),
            )
        return None

    def _check_spike(self, intent_key: str) -> AnomalyVerdict | None:
        recs = self.counter._load_recent()
        if not recs:
            return None

        now = time.time()
        # Per-hour bucket counts for this intent over the last 24h.
        buckets: dict[int, int] = {}
        oldest_ts = now
        for r in recs:
            if r.get("intent") != intent_key.upper():
                continue
            ts = r.get("ts", 0)
            if ts <= 0:
                continue
            oldest_ts = min(oldest_ts, ts)
            hour_bucket = int((now - ts) // 3600)
            if 0 <= hour_bucket < 24:
                buckets[hour_bucket] = buckets.get(hour_bucket, 0) + 1

        # Need a meaningful baseline window before computing a multiplier.
        history_hours = max(1, int((now - oldest_ts) // 3600))
        if history_hours < self.config.spike_min_baseline_hours:
            return None
        if not buckets:
            return None

        last_hour = buckets.get(0, 0)
        # Median of past hours (excluding the current one).
        past = [buckets.get(h, 0) for h in range(1, min(24, history_hours))]
        if not past:
            return None
        past_sorted = sorted(past)
        median = past_sorted[len(past_sorted) // 2]
        # Floor median at 1 so we don't divide by zero or flag every first action.
        median = max(median, 1)
        if last_hour >= self.config.rate_multiplier_threshold * median:
            return AnomalyVerdict(
                rule="rate_spike",
                reason=(
                    f"{intent_key} rate {last_hour}/hr vs 24h median {median}/hr "
                    f"(>{self.config.rate_multiplier_threshold:.1f}x)"
                ),
            )
        return None

    def _check_quiet_hour(self, intent_key: str) -> AnomalyVerdict | None:
        recs = self.counter._load_recent()
        if len(recs) < self.config.quiet_hour_min_total_actions:
            return None

        # Bucket by hour-of-day (0..23) using local time on each record.
        # Only count records of the same intent — quiet for FILE_DELETE at 3am
        # doesn't matter if SHELL_EXEC is busy at 3am.
        seen_in_hour: dict[int, int] = {}
        target_intent = intent_key.upper()
        for r in recs:
            if r.get("intent") != target_intent:
                continue
            ts = r.get("ts", 0)
            if ts <= 0:
                continue
            hod = time.localtime(ts).tm_hour
            seen_in_hour[hod] = seen_in_hour.get(hod, 0) + 1

        # Need at least one observation of this intent before flagging quiet hours.
        if not seen_in_hour:
            return None

        # Only meaningful when history spans most of the day. If the log only
        # covers, say, 3 hours-of-day, every other 21 hours look "quiet" — but
        # that's a sparse-history artefact, not behaviour we should flag.
        if len(seen_in_hour) < self.config.quiet_hour_min_distinct_hours:
            return None

        current_hod = time.localtime(time.time()).tm_hour
        if seen_in_hour.get(current_hod, 0) == 0:
            return AnomalyVerdict(
                rule="quiet_hour",
                reason=(
                    f"{intent_key} action at hour {current_hod:02d}:00 — "
                    f"no historical {intent_key} activity in this hour-of-day"
                ),
            )
        return None

    # --- helpers -----------------------------------------------------------

    @staticmethod
    def _intent_key(action: Action) -> str | None:
        try:
            it = intent_mod.classify(action)
        except Exception:
            return None
        return it.value.lower() if isinstance(it, IntentType) else None
