from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ai_firewall.adapters.api import APIAnalyzeAdapter
from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.adapters.db import DBAnalyzeAdapter
from ai_firewall.adapters.file import FileAdapter
from ai_firewall.adapters.shell import ShellAdapter
from ai_firewall.approval.cli_prompt import ApprovalFn, prompt_user
from ai_firewall.approval.pattern_memory import PatternMemory
from ai_firewall.audit.logger import AuditLogger
from ai_firewall.core.action import Action
from ai_firewall.config import guard_toml as guard_toml_mod
from ai_firewall.engine import governance as gov_mod
from ai_firewall.engine import impact as impact_mod
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine import risk as risk_mod
from ai_firewall.engine.behavior import BehaviorConfig, BehaviorEngine
from ai_firewall.engine.decision import Decision, decide
from ai_firewall.engine.inheritance import InheritanceMatch, check_inheritance
from ai_firewall.engine.policy import PolicyEngine
from ai_firewall.engine.rbac import RBACEngine, resolve_identity


class Blocked(Exception):
    """Raised when an action is blocked by policy or rejected by the operator."""

    def __init__(self, decision: Decision):
        super().__init__(f"{decision.decision}: {decision.reason}")
        self.decision = decision


@dataclass
class GuardResult:
    decision: Decision
    execution: ExecutionResult


class Guard:
    """Orchestrates the firewall pipeline for a single Action."""

    def __init__(
        self,
        rules_path: Path | str | None = None,
        audit_path: Path | str | None = None,
        approval_fn: ApprovalFn = prompt_user,
        adapters: dict[str, ExecutionAdapter] | None = None,
        *,
        memory: PatternMemory | None = None,
        memory_db_path: Path | str | None = None,
        enable_memory: bool = True,
        enable_inheritance: bool = True,
        enable_governance: bool = True,
        enable_rbac: bool = True,
        enable_behavior: bool = True,
        role: str | None = None,
        guard_toml_path: Path | str | None = None,
        inheritance_window_seconds: float = 300.0,
    ):
        self.policy = (
            PolicyEngine.from_file(Path(rules_path)) if rules_path else PolicyEngine.from_default()
        )
        if audit_path is not None:
            resolved_audit_path = Path(audit_path)
        else:
            env_audit = os.environ.get("AI_FIREWALL_AUDIT_PATH")
            resolved_audit_path = Path(env_audit) if env_audit else Path("logs/audit.jsonl")
        self.audit = AuditLogger(resolved_audit_path)
        self.approval_fn = approval_fn

        # Defaults are analyze-only for db/api so the firewall never executes
        # anything dangerous unless the caller opts in by passing a custom
        # adapter (e.g. SQLiteExecuteAdapter via `guard sql --execute`).
        defaults: dict[str, ExecutionAdapter] = {
            "shell": ShellAdapter(),
            "file": FileAdapter(),
            "db": DBAnalyzeAdapter(),
            "api": APIAnalyzeAdapter(),
        }
        if adapters:
            defaults.update(adapters)
        self.adapters: dict[str, ExecutionAdapter] = defaults

        # Smart-flow optional features (v0.3.0):
        #   memory       — auto-approves repeats of previously-approved actions
        #   inheritance  — auto-approves AI's request when user just ran the same
        # Both can be disabled per-Guard for tests / strict-mode users.
        self.enable_memory = enable_memory
        self.enable_inheritance = enable_inheritance
        self.inheritance_window_seconds = inheritance_window_seconds
        if memory is not None:
            self.memory = memory
            self._owns_memory = False
        elif enable_memory:
            self.memory = PatternMemory(memory_db_path) if memory_db_path else PatternMemory()
            self._owns_memory = True
        else:
            self.memory = None
            self._owns_memory = False

        # v0.4.0 governance: rate limits, loop detection, daily API budget.
        # Reads the same audit log this Guard writes to as the source of truth.
        self.enable_governance = enable_governance
        self.governance_config = gov_mod.GovernanceConfig.from_rules_dict(self.policy.rules)
        self.governance_counter = gov_mod.RollingCounter(self.audit.path)

        # v0.4.0 RBAC: per-role intent / path / MCP-tool gates loaded from
        # ~/.ai-firewall/guard.toml (and per-project .guard.toml override).
        self.enable_rbac = enable_rbac
        if guard_toml_path is not None:
            self.guard_toml = guard_toml_mod.load([Path(guard_toml_path)])
        else:
            self.guard_toml = guard_toml_mod.load()
        self.rbac = RBACEngine(self.guard_toml)
        self.role = resolve_identity(self.guard_toml, cli_role=role)

        # v0.4.0 behavior analytics: rule-based anomaly detection that can
        # downgrade ALLOW → REQUIRE_APPROVAL. Never escalates BLOCK.
        self.enable_behavior = enable_behavior
        self.behavior_config = BehaviorConfig.from_rules_dict(self.policy.rules)
        self.behavior = BehaviorEngine(self.audit.path, self.behavior_config)

    # --- Pipeline ----------------------------------------------------------

    def evaluate(self, action: Action) -> Decision:
        intent = intent_mod.classify(action)
        flags = intent_mod.feature_flags(action)
        base_risk = risk_mod.score(action, intent, flags)

        # v0.4.0 RBAC: identity gate. DENY here is final — no smart-flow,
        # no policy fallback. ALLOW falls through to the normal pipeline.
        if self.enable_rbac and self.guard_toml.roles:
            rbac_v = self.rbac.check(action, self.role)
            if rbac_v.decision == "DENY":
                return Decision(
                    decision="BLOCK",
                    reason=f"rbac: {rbac_v.reason}",
                    intent=intent,
                    risk=base_risk,
                    impact=impact_mod.Impact(notes="not computed (rbac block)"),
                )

        # v0.4.0 governance: rate limit, loop detection, daily API budget.
        # Runs before policy so a runaway loop can't slip through smart-flow.
        if self.enable_governance:
            gov_verdict = gov_mod.check(
                action, counter=self.governance_counter, config=self.governance_config
            )
            if gov_verdict is not None:
                return Decision(
                    decision="BLOCK",
                    reason=f"governance ({gov_verdict.rule}): {gov_verdict.reason}",
                    intent=intent,
                    risk=base_risk,
                    impact=impact_mod.Impact(notes="not computed (governance block)"),
                )

        # First pass: cheap policy check on base risk. BLOCK short-circuits.
        verdict = self.policy.evaluate(action, intent, base_risk)
        if verdict.verdict == "BLOCK":
            return decide(verdict, intent, base_risk, impact_mod.Impact(notes="not computed (blocked)"))

        # Impact + risk re-bump (existing v0.2.x behaviour).
        impact = impact_mod.estimate(action, intent)
        risk = risk_mod.apply_impact(base_risk, impact)
        if risk > base_risk:
            verdict = self.policy.evaluate(action, intent, risk)

        decision = decide(verdict, intent, risk, impact)

        # v0.3.0 smart-flow: when policy says REQUIRE_APPROVAL, see if memory
        # or inheritance can downgrade to a silent ALLOW. Never used to escalate.
        if decision.decision == "REQUIRE_APPROVAL":
            silent = self._maybe_silent_approve(action, decision)
            if silent is not None:
                decision = silent

        # v0.4.0 behavior analytics: anomaly downgrades ALLOW into
        # REQUIRE_APPROVAL. Never escalates BLOCK or upgrades approval.
        if self.enable_behavior and decision.decision == "ALLOW":
            try:
                anomaly = self.behavior.detect_anomaly(action)
            except Exception:
                anomaly = None
            if anomaly is not None:
                decision = Decision(
                    decision="REQUIRE_APPROVAL",
                    reason=f"behavior anomaly ({anomaly.rule}): {anomaly.reason}",
                    intent=decision.intent,
                    risk=decision.risk,
                    impact=decision.impact,
                )

        return decision

    def execute(self, action: Action) -> GuardResult:
        decision = self.evaluate(action)

        if decision.decision == "BLOCK":
            self.audit.log(action, decision, None, approved=False)
            raise Blocked(decision)

        approved: bool | None = None
        if decision.decision == "REQUIRE_APPROVAL":
            approved = bool(self.approval_fn(action, decision))
            if not approved:
                self.audit.log(action, decision, None, approved=False)
                raise Blocked(decision)
            # User explicitly approved → record into memory for next time.
            if self.enable_memory and self.memory is not None:
                try:
                    self.memory.record(action, decision)
                except Exception:
                    pass  # never let memory bookkeeping break execution

        adapter = self.adapters.get(action.type)
        if adapter is None:
            result = ExecutionResult(exit_code=2, stderr=f"no adapter for type '{action.type}'", executed=False)
            self.audit.log(action, decision, result, approved=approved)
            return GuardResult(decision=decision, execution=result)

        result = adapter.run(action)
        self.audit.log(action, decision, result, approved=approved if approved is not None else True)
        return GuardResult(decision=decision, execution=result)

    # --- Smart-flow helpers ------------------------------------------------

    def _maybe_silent_approve(self, action: Action, decision: Decision) -> Decision | None:
        """If memory or inheritance covers this action, return a downgraded
        ALLOW Decision with a clear reason. Otherwise None."""

        # Inheritance first: cheaper than DB lookup, and "user just typed this"
        # is the strongest signal of intent.
        if self.enable_inheritance and action.type == "shell":
            try:
                inh = check_inheritance(
                    action, decision, window_seconds=self.inheritance_window_seconds
                )
            except Exception:
                inh = None
            if inh is not None:
                age = int(inh.age_seconds)
                return Decision(
                    decision="ALLOW",
                    reason=(
                        f"inheritance: user ran an equivalent command "
                        f"({inh.similarity:.0%} match) {age}s ago in {inh.source}"
                    ),
                    intent=decision.intent,
                    risk=decision.risk,
                    impact=decision.impact,
                )

        # Then memory: project + intent + ≥0.8 Jaccard match where
        # historical_risk ≥ current risk.
        if self.enable_memory and self.memory is not None:
            try:
                match = self.memory.lookup(action, decision)
            except Exception:
                match = None
            if match is not None:
                return Decision(
                    decision="ALLOW",
                    reason=(
                        f"memory match: {match.similarity:.0%} similar to a "
                        f"previously-approved action ({match.seen_count}x)"
                    ),
                    intent=decision.intent,
                    risk=decision.risk,
                    impact=decision.impact,
                )

        return None

    # --- Cleanup -----------------------------------------------------------

    def close(self) -> None:
        if self._owns_memory and self.memory is not None:
            try:
                self.memory.close()
            except Exception:
                pass
            self.memory = None

    def __enter__(self) -> "Guard":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
