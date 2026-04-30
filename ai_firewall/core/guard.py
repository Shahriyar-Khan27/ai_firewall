from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ai_firewall.adapters.api import APIAnalyzeAdapter
from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.adapters.db import DBAnalyzeAdapter
from ai_firewall.adapters.file import FileAdapter
from ai_firewall.adapters.shell import ShellAdapter
from ai_firewall.approval.cli_prompt import ApprovalFn, prompt_user
from ai_firewall.audit.logger import AuditLogger
from ai_firewall.core.action import Action
from ai_firewall.engine import impact as impact_mod
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine import risk as risk_mod
from ai_firewall.engine.decision import Decision, decide
from ai_firewall.engine.policy import PolicyEngine


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
    ):
        self.policy = (
            PolicyEngine.from_file(Path(rules_path)) if rules_path else PolicyEngine.from_default()
        )
        self.audit = AuditLogger(Path(audit_path) if audit_path else Path("logs/audit.jsonl"))
        self.approval_fn = approval_fn
        self.adapters: dict[str, ExecutionAdapter] = adapters or {
            "shell": ShellAdapter(),
            "file": FileAdapter(),
            "db": DBAnalyzeAdapter(),
            "api": APIAnalyzeAdapter(),
        }

    def evaluate(self, action: Action) -> Decision:
        intent = intent_mod.classify(action)
        flags = intent_mod.feature_flags(action)
        base_risk = risk_mod.score(action, intent, flags)

        # First pass: cheap policy check on base risk. If this BLOCKs, skip impact —
        # walking large trees (e.g. for `rm -rf /`) before a sure BLOCK is wasteful.
        verdict = self.policy.evaluate(action, intent, base_risk)
        if verdict.verdict == "BLOCK":
            return decide(verdict, intent, base_risk, impact_mod.Impact(notes="not computed (blocked)"))

        # Compute impact, then let it bump risk (e.g. AST removed functions, git
        # uncommitted changes, large blast radius). Re-evaluate policy if risk grew —
        # a finding may now cross a require_approval threshold.
        impact = impact_mod.estimate(action, intent)
        risk = risk_mod.apply_impact(base_risk, impact)
        if risk > base_risk:
            verdict = self.policy.evaluate(action, intent, risk)

        return decide(verdict, intent, risk, impact)

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

        adapter = self.adapters.get(action.type)
        if adapter is None:
            result = ExecutionResult(exit_code=2, stderr=f"no adapter for type '{action.type}'", executed=False)
            self.audit.log(action, decision, result, approved=approved)
            return GuardResult(decision=decision, execution=result)

        result = adapter.run(action)
        self.audit.log(action, decision, result, approved=approved if approved is not None else True)
        return GuardResult(decision=decision, execution=result)
