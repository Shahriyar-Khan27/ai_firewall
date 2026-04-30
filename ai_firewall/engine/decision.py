from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ai_firewall.core.action import IntentType, RiskLevel
from ai_firewall.engine.impact import Impact
from ai_firewall.engine.policy import PolicyVerdict

DecisionKind = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class Decision:
    decision: DecisionKind
    reason: str
    intent: IntentType
    risk: RiskLevel
    impact: Impact

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "intent": self.intent.value,
            "risk": self.risk.name,
            "impact": self.impact.to_dict(),
        }


def decide(verdict: PolicyVerdict, intent: IntentType, risk: RiskLevel, impact: Impact) -> Decision:
    """Combine the policy verdict with risk/impact context. Verdict already wins ordering."""
    return Decision(
        decision=verdict.verdict,
        reason=verdict.reason,
        intent=intent,
        risk=risk,
        impact=impact,
    )
