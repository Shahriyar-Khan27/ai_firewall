from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml

from ai_firewall.core.action import Action, IntentType, RiskLevel

Verdict = Literal["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class PolicyVerdict:
    verdict: Verdict
    reason: str


class PolicyEngine:
    def __init__(self, rules: dict[str, Any]):
        self._rules = rules or {}

    @classmethod
    def from_default(cls) -> "PolicyEngine":
        with resources.files("ai_firewall.config").joinpath("default_rules.yaml").open("r", encoding="utf-8") as fh:
            rules = yaml.safe_load(fh) or {}
        return cls(rules)

    @classmethod
    def from_file(cls, path: Path) -> "PolicyEngine":
        with Path(path).open("r", encoding="utf-8") as fh:
            rules = yaml.safe_load(fh) or {}
        return cls(rules)

    @property
    def rules(self) -> dict[str, Any]:
        return self._rules

    def evaluate(self, action: Action, intent: IntentType, risk: RiskLevel) -> PolicyVerdict:
        intent_key = intent.value.lower()
        primary = self._rules.get(intent_key, {}) or {}

        # Shell actions also consult shell_exec rules so command-shape patterns
        # (e.g. `rm -rf /`, fork bombs) apply regardless of inferred intent.
        sections: list[tuple[str, dict]] = [(intent_key, primary)]
        if action.type == "shell" and intent_key != "shell_exec":
            shell_section = self._rules.get("shell_exec", {}) or {}
            if shell_section:
                sections.append(("shell_exec", shell_section))

        rendered = self._render(action)
        path = action.payload.get("path", "")

        for _name, sect in sections:
            for pat in sect.get("allowed", []) or []:
                if re.search(pat, rendered):
                    return PolicyVerdict("ALLOW", f"matches allowlist `{pat}`")

        for name, sect in sections:
            for pat in sect.get("blocked", []) or []:
                if re.search(pat, rendered):
                    return PolicyVerdict("BLOCK", f"matches blocked pattern `{pat}` in `{name}`")
            for pat in sect.get("blocked_paths", []) or []:
                if path and (fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path.replace("\\", "/"), pat)):
                    return PolicyVerdict("BLOCK", f"path matches blocked glob `{pat}` in `{name}`")

        for name, sect in sections:
            approval = sect.get("require_approval")
            if approval is True:
                return PolicyVerdict("REQUIRE_APPROVAL", f"policy `{name}.require_approval` is true")
            if isinstance(approval, dict):
                threshold_raw = approval.get("risk_at_or_above")
                if threshold_raw is not None:
                    threshold = RiskLevel.parse(threshold_raw)
                    if risk >= threshold:
                        return PolicyVerdict(
                            "REQUIRE_APPROVAL",
                            f"risk {risk.name} >= threshold {threshold.name} in `{name}`",
                        )

        return PolicyVerdict("ALLOW", "no matching block or approval rule")

    @staticmethod
    def _render(action: Action) -> str:
        if action.type == "shell":
            return str(action.payload.get("cmd", ""))
        if action.type == "file":
            op = action.payload.get("op", "")
            path = action.payload.get("path", "")
            return f"{op} {path}"
        if action.type == "db":
            return str(action.payload.get("sql", ""))
        if action.type == "api":
            return f"{action.payload.get('method', 'GET')} {action.payload.get('url', '')}".strip()
        return ""
