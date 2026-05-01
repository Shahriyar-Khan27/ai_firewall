"""Role-based access control.

RBAC runs *before* the policy engine. A DENY here returns BLOCK with a
clear "role X cannot do Y" reason. RBAC and the existing PolicyEngine are
parallel guards — both must allow.

Identity sources (priority order, checked left-to-right):
  1. `--as <role>` CLI flag (passed as `cli_role` to resolve_identity)
  2. `AI_FIREWALL_ROLE` env var
  3. `[identity].default_role` from guard.toml
  4. `"dev"` (a permissive built-in default with no roles loaded)
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from ai_firewall.config.guard_toml import GuardToml, Role, glob_match
from ai_firewall.core.action import Action, IntentType
from ai_firewall.engine import intent as intent_mod


@dataclass(frozen=True)
class RBACVerdict:
    decision: str  # "ALLOW" | "DENY"
    reason: str
    role: str


def resolve_identity(
    config: GuardToml,
    *,
    cli_role: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Pick the active role name from the priority chain."""
    if cli_role:
        return cli_role
    env = env if env is not None else os.environ
    if env.get("AI_FIREWALL_ROLE"):
        return env["AI_FIREWALL_ROLE"]
    return config.default_role or "dev"


class RBACEngine:
    """Evaluates an action against a role's intent / path / MCP-tool rules."""

    def __init__(self, config: GuardToml | None = None):
        self.config = config or GuardToml()

    def check(self, action: Action, role_name: str) -> RBACVerdict:
        role = self.config.role(role_name)

        # 1. Intent check.
        intent = intent_mod.classify(action)
        intent_str = intent.value if isinstance(intent, IntentType) else str(intent)
        v = self._check_intent(role, intent_str)
        if v is not None:
            return v

        # 2. File path check (only meaningful for file actions).
        if action.type == "file":
            path = str(action.payload.get("path", ""))
            v = self._check_path(role, path)
            if v is not None:
                return v

        # 3. MCP tool check (`action.context["mcp_tool"]` is set by the proxy).
        mcp_tool = action.context.get("mcp_tool") if action.context else None
        if mcp_tool:
            v = self._check_mcp_tool(role, str(mcp_tool))
            if v is not None:
                return v

        return RBACVerdict("ALLOW", "no rbac rule matched", role.name)

    # --- per-axis checks ---------------------------------------------------

    def _check_intent(self, role: Role, intent: str) -> RBACVerdict | None:
        # Explicit deny always wins.
        if intent in role.deny_intents or "*" in role.deny_intents:
            return RBACVerdict(
                "DENY",
                f"role '{role.name}' cannot do {intent}",
                role.name,
            )
        # Whitelist: if allow_intents is set and `*` not in it, intent must match.
        if role.allow_intents and "*" not in role.allow_intents:
            if intent not in role.allow_intents:
                return RBACVerdict(
                    "DENY",
                    f"role '{role.name}' has no allow rule for {intent}",
                    role.name,
                )
        return None

    def _check_path(self, role: Role, path: str) -> RBACVerdict | None:
        # Deny patterns always win.
        for pat in role.deny_files:
            if glob_match(path, pat):
                return RBACVerdict(
                    "DENY",
                    f"role '{role.name}' denies file path matching `{pat}`",
                    role.name,
                )
        # If allow_files is configured (whitelist mode), path must match one.
        if role.allow_files:
            if not any(glob_match(path, pat) for pat in role.allow_files):
                return RBACVerdict(
                    "DENY",
                    f"role '{role.name}' has no allow_files match for `{path}`",
                    role.name,
                )
        return None

    def _check_mcp_tool(self, role: Role, tool: str) -> RBACVerdict | None:
        if tool in role.deny_mcp_tools:
            return RBACVerdict(
                "DENY",
                f"role '{role.name}' denies MCP tool '{tool}'",
                role.name,
            )
        if role.allow_mcp_tools and tool not in role.allow_mcp_tools:
            return RBACVerdict(
                "DENY",
                f"role '{role.name}' has no allow_mcp_tools entry for '{tool}'",
                role.name,
            )
        return None
