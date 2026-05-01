#!/usr/bin/env python3
"""
Claude Code PreToolUse hook for the AI Execution Firewall.

Reads the tool-call JSON Claude Code sends on stdin, evaluates the action
through the firewall's policy pipeline, and blocks anything dangerous BEFORE
Claude Code executes it. Works even when Claude Code is running in auto-accept
or `--dangerously-skip-permissions` mode — hooks always fire.

Behaviour:
  * Bash    → guard.evaluate(Action.shell(command))
  * Write/Edit/MultiEdit → guard.evaluate(Action.file("write", path, content))
  * Other tools          → pass-through (exit 0)

Decisions:
  ALLOW              → exit 0  (let Claude Code run it)
  REQUIRE_APPROVAL   → exit 2  (block — safer default in auto-mode)
  BLOCK              → exit 2  (block, surface reason to the AI)

To override REQUIRE_APPROVAL behaviour, set env var:
  AI_FIREWALL_HOOK_APPROVAL=allow   → treat REQUIRE_APPROVAL as ALLOW
  AI_FIREWALL_HOOK_APPROVAL=block   → treat REQUIRE_APPROVAL as BLOCK (default)

Wire up via your Claude Code settings.json (see examples/claude-code-settings.json):

  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Write|Edit|MultiEdit",
      "hooks": [{
        "type": "command",
        "command": "python /absolute/path/to/claude-code-pretooluse.py"
      }]
    }]
  }
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any


def _emit_block(reason: str, decision: dict | None = None) -> None:
    """Write Claude Code's expected block-decision JSON and exit 2."""
    payload: dict[str, Any] = {
        "decision": "block",
        "reason": reason,
    }
    if decision is not None:
        payload["firewall"] = decision
    json.dump(payload, sys.stderr)
    sys.stderr.write("\n")
    sys.exit(2)


def _action_for_tool(tool_name: str, tool_input: dict[str, Any]):
    """Map a Claude Code tool call to a firewall Action, or return None to skip."""
    from ai_firewall import Action

    if tool_name == "Bash":
        cmd = (tool_input.get("command") or "").strip()
        if not cmd:
            return None
        return Action.shell(cmd)

    if tool_name in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        path = tool_input.get("file_path") or tool_input.get("path")
        if not path:
            return None
        # For Edit / MultiEdit we don't get the full proposed content easily;
        # use the new_string / edits field as a best-effort body sample.
        content = (
            tool_input.get("content")
            or tool_input.get("new_string")
            or _flatten_edits(tool_input.get("edits"))
            or ""
        )
        return Action.file("write", path, content=content)

    return None  # pass-through for tools we don't gate


def _flatten_edits(edits: Any) -> str:
    if not isinstance(edits, list):
        return ""
    return "\n".join(
        str(e.get("new_string") or "") for e in edits if isinstance(e, dict)
    )


def _approval_mode() -> str:
    raw = os.environ.get("AI_FIREWALL_HOOK_APPROVAL", "block").strip().lower()
    return raw if raw in {"allow", "block"} else "block"


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Malformed input — let Claude Code proceed; better than false-positive blocks.
        sys.exit(0)

    tool_name = input_data.get("tool_name") or ""
    tool_input = input_data.get("tool_input") or {}

    try:
        action = _action_for_tool(tool_name, tool_input)
    except Exception:
        # Never let an exception in the mapping stop Claude Code.
        sys.exit(0)

    if action is None:
        sys.exit(0)

    try:
        from ai_firewall import Guard

        guard = Guard()
        decision = guard.evaluate(action)
    except ImportError:
        # ai_firewall not installed in this Python — silently allow (fail open).
        # Better than blocking everything if the user uninstalls the package.
        sys.exit(0)
    except Exception as e:
        # Any other error: fail open (allow), but log the reason.
        print(f"[ai-firewall hook] internal error: {e}", file=sys.stderr)
        sys.exit(0)

    if decision.decision == "BLOCK":
        _emit_block(
            f"AI Execution Firewall BLOCKED ({decision.risk.name}): {decision.reason}",
            decision=decision.to_dict(),
        )

    if decision.decision == "REQUIRE_APPROVAL":
        if _approval_mode() == "allow":
            sys.exit(0)
        findings = list(decision.impact.code_findings)[:3]
        findings_str = f"; findings: {findings}" if findings else ""
        _emit_block(
            f"AI Execution Firewall requires approval "
            f"({decision.risk.name}): {decision.reason}{findings_str}. "
            f"Either pre-approve via policy or run manually with `guard run`.",
            decision=decision.to_dict(),
        )

    # ALLOW
    sys.exit(0)


if __name__ == "__main__":
    main()
