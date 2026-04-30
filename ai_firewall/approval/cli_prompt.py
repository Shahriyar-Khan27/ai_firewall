from __future__ import annotations

import os
import sys
from typing import Callable

from ai_firewall.core.action import Action
from ai_firewall.engine.decision import Decision

ApprovalFn = Callable[[Action, Decision], bool]


def prompt_user(action: Action, decision: Decision) -> bool:
    """Prompt the operator to approve or reject the action.

    Reads from the controlling terminal directly so the prompt still works
    when stdin is being piped from an AI agent.
    """
    banner = render_banner(action, decision)
    tty_in, tty_out = _open_tty()
    try:
        tty_out.write(banner)
        tty_out.flush()
        answer = (tty_in.readline() or "").strip().lower()
    finally:
        if tty_in is not sys.stdin:
            tty_in.close()
        if tty_out is not sys.stderr:
            tty_out.close()
    return answer in {"y", "yes"}


def render_banner(action: Action, decision: Decision) -> str:
    rendered = _render(action)
    impact = decision.impact
    lines = [
        "",
        "[FIREWALL] Action requires approval",
        f"  intent : {decision.intent.value}",
        f"  risk   : {decision.risk.name}",
        f"  reason : {decision.reason}",
        f"  impact : {impact.summary()}",
        f"  cmd    : {rendered}",
    ]
    if impact.code_findings:
        lines.append("  findings:")
        for f in impact.code_findings:
            lines.append(f"    - {f}")
    if impact.git:
        for key in ("uncommitted_changes", "untracked", "gitignored"):
            vals = impact.git.get(key)
            if vals:
                lines.append(f"  git    : {key}: {', '.join(vals[:5])}")
    if impact.diff:
        lines.append("  diff   :")
        for ln in impact.diff.splitlines():
            lines.append(f"    {ln}")
    lines.append("Approve? [y/N]: ")
    return "\n".join(lines)


def auto_deny(_action: Action, _decision: Decision) -> bool:
    return False


def auto_approve(_action: Action, _decision: Decision) -> bool:
    return True


def _open_tty():
    if os.name == "posix":
        try:
            tty_in = open("/dev/tty", "r", encoding="utf-8")
            tty_out = open("/dev/tty", "w", encoding="utf-8")
            return tty_in, tty_out
        except OSError:
            return sys.stdin, sys.stderr
    if os.name == "nt":
        try:
            tty_in = open("CONIN$", "r", encoding="utf-8")
            tty_out = open("CONOUT$", "w", encoding="utf-8")
            return tty_in, tty_out
        except OSError:
            return sys.stdin, sys.stderr
    return sys.stdin, sys.stderr


def _render(action: Action) -> str:
    if action.type == "shell":
        return str(action.payload.get("cmd", ""))
    if action.type == "file":
        return f"{action.payload.get('op', '')} {action.payload.get('path', '')}".strip()
    if action.type == "db":
        return str(action.payload.get("sql", ""))
    return ""
