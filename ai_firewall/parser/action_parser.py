from __future__ import annotations

import os
import shlex
from typing import Any, Iterable

from ai_firewall.core.action import Action


def parse_shell_string(cmd: str, *, cwd: str | None = None) -> Action:
    return Action.shell(cmd.strip(), cwd=cwd or os.getcwd())


def parse_argv(argv: Iterable[str], *, cwd: str | None = None) -> Action:
    rendered = " ".join(shlex.quote(a) for a in argv)
    return Action.shell(rendered, cwd=cwd or os.getcwd())


def parse_dict(payload: dict[str, Any]) -> Action:
    """Parse a structured action description (the form an agent would emit)."""
    type_ = (payload.get("type") or "shell").lower()
    if type_ == "shell":
        cmd = payload.get("cmd") or payload.get("command") or ""
        return Action.shell(str(cmd), cwd=payload.get("cwd"))
    if type_ == "file":
        return Action.file(
            payload.get("op", ""),
            payload.get("path", ""),
            content=payload.get("content"),
        )
    return Action(type=type_, payload=payload, context={"cwd": payload.get("cwd") or os.getcwd()})
