from __future__ import annotations

import os
import re
import shlex

from ai_firewall.core.action import Action, IntentType

_POSIX_SHLEX = os.name != "nt"


def _split(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=_POSIX_SHLEX)
    except ValueError:
        return cmd.split()

_SHELL_DELETE_CMDS = {"rm", "rmdir", "unlink", "del", "erase"}
_SHELL_WRITE_HINTS = (">", ">>", "tee")
_SHELL_READ_CMDS = {"cat", "less", "more", "head", "tail", "type"}
_CODE_FILE_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".c", ".cpp", ".h")


def classify(action: Action) -> IntentType:
    """Map an Action to its IntentType. Pure, deterministic, no I/O."""
    if action.type == "db":
        # Defer to sql_analysis so the same parser drives both classifier and impact.
        from ai_firewall.engine import sql_analysis
        sql = action.payload.get("sql") or ""
        a = sql_analysis.analyze(sql, dialect=action.payload.get("dialect", "generic"))
        primary = sql_analysis.primary_intent(a.statements)
        if primary == "DB_READ":
            return IntentType.DB_READ
        if primary == "DB_WRITE":
            return IntentType.DB_WRITE
        if primary == "DB_DESTRUCTIVE":
            return IntentType.DB_DESTRUCTIVE
        return IntentType.UNKNOWN

    if action.type == "file":
        op = (action.payload.get("op") or "").lower()
        path = action.payload.get("path") or ""
        if op == "delete":
            return IntentType.FILE_DELETE
        if op in {"write", "create", "append"}:
            if path.endswith(_CODE_FILE_EXTS):
                return IntentType.CODE_MODIFY
            return IntentType.FILE_WRITE
        if op == "read":
            return IntentType.FILE_READ
        return IntentType.UNKNOWN

    if action.type == "shell":
        cmd = (action.payload.get("cmd") or "").strip()
        if not cmd:
            return IntentType.UNKNOWN
        tokens = _split(cmd)
        if not tokens:
            return IntentType.UNKNOWN
        head = tokens[0].lower()
        if head == "sudo" and len(tokens) > 1:
            head = tokens[1].lower()

        if head in _SHELL_DELETE_CMDS:
            return IntentType.FILE_DELETE
        if any(hint in tokens for hint in _SHELL_WRITE_HINTS) or head == "tee":
            return IntentType.FILE_WRITE
        if head in _SHELL_READ_CMDS:
            return IntentType.FILE_READ
        return IntentType.SHELL_EXEC

    return IntentType.UNKNOWN


def feature_flags(action: Action) -> dict[str, bool]:
    """Surface payload features used by the risk analyzer."""
    flags = {
        "recursive": False,
        "wildcard": False,
        "system_path": False,
        "sudo_or_admin": False,
        "force": False,
    }

    if action.type == "shell":
        cmd = action.payload.get("cmd") or ""
        tokens = _split(cmd)
        for tok in tokens:
            if tok in {"-r", "-R", "--recursive"} or re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*", tok):
                flags["recursive"] = True
            if tok in {"-f", "--force"} or re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", tok):
                flags["force"] = True
            if "*" in tok or "?" in tok:
                flags["wildcard"] = True
            if _is_system_path(tok):
                flags["system_path"] = True
        if tokens and tokens[0].lower() in {"sudo", "doas", "runas"}:
            flags["sudo_or_admin"] = True

    elif action.type == "file":
        path = action.payload.get("path") or ""
        if "*" in path or "?" in path:
            flags["wildcard"] = True
        if _is_system_path(path):
            flags["system_path"] = True
        if action.payload.get("recursive"):
            flags["recursive"] = True

    return flags


_SYSTEM_PATH_PATTERNS = (
    re.compile(r"^/$"),
    re.compile(r"^/(etc|usr|var|bin|sbin|boot|lib|lib64|root|sys|proc)(/|$)"),
    re.compile(r"^[A-Za-z]:[\\/]?$"),
    re.compile(r"^[A-Za-z]:[\\/](Windows|Program Files|Program Files \(x86\)|System32)", re.IGNORECASE),
)


def _is_system_path(path: str) -> bool:
    if not path:
        return False
    p = path.strip().strip('"').strip("'")
    return any(pat.match(p) for pat in _SYSTEM_PATH_PATTERNS)
