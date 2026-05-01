from __future__ import annotations

import os
import re
import shlex

from ai_firewall.core.action import Action, IntentType
from ai_firewall.parser.shell_ast import parse as parse_shell_ast

_POSIX_SHLEX = os.name != "nt"


def _split(cmd: str) -> list[str]:
    """Tokenize a shell command — kept as a fallback when AST parsing fails."""
    try:
        return shlex.split(cmd, posix=_POSIX_SHLEX)
    except ValueError:
        return cmd.split()

_SHELL_DELETE_CMDS = {"rm", "rmdir", "unlink", "del", "erase"}
_SHELL_WRITE_HINTS = (">", ">>", "tee")
_SHELL_READ_CMDS = {"cat", "less", "more", "head", "tail", "type"}
_CODE_FILE_EXTS = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".c", ".cpp", ".h")

# Egress verbs — shell commands that issue HTTP requests (treated as API_*
# matching the verb's HTTP method) vs. open raw network sockets (NETWORK_EGRESS).
_HTTP_EGRESS_VERBS = {"curl", "wget", "httpie", "http", "https", "fetch"}
_RAW_NETWORK_VERBS = {"nc", "ncat", "telnet", "socat"}
_FILE_TRANSFER_VERBS = {"scp", "rsync", "sftp", "ftp"}

# Ordering used to pick the "worst" intent across multi-command shell input.
# Higher rank = more dangerous; higher rank wins.
_INTENT_RANK = {
    IntentType.UNKNOWN: 0,
    IntentType.FILE_READ: 1,
    IntentType.SHELL_EXEC: 2,
    IntentType.FILE_WRITE: 3,
    IntentType.CODE_MODIFY: 4,
    IntentType.FILE_DELETE: 5,
    IntentType.DB_READ: 1,
    IntentType.DB_WRITE: 3,
    IntentType.DB_DESTRUCTIVE: 5,
    IntentType.API_READ: 1,
    IntentType.API_WRITE: 3,
    IntentType.API_DESTRUCTIVE: 5,
    IntentType.NETWORK_EGRESS: 5,
}


_URL_RE = re.compile(r"https?://[^\s\"'`]+")


def _http_method_from_curl_args(args: list[str]) -> str:
    """Inspect curl/wget args and infer the HTTP method (default GET)."""
    for i, tok in enumerate(args):
        # curl: `-X METHOD` or `--request METHOD`
        if tok in ("-X", "--request") and i + 1 < len(args):
            return args[i + 1].upper()
        # curl shortcuts
        if tok in ("--get", "-G"):
            return "GET"
        if tok == "--head" or tok == "-I":
            return "HEAD"
        if tok in ("-d", "--data", "--data-raw", "--data-binary", "--form", "-F", "--data-urlencode"):
            return "POST"  # presence of body data implies POST unless overridden later
    return "GET"


def _extract_egress_url(verb: str, args: list[str]) -> str | None:
    """Find the first http(s) URL in the args of a curl/wget/etc command."""
    for tok in args:
        m = _URL_RE.search(tok)
        if m:
            return m.group(0).rstrip(",;)")
    return None


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

    if action.type == "api":
        from ai_firewall.engine import url_analysis
        primary = url_analysis.primary_intent(action.payload.get("method") or "GET")
        if primary == "API_READ":
            return IntentType.API_READ
        if primary == "API_WRITE":
            return IntentType.API_WRITE
        if primary == "API_DESTRUCTIVE":
            return IntentType.API_DESTRUCTIVE
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

        # Walk the AST: for chained / piped / obfuscated commands, each
        # EffectiveCommand is classified individually and the worst wins.
        # This catches `echo "<base64>" | base64 -d | sh` as FILE_DELETE,
        # not SHELL_EXEC (which would otherwise be the verb of `sh`).
        parsed = parse_shell_ast(cmd)
        if parsed.commands:
            worst = IntentType.UNKNOWN
            worst_rank = -1
            for ec in parsed.commands:
                intent = _classify_shell_tokens([ec.verb, *ec.args])
                rank = _INTENT_RANK.get(intent, 0)
                if rank > worst_rank:
                    worst = intent
                    worst_rank = rank
            return worst

        # Fallback: AST parse failed entirely.
        return _classify_shell_tokens(_split(cmd))

    return IntentType.UNKNOWN


def _classify_shell_tokens(tokens: list[str]) -> IntentType:
    """Classify a single command's verb + args. Pure, no AST."""
    if not tokens:
        return IntentType.UNKNOWN
    head = (tokens[0] or "").lower()
    if head == "sudo" and len(tokens) > 1:
        head = (tokens[1] or "").lower()

    if head in _SHELL_DELETE_CMDS:
        return IntentType.FILE_DELETE

    # Egress: HTTP-issuing verbs map to API_*; raw-socket / file-transfer verbs
    # map to NETWORK_EGRESS regardless of method.
    if head in _HTTP_EGRESS_VERBS:
        method = _http_method_from_curl_args(tokens[1:])
        if method in ("DELETE",):
            return IntentType.API_DESTRUCTIVE
        if method in ("POST", "PUT", "PATCH", "MERGE"):
            return IntentType.API_WRITE
        return IntentType.API_READ  # GET/HEAD/OPTIONS or no body
    if head in _RAW_NETWORK_VERBS or head in _FILE_TRANSFER_VERBS:
        return IntentType.NETWORK_EGRESS

    if any(hint in tokens for hint in _SHELL_WRITE_HINTS) or head == "tee":
        return IntentType.FILE_WRITE
    if head in _SHELL_READ_CMDS:
        return IntentType.FILE_READ
    return IntentType.SHELL_EXEC


def feature_flags(action: Action) -> dict[str, bool]:
    """Surface payload features used by the risk analyzer.

    For shell actions, walks the AST and unions flags across every effective
    command (so an obfuscated payload's flags bubble up). Sets
    `obfuscation_detected` when any command came from a decoded base64/hex
    payload — that alone is grounds for risk to bump.
    """
    flags = {
        "recursive": False,
        "wildcard": False,
        "system_path": False,
        "sudo_or_admin": False,
        "force": False,
        "obfuscation_detected": False,
    }

    if action.type == "shell":
        cmd = action.payload.get("cmd") or ""
        parsed = parse_shell_ast(cmd)

        if parsed.obfuscation_detected:
            flags["obfuscation_detected"] = True

        if parsed.commands:
            for ec in parsed.commands:
                tokens = [ec.verb, *ec.args]
                _union_token_flags(tokens, flags)
            return flags

        # Fallback when AST parsing failed entirely
        _union_token_flags(_split(cmd), flags)
        return flags

    elif action.type == "file":
        path = action.payload.get("path") or ""
        if "*" in path or "?" in path:
            flags["wildcard"] = True
        if _is_system_path(path):
            flags["system_path"] = True
        if action.payload.get("recursive"):
            flags["recursive"] = True

    return flags


def _union_token_flags(tokens: list[str], flags: dict[str, bool]) -> None:
    """Mutate `flags` in place to OR-in any signal from this command's tokens."""
    for tok in tokens:
        if tok in {"-r", "-R", "--recursive"} or re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*", tok):
            flags["recursive"] = True
        if tok in {"-f", "--force"} or re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", tok):
            flags["force"] = True
        if "*" in tok or "?" in tok:
            flags["wildcard"] = True
        if _is_system_path(tok):
            flags["system_path"] = True
    if tokens and (tokens[0] or "").lower() in {"sudo", "doas", "runas"}:
        flags["sudo_or_admin"] = True


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
