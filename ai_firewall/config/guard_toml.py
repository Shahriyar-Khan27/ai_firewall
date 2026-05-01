"""guard.toml loader, role-inheritance resolver, glob matcher.

Schema (per `~/.ai-firewall/guard.toml` or per-project `.guard.toml`):

    [identity]
    default_role = "dev"

    [roles.dev]
    allow_intents   = ["*"]                        # everything by default
    deny_intents    = []                           # explicit intent denies
    allow_files     = ["./**", "~/projects/**"]   # whitelist paths (omit for "all")
    deny_files      = ["~/.ssh/**"]                # denies always win
    allow_mcp_tools = ["fetch", "filesystem"]      # whitelist MCP tools
    deny_mcp_tools  = []

    [roles.dev-junior]
    inherits = "dev"
    deny_intents = ["FILE_DELETE", "DB_DESTRUCTIVE"]

    [roles.admin]
    allow_intents = ["*"]

Per-project `.guard.toml` overrides the user-level file (table-by-table merge).
"""
from __future__ import annotations

import fnmatch
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# tomllib is stdlib in Python 3.11+. On 3.10 we fall back to the
# tomli PyPI backport (declared as a conditional dependency in
# pyproject.toml). The fallback exposes the same loads / load API,
# so the rest of this file is version-agnostic.
if sys.version_info >= (3, 11):
    import tomllib  # type: ignore[import-not-found]
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib  # type: ignore[import-not-found, no-redef]


@dataclass(frozen=True)
class Role:
    """A flattened role — inheritance chain already resolved."""

    name: str
    allow_intents: tuple[str, ...] = ("*",)
    deny_intents: tuple[str, ...] = ()
    allow_files: tuple[str, ...] = ()  # empty = no path whitelist
    deny_files: tuple[str, ...] = ()
    allow_mcp_tools: tuple[str, ...] = ()  # empty = no MCP whitelist
    deny_mcp_tools: tuple[str, ...] = ()


@dataclass(frozen=True)
class GuardToml:
    default_role: str = "dev"
    roles: dict[str, Role] = field(default_factory=dict)

    def role(self, name: str) -> Role:
        """Return the named role, or a permissive fallback."""
        return self.roles.get(name) or Role(name=name)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_USER_PATH = Path.home() / ".ai-firewall" / "guard.toml"


def find_config(start: Path | None = None) -> list[Path]:
    """Return existing config paths in precedence order (most-specific last).

    Per-project `.guard.toml` (walking up from `start`) overrides the user
    file. We return both so the loader can merge them.
    """
    found: list[Path] = []
    if _USER_PATH.exists():
        found.append(_USER_PATH)

    cwd = (start or Path.cwd()).resolve()
    while True:
        candidate = cwd / ".guard.toml"
        if candidate.exists():
            found.append(candidate)
            break
        if cwd.parent == cwd:
            break
        cwd = cwd.parent
    return found


def load(paths: list[Path] | None = None) -> GuardToml:
    """Load and merge one or more guard.toml files."""
    if paths is None:
        paths = find_config()
    if not paths:
        return GuardToml()

    merged: dict = {"identity": {}, "roles": {}}
    for path in paths:
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            continue
        if "identity" in data and isinstance(data["identity"], dict):
            merged["identity"].update(data["identity"])
        for rname, rdata in (data.get("roles") or {}).items():
            if not isinstance(rdata, dict):
                continue
            merged["roles"].setdefault(rname, {}).update(rdata)

    default_role = merged["identity"].get("default_role", "dev")
    raw_roles = merged["roles"]
    resolved: dict[str, Role] = {}
    for rname in raw_roles:
        resolved[rname] = _resolve_role(rname, raw_roles, seen=set())
    return GuardToml(default_role=default_role, roles=resolved)


def _resolve_role(name: str, raw: dict, *, seen: set[str]) -> Role:
    """Walk the `inherits` chain and merge fields. Cycles short-circuit."""
    if name in seen:
        return Role(name=name)
    seen = seen | {name}

    spec = raw.get(name) or {}
    parent_name = spec.get("inherits")
    if parent_name and parent_name in raw:
        parent = _resolve_role(parent_name, raw, seen=seen)
    else:
        parent = Role(name=name)

    def _list(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
        if key in spec:
            v = spec[key]
            if isinstance(v, list):
                return tuple(str(x) for x in v)
            if isinstance(v, str):
                return (v,)
            return default
        return default

    return Role(
        name=name,
        allow_intents=_list("allow_intents", parent.allow_intents),
        deny_intents=_list("deny_intents", parent.deny_intents),
        allow_files=_list("allow_files", parent.allow_files),
        deny_files=_list("deny_files", parent.deny_files),
        allow_mcp_tools=_list("allow_mcp_tools", parent.allow_mcp_tools),
        deny_mcp_tools=_list("deny_mcp_tools", parent.deny_mcp_tools),
    )


# ---------------------------------------------------------------------------
# Glob matcher with `**` recursive support
# ---------------------------------------------------------------------------

def glob_match(path: str, pattern: str) -> bool:
    """Match `path` against `pattern` with `**` (zero or more components)."""
    if not path or not pattern:
        return False
    path_n = _normalize(path)
    pat_n = _normalize(pattern)
    return _match_parts(path_n.split("/"), pat_n.split("/"))


def _normalize(p: str) -> str:
    p = os.path.expanduser(p)
    p = p.replace("\\", "/")
    # Strip leading "./"
    while p.startswith("./"):
        p = p[2:]
    return p


def _match_parts(haystack: list[str], pattern: list[str]) -> bool:
    if not pattern:
        return not haystack
    head, *rest = pattern
    if head == "**":
        if not rest:
            return True
        for i in range(len(haystack) + 1):
            if _match_parts(haystack[i:], rest):
                return True
        return False
    if not haystack:
        return False
    if fnmatch.fnmatchcase(haystack[0], head):
        return _match_parts(haystack[1:], rest)
    return False
