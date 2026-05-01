"""Detect MCP server configurations in known host config locations.

Surfaces unwrapped MCP servers (i.e. ones that don't already route through
`guard mcp-proxy`) so the user can opt into firewall protection. The
`install`/`uninstall` helpers here also rewrite a host's mcp.json to insert
or remove the wrapper.

Supported hosts:
  - Claude Code  (~/.claude/mcp.json, .mcp.json in repo)
  - Cursor       (~/.cursor/mcp.json, .cursor/mcp.json in repo)
  - Continue.dev (~/.continue/config.json — `mcpServers` key)
  - Zed          (per-workspace settings)
  - Generic .mcp.json in any project
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Identifier we use in the wrapped command's args — lets us recognize an
# already-wrapped server on subsequent scans.
WRAPPER_MARKER = "--firewall-wrapped"


@dataclass(frozen=True)
class MCPServerEntry:
    host: str                                   # "claude-code" / "cursor" / "continue" / "zed" / "generic"
    config_path: Path                           # the file that declared this entry
    name: str                                   # the key under "mcpServers"
    command: str                                # current command (may be `guard` if already wrapped)
    args: tuple[str, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    wrapped: bool = False                       # True if currently wrapped by us
    upstream_command: str | None = None         # the original cmd if wrapped
    upstream_args: tuple[str, ...] = ()         # original args if wrapped


def known_config_paths() -> list[tuple[str, Path]]:
    """Default global/per-user config file paths we know how to read."""
    home = Path.home()
    out: list[tuple[str, Path]] = []
    out.append(("claude-code", home / ".claude" / "mcp.json"))
    out.append(("cursor", home / ".cursor" / "mcp.json"))
    out.append(("continue", home / ".continue" / "config.json"))
    appdata = os.environ.get("APPDATA")
    if appdata:
        # Windows-specific Cursor path (sometimes here)
        out.append(("cursor", Path(appdata) / "Cursor" / "User" / "globalStorage" / "mcp.json"))
    return out


def discover_workspace_paths(workspace: Path | None) -> list[tuple[str, Path]]:
    """Per-project config paths to scan for a given workspace folder."""
    if workspace is None:
        return []
    ws = Path(workspace)
    return [
        ("generic", ws / ".mcp.json"),
        ("claude-code", ws / ".mcp.json"),  # also Claude Code project-level
        ("cursor", ws / ".cursor" / "mcp.json"),
        ("continue", ws / ".continue" / "config.json"),
    ]


def scan(extra_paths: Iterable[tuple[str, Path]] | None = None) -> list[MCPServerEntry]:
    """Read every reachable host config and return the union of MCP servers."""
    paths: list[tuple[str, Path]] = list(known_config_paths())
    if extra_paths:
        paths.extend(extra_paths)

    out: list[MCPServerEntry] = []
    seen_names: set[tuple[str, str]] = set()  # (host, name) — dedupe across global + repo
    for host, p in paths:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        servers = _extract_servers(host, data)
        for name, spec in servers.items():
            key = (host, name)
            if key in seen_names:
                continue
            seen_names.add(key)
            out.append(_to_entry(host, p, name, spec))
    return out


def _extract_servers(host: str, data: dict) -> dict:
    """Pull the mcpServers map out of a host config (the shape varies)."""
    if not isinstance(data, dict):
        return {}
    # Most hosts: top-level `mcpServers`
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    # Continue: nested under various keys; also accept top-level `mcp`
    nested = data.get("mcp")
    if isinstance(nested, dict):
        s = nested.get("servers")
        if isinstance(s, dict):
            return s
    return {}


def _to_entry(host: str, path: Path, name: str, spec: dict) -> MCPServerEntry:
    cmd = spec.get("command", "")
    args = tuple(spec.get("args") or [])
    env = dict(spec.get("env") or {})
    wrapped = bool(args) and (WRAPPER_MARKER in args or (cmd == "guard" and "mcp-proxy" in args))
    upstream_cmd: str | None = None
    upstream_args: tuple[str, ...] = ()
    if wrapped:
        upstream_cmd, upstream_args = _extract_upstream(args)
    return MCPServerEntry(
        host=host,
        config_path=path,
        name=name,
        command=cmd,
        args=args,
        env=env,
        wrapped=wrapped,
        upstream_command=upstream_cmd,
        upstream_args=upstream_args,
    )


def _extract_upstream(args: tuple[str, ...]) -> tuple[str | None, tuple[str, ...]]:
    """Pull the original command/args back out of a wrapper's args list."""
    args_list = list(args)
    upstream_cmd: str | None = None
    upstream_args: list[str] = []
    i = 0
    while i < len(args_list):
        a = args_list[i]
        if a == "--upstream-cmd" and i + 1 < len(args_list):
            upstream_cmd = args_list[i + 1]
            i += 2
        elif a == "--upstream-arg" and i + 1 < len(args_list):
            upstream_args.append(args_list[i + 1])
            i += 2
        else:
            i += 1
    return upstream_cmd, tuple(upstream_args)


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

def install(entry: MCPServerEntry, *, guard_cmd: str = "guard") -> dict:
    """Return the wrapped-server spec that should replace the original.

    Caller is responsible for writing it back to disk; this function does
    not mutate the file directly.
    """
    if entry.wrapped:
        return {"command": entry.command, "args": list(entry.args), "env": entry.env}

    new_args = [
        "mcp-proxy",
        WRAPPER_MARKER,
        "--upstream-cmd",
        entry.command,
    ]
    for a in entry.args:
        new_args.append("--upstream-arg")
        new_args.append(a)
    spec = {"command": guard_cmd, "args": new_args}
    if entry.env:
        spec["env"] = dict(entry.env)
    return spec


def uninstall(entry: MCPServerEntry) -> dict | None:
    """Return the original (unwrapped) server spec, or None if unwrapping fails."""
    if not entry.wrapped or not entry.upstream_command:
        return None
    spec = {"command": entry.upstream_command, "args": list(entry.upstream_args)}
    if entry.env:
        spec["env"] = dict(entry.env)
    return spec


def write_servers(path: Path, servers: dict) -> None:
    """Atomically write the `mcpServers` block back to a host config file.

    Preserves any sibling top-level keys in the file (e.g. Continue's other
    settings).
    """
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, dict):
                existing = {}
        except (OSError, json.JSONDecodeError):
            existing = {}
    else:
        existing = {}
        path.parent.mkdir(parents=True, exist_ok=True)

    existing["mcpServers"] = servers
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    tmp.replace(path)
