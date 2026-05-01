"""
MCP server for the AI Execution Firewall.

Exposes the firewall as an MCP server so MCP-capable AI tools (Claude Code,
Cursor, Continue.dev, Zed, Cline, ...) can route their actions through it
instead of using their own built-in shell/file tools. When configured, every
shell command, file write, SQL query, or HTTP request the AI tries first
goes through the firewall's policy pipeline. Anything BLOCK'd or pending
approval never executes — even in auto-mode.

Run with: `guard mcp` (stdio transport, the default for MCP).

Add to your MCP host config, e.g. for Claude Code (.claude/mcp.json):

    {
      "mcpServers": {
        "ai-firewall": {
          "command": "guard",
          "args": ["mcp"]
        }
      }
    }

Tool semantics:

* `firewall_run_shell(command)`        — evaluates + (if allowed) runs.
* `firewall_evaluate_shell(command)`   — evaluates only, returns Decision JSON.
* `firewall_run_sql(query, dialect, connection?)` — evaluates SQL.
                                          With `connection`, executes via
                                          SQLiteExecuteAdapter; otherwise
                                          analyze-only.
* `firewall_run_api(method, url, body?, headers?, execute?)` — evaluates HTTP.
* `firewall_run_file(op, path, content?)` — gates writes/deletes.

REQUIRE_APPROVAL handling:
    Default in MCP context is to BLOCK (return executed=False with the
    Decision attached) so auto-mode AI tools don't accidentally execute
    anything risky. The user can examine the Decision and re-issue the
    command via the firewall CLI if they want it to proceed.
"""
from __future__ import annotations

import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from ai_firewall.adapters.api_execute import HTTPExecuteAdapter
from ai_firewall.adapters.db_execute import SQLiteExecuteAdapter
from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard


_mcp = FastMCP("ai-execution-firewall")


def _make_guard(approval: str = "block") -> Guard:
    """Return a Guard with REQUIRE_APPROVAL pre-resolved.

    `approval` is one of:
      "block"   → REQUIRE_APPROVAL is rejected (auto-deny). Default and safest.
      "approve" → REQUIRE_APPROVAL is auto-approved. Use only with trust.

    Guard itself honours `AI_FIREWALL_AUDIT_PATH` for the default audit log,
    so callers (including tests) can redirect on-disk state via env.
    """
    fn = auto_approve if approval == "approve" else auto_deny
    return Guard(approval_fn=fn)


def _wrap_decision(decision) -> dict[str, Any]:
    return decision.to_dict()


def _execute(
    action: Action,
    *,
    approval: str = "block",
    custom_adapter_for_type: tuple[str, Any] | None = None,
) -> dict[str, Any]:
    """Run action through Guard. Return a tool-result dict (never raises)."""
    guard = _make_guard(approval=approval)
    if custom_adapter_for_type is not None:
        type_, adapter = custom_adapter_for_type
        guard.adapters[type_] = adapter

    decision = guard.evaluate(action)
    if decision.decision == "BLOCK":
        return {
            "executed": False,
            "blocked": True,
            "decision": _wrap_decision(decision),
            "reason": decision.reason,
        }

    if decision.decision == "REQUIRE_APPROVAL" and approval != "approve":
        return {
            "executed": False,
            "blocked": True,
            "decision": _wrap_decision(decision),
            "reason": (
                f"REQUIRE_APPROVAL ({decision.risk.name}): {decision.reason}. "
                f"Re-issue manually via `guard run/sql/api ...` to approve."
            ),
        }

    try:
        result = guard.execute(action)
    except Blocked as exc:
        return {
            "executed": False,
            "blocked": True,
            "decision": _wrap_decision(exc.decision),
            "reason": exc.decision.reason,
        }

    return {
        "executed": result.execution.executed,
        "blocked": False,
        "decision": _wrap_decision(result.decision),
        "exit_code": result.execution.exit_code,
        "stdout": result.execution.stdout,
        "stderr": result.execution.stderr,
        "note": result.execution.note,
    }


# ----- Shell -----

@_mcp.tool()
def firewall_run_shell(command: str, approval: str = "block") -> dict[str, Any]:
    """Evaluate a shell command through the firewall and run it if allowed.

    Args:
        command: The shell command to run (e.g. ``echo hello``).
        approval: ``"block"`` (default — REQUIRE_APPROVAL is rejected) or
                  ``"approve"`` (REQUIRE_APPROVAL auto-accepted; use only when
                  the host already has its own approval UI).

    Returns a dict with ``executed``, ``blocked``, ``decision`` (the firewall's
    Decision JSON), and either ``stdout``/``stderr``/``exit_code`` (if
    executed) or ``reason`` (if blocked).
    """
    return _execute(Action.shell(command), approval=approval)


@_mcp.tool()
def firewall_evaluate_shell(command: str) -> dict[str, Any]:
    """Evaluate a shell command without executing it. Returns the Decision JSON."""
    guard = _make_guard()
    decision = guard.evaluate(Action.shell(command))
    return _wrap_decision(decision)


# ----- File -----

@_mcp.tool()
def firewall_run_file(
    op: str,
    path: str,
    content: str | None = None,
    approval: str = "block",
) -> dict[str, Any]:
    """Evaluate a filesystem operation and run it if allowed.

    Args:
        op: One of ``"write"``, ``"create"``, ``"append"``, ``"delete"``, ``"read"``.
        path: Target file path.
        content: Required for write/create/append.
        approval: Same semantics as :func:`firewall_run_shell`.
    """
    action = Action.file(op, path, content=content)
    return _execute(action, approval=approval)


# ----- SQL -----

@_mcp.tool()
def firewall_run_sql(
    query: str,
    dialect: str = "generic",
    connection: str | None = None,
    approval: str = "block",
) -> dict[str, Any]:
    """Evaluate a SQL query and (if allowed and ``connection`` is given) run it.

    Args:
        query: The SQL statement(s) to evaluate.
        dialect: sqlglot dialect, e.g. ``"sqlite"``, ``"postgres"``, ``"mysql"``.
                 Default ``"generic"``.
        connection: SQLite connection spec (path or ``sqlite:///path``). When
                    set, an opt-in execute adapter runs the query against it.
                    When omitted, the action is analyze-only — the firewall
                    returns the Decision without touching any DB.
        approval: Same semantics as :func:`firewall_run_shell`.
    """
    action = Action.db(query, dialect=dialect, connection=connection)
    custom: tuple[str, Any] | None = None
    if connection:
        custom = ("db", SQLiteExecuteAdapter(connection))
    return _execute(action, approval=approval, custom_adapter_for_type=custom)


# ----- API -----

@_mcp.tool()
def firewall_run_api(
    method: str,
    url: str,
    body: str | None = None,
    headers: dict[str, str] | None = None,
    execute: bool = False,
    approval: str = "block",
) -> dict[str, Any]:
    """Evaluate an HTTP request and (if ``execute=True`` and allowed) issue it.

    Args:
        method: ``GET``, ``POST``, ``PUT``, ``PATCH``, ``DELETE``, etc.
        url: Target URL.
        body: Optional request body. Scanned for leaked secrets.
        headers: Optional request headers. ``Authorization`` /
                 ``X-Api-Key`` / ``X-Auth-Token`` are scanned for leaks.
        execute: When True, issue the request via stdlib ``urllib`` if allowed.
                 When False (default), analyze-only — the firewall never makes
                 the request.
        approval: Same semantics as :func:`firewall_run_shell`.
    """
    action = Action.api(method, url, body=body, headers=headers)
    custom: tuple[str, Any] | None = None
    if execute:
        custom = ("api", HTTPExecuteAdapter())
    return _execute(action, approval=approval, custom_adapter_for_type=custom)


# ----- Policy introspection -----

@_mcp.tool()
def firewall_show_policy() -> str:
    """Return the effective policy YAML the firewall is using."""
    import yaml
    guard = _make_guard()
    return yaml.safe_dump(guard.policy.rules, sort_keys=False)


def main() -> None:
    """Run the MCP server over stdio. Invoked via `guard mcp`."""
    _mcp.run()


if __name__ == "__main__":
    main()
