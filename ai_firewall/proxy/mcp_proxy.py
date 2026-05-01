"""MCP stdio proxy — sits between an AI host and an upstream MCP server.

Spawned as a subprocess by `guard mcp-proxy --upstream-cmd <cmd> [--upstream-arg X ...]`.
Reads line-delimited JSON-RPC from stdin (the host), forwards to the upstream
server's stdin, and forwards the server's stdout back to the host. For
`tools/call` requests, runs the proposed action through Guard.evaluate first
and refuses with a JSON-RPC error if policy says BLOCK or REQUIRE_APPROVAL
(safe default for auto-mode AI tools).

The proxy is fully stdio-transparent for non-tool-call traffic (initialize,
tools/list, ping, notifications, etc.) — it doesn't parse or rewrite those.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable

from ai_firewall.core.action import Action
from ai_firewall.core.guard import Guard


# ---------------------------------------------------------------------------
# Action mapping — heuristically map an MCP tool call to a firewall Action
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]


def map_to_action(call: ToolCall) -> Action | None:
    """Best-effort: look at the tool name + arg shape and produce an Action.

    Returns None when we can't map confidently — caller passes through.
    """
    name = (call.name or "").lower()
    args = call.arguments or {}

    # Shell-ish: any of the common arg names that hold a command string.
    for arg_key in ("command", "cmd", "shellCommand", "script"):
        cmd = args.get(arg_key)
        if isinstance(cmd, str) and cmd.strip():
            return Action.shell(cmd)

    # File-ish: write/edit/create style tools.
    path = args.get("file_path") or args.get("path") or args.get("filePath")
    if isinstance(path, str) and path:
        op = "delete" if "delete" in name else (
            "read" if "read" in name else "write"
        )
        content = (
            args.get("content")
            or args.get("text")
            or args.get("new_string")
            or args.get("newText")
            or ""
        )
        return Action.file(op, path, content=content if isinstance(content, str) else None)

    # SQL-ish
    sql = args.get("sql") or args.get("query")
    if isinstance(sql, str) and sql.strip() and ("sql" in name or "query" in name or "database" in name):
        dialect = str(args.get("dialect") or "generic")
        return Action.db(sql, dialect=dialect)

    # HTTP-ish
    url = args.get("url")
    if isinstance(url, str) and url.startswith(("http://", "https://", "file://")):
        method = (args.get("method") or "GET").upper()
        body = args.get("body") or args.get("data")
        return Action.api(method, url, body=body if isinstance(body, str) else None)

    return None


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _is_tool_call(msg: dict) -> bool:
    return msg.get("method") == "tools/call" and isinstance(msg.get("params"), dict)


def _build_block_response(request_id: Any, reason: str) -> dict:
    """Return a `tools/call` response that surfaces the block as the tool's content.

    We use an error-shaped result rather than a JSON-RPC `error` field so the
    AI sees it as the tool's output and can react gracefully (apologize, try
    a different approach) instead of crashing on a transport error.
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": f"AI Execution Firewall blocked this tool call.\n\nReason: {reason}",
                }
            ],
            "isError": True,
        },
    }


# ---------------------------------------------------------------------------
# Inspect a single message; return either a passthrough or a synthetic response
# ---------------------------------------------------------------------------

def inspect_request(
    msg: dict, *, guard: Guard, approval_mode: str = "block"
) -> tuple[str, dict | None]:
    """Decide what to do with a JSON-RPC message from the host.

    Returns (action, payload):
      ("forward", None)         pass the message to upstream as-is
      ("block", response_msg)   send response_msg back to host, do NOT forward
    """
    if not _is_tool_call(msg):
        return ("forward", None)

    params = msg.get("params") or {}
    name = str(params.get("name") or "")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return ("forward", None)

    action = map_to_action(ToolCall(name=name, arguments=arguments))
    if action is None:
        return ("forward", None)  # unrecognized shape; let upstream handle it

    try:
        decision = guard.evaluate(action)
    except Exception:
        # Never let firewall errors block tool calls — fail open.
        return ("forward", None)

    if decision.decision == "BLOCK":
        return ("block", _build_block_response(msg.get("id"), decision.reason))

    if decision.decision == "REQUIRE_APPROVAL" and approval_mode != "approve":
        return ("block", _build_block_response(
            msg.get("id"),
            f"REQUIRE_APPROVAL ({decision.risk.name}): {decision.reason}",
        ))

    return ("forward", None)


# ---------------------------------------------------------------------------
# stdio pump — runs the upstream subprocess and forwards bidirectionally
# ---------------------------------------------------------------------------

def run_proxy(
    upstream_cmd: str,
    upstream_args: list[str],
    *,
    guard: Guard | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    approval_mode: str = "block",
) -> int:
    """Launch upstream and shuttle JSON-RPC between host and it.

    Args:
        upstream_cmd / upstream_args: the original MCP server we wrap.
        guard: a Guard instance to evaluate tool calls against. If None,
               a default Guard is constructed (uses default rules + memory).
        approval_mode: "block" (default) or "approve".

    Blocks until either the host or the upstream closes its stdout. Returns
    the upstream's exit code.
    """
    host_in = stdin or sys.stdin.buffer
    host_out = stdout or sys.stdout.buffer
    host_err = stderr or sys.stderr.buffer

    if guard is None:
        guard = Guard()

    proc = subprocess.Popen(
        [upstream_cmd, *upstream_args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        env=os.environ.copy(),
    )

    # Lock for serialized writes to host_out (both pumps may send to host).
    out_lock = threading.Lock()

    def _write_host(line: bytes) -> None:
        with out_lock:
            try:
                host_out.write(line)
                host_out.flush()
            except BrokenPipeError:
                pass

    def _pump_host_to_upstream() -> None:
        """Read host stdin → optionally inspect → forward to upstream stdin."""
        try:
            for raw in host_in:
                if not raw:
                    break
                # Don't lose binary content — only attempt JSON parse on UTF-8 lines.
                try:
                    text = raw.decode("utf-8")
                    msg = json.loads(text)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # Not JSON — forward verbatim (could be initialize handshake bytes)
                    _safe_write(proc.stdin, raw)
                    continue

                action, response = inspect_request(msg, guard=guard, approval_mode=approval_mode)
                if action == "block" and response is not None:
                    _write_host(json.dumps(response).encode("utf-8") + b"\n")
                    continue
                _safe_write(proc.stdin, raw if raw.endswith(b"\n") else raw + b"\n")
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass

    def _pump_upstream_to_host() -> None:
        """Read upstream stdout → forward to host stdout."""
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                if not raw:
                    break
                _write_host(raw)
        except Exception:
            pass

    def _pump_upstream_stderr() -> None:
        """Forward upstream stderr to our stderr so the user sees server logs."""
        try:
            assert proc.stderr is not None
            for raw in proc.stderr:
                if not raw:
                    break
                try:
                    host_err.write(raw)
                    host_err.flush()
                except BrokenPipeError:
                    pass
        except Exception:
            pass

    t1 = threading.Thread(target=_pump_host_to_upstream, daemon=True)
    t2 = threading.Thread(target=_pump_upstream_to_host, daemon=True)
    t3 = threading.Thread(target=_pump_upstream_stderr, daemon=True)
    t1.start()
    t2.start()
    t3.start()

    rc = proc.wait()
    # Drain any remaining stdout/stderr
    t2.join(timeout=2)
    t3.join(timeout=2)
    return rc


def _safe_write(stream, data: bytes) -> None:
    if stream is None:
        return
    try:
        stream.write(data)
        stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass


# ---------------------------------------------------------------------------
# CLI entry point — `guard mcp-proxy ...`
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Parse our own args (--upstream-cmd, --upstream-arg, --firewall-wrapped) and run."""
    import argparse

    parser = argparse.ArgumentParser(prog="guard mcp-proxy", add_help=True)
    parser.add_argument("--upstream-cmd", required=True, help="Command of the upstream MCP server.")
    parser.add_argument("--upstream-arg", action="append", default=[], help="Argument for the upstream (repeatable).")
    parser.add_argument("--firewall-wrapped", action="store_true", help="Marker; harmless to leave in.")
    parser.add_argument(
        "--approval",
        choices=["block", "approve"],
        default=os.environ.get("AI_FIREWALL_PROXY_APPROVAL", "block"),
        help="Behaviour on REQUIRE_APPROVAL (default: block, safest in auto-mode).",
    )
    args = parser.parse_args(argv)
    return run_proxy(
        upstream_cmd=args.upstream_cmd,
        upstream_args=list(args.upstream_arg),
        approval_mode=args.approval,
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
