"""Bridge a `(Action, Decision) -> bool` approval into the VS Code extension.

When the user has installed our VS Code extension AND opted in to auto-wire,
the extension binds an HTTP server on `127.0.0.1:<random>` and writes the
port + a shared secret into `~/.ai-firewall/extension.port`. The Python
side (Claude Code hook, MCP proxy, plain `guard run` from a terminal that
happens to be inside an active editor session) discovers that file and
POSTs the Decision payload there. The user gets a webview popup with
Accept / Reject; the response flows back as the function's return.

Design choices:

* Loopback-only (we bind 127.0.0.1, never 0.0.0.0). The port file lives
  under `~/.ai-firewall/` with a 16-byte hex token the request must carry
  in `X-Firewall-Token`. Tampering = 401 = fall-through to safe fallback.
* Synchronous: the hook subprocess blocks for `timeout_s` seconds (default
  30s). On timeout we behave as the configured `fallback_fn` says
  (typically `auto_deny`), so a crashed or absent extension never hangs
  Claude Code or makes things less safe than today.
* No new top-level deps. Uses `urllib.request` from the stdlib.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ai_firewall.approval.cli_prompt import ApprovalFn, auto_deny
from ai_firewall.core.action import Action
from ai_firewall.engine.decision import Decision


_DEFAULT_PORT_FILE = Path.home() / ".ai-firewall" / "extension.port"


@dataclass(frozen=True)
class _BridgeTarget:
    url: str          # e.g. "http://127.0.0.1:53219/approve"
    token: str        # X-Firewall-Token value the extension expects
    pid: int | None   # extension's PID, used only for diagnostics


def discover_target(port_file: Path | None = None) -> _BridgeTarget | None:
    """Read the port file the extension wrote and parse it.

    Returns None when the file is missing, malformed, or stale (refers to
    a host:port that no longer accepts connections — that check happens
    when we actually try to POST). Never raises.
    """
    path = Path(port_file) if port_file is not None else _DEFAULT_PORT_FILE
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    host = data.get("host") or "127.0.0.1"
    port = data.get("port")
    token = data.get("token") or ""
    if not isinstance(port, int) or not isinstance(token, str) or not token:
        return None
    pid = data.get("pid")
    pid = pid if isinstance(pid, int) else None
    return _BridgeTarget(
        url=f"http://{host}:{int(port)}/approve",
        token=token,
        pid=pid,
    )


def make_extension_approval(
    *,
    fallback_fn: ApprovalFn = auto_deny,
    timeout_s: float = 30.0,
    port_file: Path | None = None,
) -> ApprovalFn:
    """Build an `ApprovalFn` that defers to the VS Code extension.

    If no extension is reachable (port file missing, server down, request
    times out, etc.) it delegates to `fallback_fn` — which defaults to
    `auto_deny` so this never makes a hook *less* safe than it is today.
    """

    def approve(action: Action, decision: Decision) -> bool:
        target = discover_target(port_file)
        if target is None:
            return fallback_fn(action, decision)

        body = {
            "action_id": action.id,
            "action": {
                "type": action.type,
                "payload": _redact_payload(action.payload),
                "context": dict(action.context or {}),
            },
            "decision": decision.to_dict(),
        }
        try:
            req = urllib.request.Request(
                target.url,
                data=json.dumps(body).encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Firewall-Token": target.token,
                },
            )
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if resp.status != 200:
                    return fallback_fn(action, decision)
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            return fallback_fn(action, decision)

        verdict = (payload.get("decision") or "").lower()
        return verdict in {"approve", "approved", "allow", "yes"}

    return approve


def _redact_payload(payload: dict) -> dict:
    """Pass through everything except clearly secret fields.

    Today this is just a shallow copy with bytes/`body` kept as-is — the
    extension webview already masks secrets via the shared `code_findings`
    flow. We strip nothing; the loopback boundary is the secret-containment
    perimeter, and the user is the one looking at the webview.
    """
    return dict(payload or {})
