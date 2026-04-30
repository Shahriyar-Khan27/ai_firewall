from __future__ import annotations

import socket
import urllib.error
import urllib.request

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


_DEFAULT_TIMEOUT_SECONDS = 15
_MAX_RESPONSE_BYTES = 4096
_MAX_HEADER_LINES = 16


class HTTPExecuteAdapter(ExecutionAdapter):
    """Real-execution HTTP adapter via stdlib urllib.

    Opt-in via `guard api … --execute`. The firewall has already passed policy
    by the time this runs; this adapter just issues the HTTP request and
    captures status + truncated headers + truncated body for the audit log.

    No new dependencies (urllib is stdlib). Methods supported: any HTTP verb.
    """

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT_SECONDS):
        self.timeout = timeout

    def run(self, action: Action) -> ExecutionResult:
        method = (action.payload.get("method") or "GET").upper()
        url = action.payload.get("url") or ""
        if not url:
            return ExecutionResult(exit_code=2, stderr="missing URL", executed=False)

        body = action.payload.get("body")
        data = body.encode("utf-8") if isinstance(body, str) and body else None
        headers = dict(action.payload.get("headers") or {})

        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                resp_headers = list(resp.headers.items())
                raw = resp.read(_MAX_RESPONSE_BYTES + 1)
                truncated = len(raw) > _MAX_RESPONSE_BYTES
                if truncated:
                    raw = raw[:_MAX_RESPONSE_BYTES]
                try:
                    text = raw.decode("utf-8", errors="replace")
                except Exception:
                    text = repr(raw)
                rendered = _render(method, url, status, resp_headers, text, truncated)
                return ExecutionResult(
                    exit_code=0 if 200 <= status < 400 else 1,
                    stdout=rendered,
                    stderr="",
                    executed=True,
                    note=f"HTTP {status}",
                )
        except urllib.error.HTTPError as e:
            # 4xx / 5xx still completed a real request — surface status + body.
            try:
                body_text = e.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            rendered = _render(method, url, e.code, list(e.headers.items() if e.headers else []), body_text, False)
            return ExecutionResult(
                exit_code=1,
                stdout=rendered,
                stderr="",
                executed=True,
                note=f"HTTP {e.code}",
            )
        except urllib.error.URLError as e:
            return ExecutionResult(
                exit_code=1,
                stderr=f"URL error: {e.reason}",
                executed=False,
            )
        except socket.timeout:
            return ExecutionResult(
                exit_code=1,
                stderr=f"timeout after {self.timeout}s",
                executed=False,
            )


def _render(
    method: str,
    url: str,
    status: int,
    headers: list[tuple[str, str]],
    body: str,
    truncated: bool,
) -> str:
    lines = [f"{method} {url} → HTTP {status}"]
    for k, v in headers[:_MAX_HEADER_LINES]:
        lines.append(f"{k}: {v}")
    if len(headers) > _MAX_HEADER_LINES:
        lines.append(f"… ({len(headers) - _MAX_HEADER_LINES} more headers)")
    lines.append("")
    lines.append(body)
    if truncated:
        lines.append("… (response body truncated)")
    return "\n".join(lines) + "\n"
