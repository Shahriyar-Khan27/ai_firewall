from __future__ import annotations

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


class APIAnalyzeAdapter(ExecutionAdapter):
    """Analyze-only HTTP adapter.

    The firewall does not actually issue any HTTP request — it only confirms
    the action passed policy. Callers/agents are expected to make the real
    request via their own HTTP client (requests, urllib, fetch, etc.).
    """

    def run(self, action: Action) -> ExecutionResult:
        method = action.payload.get("method", "GET")
        url = action.payload.get("url", "")
        return ExecutionResult(
            exit_code=0,
            stdout=f"[firewall] approved (analyze-only): {method} {url}\n",
            stderr="",
            executed=False,
            note="analyze-only mode; firewall did not issue the HTTP request",
        )
