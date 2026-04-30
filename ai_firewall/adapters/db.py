from __future__ import annotations

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


class DBAnalyzeAdapter(ExecutionAdapter):
    """Analyze-only DB adapter.

    The firewall does not hold any DB connection or execute the query — it just
    confirms the action passed policy, with a clear `executed=False` audit row.
    Callers/agents are expected to run the actual SQL via their own client.

    The hook for a future `DBExecuteAdapter` (Phase 3.5) is the same `run` signature.
    """

    def run(self, action: Action) -> ExecutionResult:
        sql = (action.payload.get("sql") or "").strip()
        first_chars = sql[:80] + ("…" if len(sql) > 80 else "")
        return ExecutionResult(
            exit_code=0,
            stdout=f"[firewall] approved (analyze-only): {first_chars}\n",
            stderr="",
            executed=False,
            note="analyze-only mode; firewall did not execute the query",
        )
