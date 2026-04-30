from __future__ import annotations

import json
import time
from pathlib import Path

from ai_firewall.adapters.base import ExecutionResult
from ai_firewall.core.action import Action
from ai_firewall.engine.decision import Decision


class AuditLogger:
    """Append-only JSONL audit log. One record per evaluated action."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        action: Action,
        decision: Decision,
        result: ExecutionResult | None = None,
        *,
        approved: bool | None = None,
    ) -> None:
        record = {
            "ts": time.time(),
            "action_id": action.id,
            "type": action.type,
            "rendered": _render(action),
            "intent": decision.intent.value,
            "risk": decision.risk.name,
            "decision": decision.decision,
            "reason": decision.reason,
            "impact": decision.impact.to_dict(),
            "approved": approved,
            "executed": bool(result and result.executed),
            "exit_code": result.exit_code if result else None,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _render(action: Action) -> str:
    if action.type == "shell":
        return str(action.payload.get("cmd", ""))
    if action.type == "file":
        return f"{action.payload.get('op', '')} {action.payload.get('path', '')}".strip()
    if action.type == "db":
        return str(action.payload.get("sql", ""))
    if action.type == "api":
        return f"{action.payload.get('method', 'GET')} {action.payload.get('url', '')}".strip()
    return ""
