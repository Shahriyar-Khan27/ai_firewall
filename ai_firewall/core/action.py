from __future__ import annotations

import os
import sys
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

# StrEnum landed in Python 3.11 stdlib. On 3.10 we polyfill with the
# documented (str, Enum) pattern, which is exactly what 3.11's
# StrEnum is internally. Both produce instances that compare equal
# to their str value (e.g. IntentType.FILE_DELETE == "FILE_DELETE").
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:  # pragma: no cover - exercised only on 3.10
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of enum.StrEnum (Python 3.11+)."""

        def __str__(self) -> str:
            return self.value


class IntentType(StrEnum):
    FILE_DELETE = "FILE_DELETE"
    FILE_WRITE = "FILE_WRITE"
    FILE_READ = "FILE_READ"
    SHELL_EXEC = "SHELL_EXEC"
    CODE_MODIFY = "CODE_MODIFY"
    DB_READ = "DB_READ"
    DB_WRITE = "DB_WRITE"
    DB_DESTRUCTIVE = "DB_DESTRUCTIVE"
    API_READ = "API_READ"
    API_WRITE = "API_WRITE"
    API_DESTRUCTIVE = "API_DESTRUCTIVE"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    UNKNOWN = "UNKNOWN"


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "RiskLevel") -> "RiskLevel":
        if isinstance(value, RiskLevel):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]


@dataclass(frozen=True)
class Action:
    """A single operation an AI agent wants to perform."""

    type: str  # adapter family: "shell" | "file"
    payload: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @staticmethod
    def shell(cmd: str, *, cwd: str | None = None) -> "Action":
        return Action(
            type="shell",
            payload={"cmd": cmd},
            context={"cwd": cwd or os.getcwd()},
        )

    @staticmethod
    def file(op: str, path: str, *, content: str | None = None) -> "Action":
        payload: dict[str, Any] = {"op": op, "path": path}
        if content is not None:
            payload["content"] = content
        return Action(type="file", payload=payload, context={"cwd": os.getcwd()})

    @staticmethod
    def db(sql: str, *, dialect: str = "generic", connection: str | None = None) -> "Action":
        ctx: dict[str, Any] = {"cwd": os.getcwd()}
        if connection:
            ctx["connection"] = connection
        return Action(
            type="db",
            payload={"sql": sql, "dialect": dialect},
            context=ctx,
        )

    @staticmethod
    def api(
        method: str,
        url: str,
        *,
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> "Action":
        payload: dict[str, Any] = {"method": (method or "GET").upper(), "url": url}
        if body is not None:
            payload["body"] = body
        if headers:
            payload["headers"] = dict(headers)
        return Action(type="api", payload=payload, context={"cwd": os.getcwd()})
