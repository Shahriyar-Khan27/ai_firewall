from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any


class IntentType(StrEnum):
    FILE_DELETE = "FILE_DELETE"
    FILE_WRITE = "FILE_WRITE"
    FILE_READ = "FILE_READ"
    SHELL_EXEC = "SHELL_EXEC"
    CODE_MODIFY = "CODE_MODIFY"
    DB_READ = "DB_READ"
    DB_WRITE = "DB_WRITE"
    DB_DESTRUCTIVE = "DB_DESTRUCTIVE"
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
    def db(sql: str, *, dialect: str = "generic") -> "Action":
        return Action(
            type="db",
            payload={"sql": sql, "dialect": dialect},
            context={"cwd": os.getcwd()},
        )
