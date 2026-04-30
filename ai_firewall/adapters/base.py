from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ai_firewall.core.action import Action


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    executed: bool = True
    note: str = ""


class ExecutionAdapter(ABC):
    @abstractmethod
    def run(self, action: Action) -> ExecutionResult: ...
