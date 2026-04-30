from __future__ import annotations

import subprocess

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


class ShellAdapter(ExecutionAdapter):
    """Runs shell commands via subprocess.

    Uses shell=True so chained commands and redirects work as the user expects.
    Approved actions only ever reach here — the firewall has already gated them.
    """

    def run(self, action: Action) -> ExecutionResult:
        cmd = action.payload.get("cmd") or ""
        cwd = action.context.get("cwd")
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
        )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            executed=True,
        )
