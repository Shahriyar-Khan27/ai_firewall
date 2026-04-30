from __future__ import annotations

import shutil
from pathlib import Path

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


class FileAdapter(ExecutionAdapter):
    """Performs filesystem operations through pathlib."""

    def run(self, action: Action) -> ExecutionResult:
        op = (action.payload.get("op") or "").lower()
        raw_path = action.payload.get("path")
        if not raw_path:
            return ExecutionResult(exit_code=2, stderr="missing 'path'", executed=False)

        cwd = Path(action.context.get("cwd") or Path.cwd())
        path = Path(raw_path)
        if not path.is_absolute():
            path = cwd / path

        if op == "delete":
            return self._delete(path)
        if op in {"write", "create"}:
            return self._write(path, action.payload.get("content") or "", append=False)
        if op == "append":
            return self._write(path, action.payload.get("content") or "", append=True)
        if op == "read":
            return self._read(path)
        return ExecutionResult(exit_code=2, stderr=f"unknown op '{op}'", executed=False)

    @staticmethod
    def _delete(path: Path) -> ExecutionResult:
        if not path.exists():
            return ExecutionResult(exit_code=1, stderr=f"not found: {path}", executed=False)
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return ExecutionResult(exit_code=0, stdout=f"deleted {path}\n")

    @staticmethod
    def _write(path: Path, content: str, *, append: bool) -> ExecutionResult:
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with path.open(mode, encoding="utf-8") as fh:
            fh.write(content)
        return ExecutionResult(exit_code=0, stdout=f"wrote {len(content)} bytes to {path}\n")

    @staticmethod
    def _read(path: Path) -> ExecutionResult:
        if not path.exists() or not path.is_file():
            return ExecutionResult(exit_code=1, stderr=f"not a file: {path}", executed=False)
        return ExecutionResult(exit_code=0, stdout=path.read_text(encoding="utf-8"))
