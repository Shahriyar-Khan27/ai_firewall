"""End-to-end tests for the Claude Code PreToolUse hook script.

Spawns the hook as a subprocess (just like Claude Code does), feeds it the
tool-call JSON Claude Code would send, and checks the exit code + stderr.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "scripts" / "claude-code-pretooluse.py"


def _run_hook(payload: dict, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, **(env or {})},
        timeout=15,
    )


def test_hook_allows_safe_shell_command():
    proc = _run_hook({"tool_name": "Bash", "tool_input": {"command": "echo hello"}})
    assert proc.returncode == 0


def test_hook_blocks_rm_rf_root():
    proc = _run_hook({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    assert proc.returncode == 2
    body = json.loads(proc.stderr.strip())
    assert body["decision"] == "block"
    assert "BLOCKED" in body["reason"]
    assert body["firewall"]["risk"] == "CRITICAL"


def test_hook_blocks_require_approval_by_default():
    proc = _run_hook({"tool_name": "Bash", "tool_input": {"command": "rm tmp.txt"}})
    assert proc.returncode == 2
    body = json.loads(proc.stderr.strip())
    assert "requires approval" in body["reason"]


def test_hook_allows_require_approval_when_env_set():
    proc = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "rm tmp.txt"}},
        env={"AI_FIREWALL_HOOK_APPROVAL": "allow"},
    )
    assert proc.returncode == 0


def test_hook_prompt_mode_falls_back_to_block_when_no_extension():
    """`AI_FIREWALL_HOOK_APPROVAL=prompt` with no port file → safe-default BLOCK.

    The extension might be uninstalled or not yet activated; the hook must
    not hang or accidentally allow risky actions.
    """
    proc = _run_hook(
        {"tool_name": "Bash", "tool_input": {"command": "rm tmp.txt"}},
        env={"AI_FIREWALL_HOOK_APPROVAL": "prompt"},
    )
    assert proc.returncode == 2
    body = json.loads(proc.stderr.strip())
    assert "requires approval" in body["reason"]


def test_hook_passes_through_unknown_tool():
    proc = _run_hook({"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}})
    assert proc.returncode == 0


def test_hook_blocks_dangerous_write():
    proc = _run_hook({
        "tool_name": "Write",
        "tool_input": {"file_path": "/etc/passwd", "content": "root::0:0::/:/bin/sh"},
    })
    assert proc.returncode == 2
    body = json.loads(proc.stderr.strip())
    assert body["decision"] == "block"


def test_hook_handles_empty_command_gracefully():
    proc = _run_hook({"tool_name": "Bash", "tool_input": {"command": ""}})
    # Empty command → no action constructed → pass-through
    assert proc.returncode == 0


def test_hook_handles_malformed_input_gracefully():
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input="not valid json",
        capture_output=True,
        text=True,
        timeout=15,
    )
    # Fail-open: better to allow than to block-everything on bad input
    assert proc.returncode == 0


def test_hook_handles_missing_tool_input():
    proc = _run_hook({"tool_name": "Bash"})
    assert proc.returncode == 0
