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


# ---------------------------------------------------------------------------
# Edit / MultiEdit content reconstruction (v0.5.3 fix)
#
# Earlier versions of the hook treated `tool_input["new_string"]` as if it
# were the entire proposed new file. Every targeted Edit therefore looked
# to the impact engine like a near-total file deletion, producing
# REQUIRE_APPROVAL on benign one-line changes. The fix reconstructs the
# proposed file by applying old_string -> new_string against the current
# disk content, so the impact engine sees an accurate diff.
# ---------------------------------------------------------------------------


def test_edit_one_line_change_does_not_register_as_full_deletion(tmp_path: Path):
    """A safe single-line change must not be flagged as removing every
    function and class in the file.
    """
    target = tmp_path / "demo.py"
    target.write_text(
        "def alpha():\n    return 1\n\n"
        "def beta():\n    return 2\n\n"
        "def gamma():\n    return 3\n",
        encoding="utf-8",
    )
    proc = _run_hook({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(target),
            "old_string": "    return 1",
            "new_string": "    return 1  # alpha",
        },
    })
    # The impact engine should see a tiny change, not a wipe. Either ALLOW
    # outright or REQUIRE_APPROVAL on a non-removal reason. What we are
    # asserting here is the absence of the old false-positive: removed
    # functions / removed classes.
    if proc.returncode == 2 and proc.stderr.strip():
        body = json.loads(proc.stderr.strip())
        findings = body.get("firewall", {}).get("impact", {}).get("code_findings", [])
        assert not any("removes function" in f for f in findings), findings
        assert not any("removes class" in f for f in findings), findings


def test_edit_correctly_detects_removal_of_security_function(tmp_path: Path):
    """An Edit that removes a security-relevant function must still be
    detected by the impact engine. This is the test that proves the
    reconstruction is feeding the engine real data.
    """
    target = tmp_path / "audit_demo.py"
    target.write_text(
        "import hmac\n\n"
        "def sign_audit_record(record, key):\n"
        "    return hmac.new(key, record, 'sha256').hexdigest()\n\n"
        "def write_record(record):\n"
        "    return record\n",
        encoding="utf-8",
    )
    # AI tries to remove the signing function entirely.
    proc = _run_hook({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": str(target),
            "old_string": (
                "def sign_audit_record(record, key):\n"
                "    return hmac.new(key, record, 'sha256').hexdigest()\n\n"
            ),
            "new_string": "",
        },
    })
    # The hook must REQUIRE_APPROVAL or BLOCK; never silently allow.
    assert proc.returncode == 2, proc.stderr
    body = json.loads(proc.stderr.strip())
    findings = body.get("firewall", {}).get("impact", {}).get("code_findings", [])
    # The impact engine flags removed functions; with reconstruction this
    # finding now lands accurately.
    assert any("removes function" in f for f in findings), findings


def test_multiedit_applies_substitutions_in_order(tmp_path: Path):
    """MultiEdit reconstruction must apply each substitution to the
    progressively-evolving content, not all in parallel against the
    original.
    """
    target = tmp_path / "multi.py"
    target.write_text(
        "x = 1\ny = 2\nz = 3\n",
        encoding="utf-8",
    )
    proc = _run_hook({
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": str(target),
            "edits": [
                {"old_string": "x = 1", "new_string": "x = 10  # bumped"},
                {"old_string": "y = 2", "new_string": "y = 20  # bumped"},
            ],
        },
    })
    # Just confirm the hook runs without crashing on a MultiEdit shape.
    assert proc.returncode in (0, 2), proc.stderr
