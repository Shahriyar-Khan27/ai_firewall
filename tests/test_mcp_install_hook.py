"""v0.5.0 — `guard mcp install-hook` / `uninstall-hook` and `scan --json`."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ai_firewall.cli.main import cli

runner = CliRunner()


# ---------------------------------------------------------------------------
# `guard mcp scan --json`
# ---------------------------------------------------------------------------


def test_scan_json_returns_well_formed_payload(tmp_path: Path):
    """JSON output is what the VS Code extension consumes for auto-detect.

    Even with no hosts configured (the conftest fixture neuters the user
    paths), the response shape is stable: `mcp_servers` array + a
    `claude_code_hook` object.
    """
    result = runner.invoke(cli, ["mcp", "scan", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "mcp_servers" in payload
    assert isinstance(payload["mcp_servers"], list)
    assert "claude_code_hook" in payload
    hook = payload["claude_code_hook"]
    assert "settings_path" in hook
    assert "installed" in hook


# ---------------------------------------------------------------------------
# `guard mcp install-hook`
# ---------------------------------------------------------------------------


def test_install_hook_creates_settings_when_missing(tmp_path: Path):
    settings = tmp_path / "settings.json"
    result = runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings)])
    assert result.exit_code == 0, result.output
    assert "installed" in result.output

    data = json.loads(settings.read_text(encoding="utf-8"))
    pre = data["hooks"]["PreToolUse"]
    assert len(pre) == 1
    assert pre[0]["matcher"] == "Bash|Write|Edit|MultiEdit|NotebookEdit"
    cmd = pre[0]["hooks"][0]["command"]
    assert "claude-code-pretooluse" in cmd
    env = pre[0]["hooks"][0]["env"]
    assert env["AI_FIREWALL_HOOK_APPROVAL"] == "prompt"


def test_install_hook_preserves_existing_unrelated_hooks(tmp_path: Path):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Read",
                "hooks": [{"type": "command", "command": "/bin/echo unrelated"}],
            }]
        },
        "theme": "monokai",
    }))
    result = runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings)])
    assert result.exit_code == 0, result.output
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["theme"] == "monokai"  # unrelated keys untouched
    pre = data["hooks"]["PreToolUse"]
    # Original hook + ours = 2 entries
    assert len(pre) == 2
    assert any("/bin/echo unrelated" == h.get("command")
               for entry in pre for h in entry.get("hooks") or [])
    assert any("claude-code-pretooluse" in str(h.get("command", ""))
               for entry in pre for h in entry.get("hooks") or [])


def test_install_hook_idempotent(tmp_path: Path):
    """Calling install twice doesn't accumulate duplicate hook entries."""
    settings = tmp_path / "settings.json"
    runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings)])
    runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings),
                        "--approval-mode", "block"])
    data = json.loads(settings.read_text(encoding="utf-8"))
    pre = data["hooks"]["PreToolUse"]
    ours = [
        entry for entry in pre
        if any("claude-code-pretooluse" in str(h.get("command", ""))
               for h in entry.get("hooks") or [])
    ]
    assert len(ours) == 1
    env = ours[0]["hooks"][0]["env"]
    assert env["AI_FIREWALL_HOOK_APPROVAL"] == "block"  # second call updated mode


def test_install_hook_refuses_invalid_json(tmp_path: Path):
    settings = tmp_path / "settings.json"
    settings.write_text("not json {{{")
    result = runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings)])
    assert result.exit_code == 1
    # File untouched
    assert settings.read_text(encoding="utf-8") == "not json {{{"


# ---------------------------------------------------------------------------
# `guard mcp uninstall-hook`
# ---------------------------------------------------------------------------


def test_uninstall_hook_removes_only_our_entry(tmp_path: Path):
    settings = tmp_path / "settings.json"
    runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings)])
    # Add an unrelated user hook AFTER install
    data = json.loads(settings.read_text(encoding="utf-8"))
    data["hooks"]["PreToolUse"].append({
        "matcher": "Read",
        "hooks": [{"type": "command", "command": "/bin/echo from-user"}],
    })
    settings.write_text(json.dumps(data))

    result = runner.invoke(cli, ["mcp", "uninstall-hook", "--settings", str(settings)])
    assert result.exit_code == 0, result.output

    data = json.loads(settings.read_text(encoding="utf-8"))
    pre = data["hooks"]["PreToolUse"]
    # Our entry gone, user's preserved
    assert all("claude-code-pretooluse" not in str(h.get("command", ""))
               for entry in pre for h in entry.get("hooks") or [])
    assert any("/bin/echo from-user" == h.get("command")
               for entry in pre for h in entry.get("hooks") or [])


def test_uninstall_hook_removes_hooks_key_when_empty(tmp_path: Path):
    settings = tmp_path / "settings.json"
    runner.invoke(cli, ["mcp", "install-hook", "--settings", str(settings)])
    runner.invoke(cli, ["mcp", "uninstall-hook", "--settings", str(settings)])
    data = json.loads(settings.read_text(encoding="utf-8"))
    # No leftover empty hooks scaffold
    assert "hooks" not in data


def test_uninstall_hook_handles_missing_file(tmp_path: Path):
    """Uninstall on a settings.json that doesn't exist should no-op cleanly."""
    settings = tmp_path / "missing.json"
    result = runner.invoke(cli, ["mcp", "uninstall-hook", "--settings", str(settings)])
    assert result.exit_code == 0
    assert "does not exist" in result.output
