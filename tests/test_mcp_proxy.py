"""Feature A — MCP detector + transparent proxy."""
import json
import sys
from pathlib import Path

import pytest

from ai_firewall.discovery import mcp_detector
from ai_firewall.proxy.mcp_proxy import (
    ToolCall,
    _build_block_response,
    _is_tool_call,
    inspect_request,
    map_to_action,
)


# --- Detector ---


def test_scan_finds_unwrapped_server(tmp_path: Path):
    cfg = tmp_path / "claude" / "mcp.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({
        "mcpServers": {
            "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}
        }
    }), encoding="utf-8")

    entries = mcp_detector.scan(extra_paths=[("claude-code", cfg)])
    assert len(entries) == 1
    e = entries[0]
    assert e.name == "fetch"
    assert e.command == "uvx"
    assert e.args == ("mcp-server-fetch",)
    assert e.wrapped is False


def test_scan_recognizes_already_wrapped_server(tmp_path: Path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "fetch": {
                "command": "guard",
                "args": [
                    "mcp-proxy",
                    mcp_detector.WRAPPER_MARKER,
                    "--upstream-cmd", "uvx",
                    "--upstream-arg", "mcp-server-fetch",
                ],
            }
        }
    }), encoding="utf-8")

    entries = mcp_detector.scan(extra_paths=[("generic", cfg)])
    assert len(entries) == 1
    e = entries[0]
    assert e.wrapped is True
    assert e.upstream_command == "uvx"
    assert e.upstream_args == ("mcp-server-fetch",)


def test_install_returns_wrapper_spec(tmp_path: Path):
    e = mcp_detector.MCPServerEntry(
        host="claude-code",
        config_path=tmp_path / "mcp.json",
        name="fetch",
        command="uvx",
        args=("mcp-server-fetch",),
    )
    spec = mcp_detector.install(e, guard_cmd="guard")
    assert spec["command"] == "guard"
    assert spec["args"][0] == "mcp-proxy"
    assert mcp_detector.WRAPPER_MARKER in spec["args"]
    assert "uvx" in spec["args"]
    assert "mcp-server-fetch" in spec["args"]


def test_uninstall_recovers_original(tmp_path: Path):
    wrapped = mcp_detector.MCPServerEntry(
        host="claude-code",
        config_path=tmp_path / "mcp.json",
        name="fetch",
        command="guard",
        args=("mcp-proxy", mcp_detector.WRAPPER_MARKER, "--upstream-cmd", "uvx", "--upstream-arg", "mcp-server-fetch"),
        wrapped=True,
        upstream_command="uvx",
        upstream_args=("mcp-server-fetch",),
    )
    original = mcp_detector.uninstall(wrapped)
    assert original is not None
    assert original["command"] == "uvx"
    assert original["args"] == ["mcp-server-fetch"]


def test_write_servers_preserves_other_keys(tmp_path: Path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({
        "theme": "dark",
        "mcpServers": {"fetch": {"command": "uvx", "args": []}},
    }), encoding="utf-8")

    mcp_detector.write_servers(cfg, {"fetch": {"command": "guard", "args": []}})
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["theme"] == "dark"
    assert data["mcpServers"]["fetch"]["command"] == "guard"


# --- Tool-call → Action mapping ---


def test_map_to_action_shell_command():
    a = map_to_action(ToolCall("run_shell", {"command": "rm -rf /"}))
    assert a is not None
    assert a.type == "shell"
    assert a.payload["cmd"] == "rm -rf /"


def test_map_to_action_file_write():
    a = map_to_action(ToolCall("write_file", {"file_path": "/tmp/x", "content": "data"}))
    assert a is not None
    assert a.type == "file"
    assert a.payload["op"] == "write"


def test_map_to_action_file_delete_by_name():
    a = map_to_action(ToolCall("delete_file", {"file_path": "/tmp/x"}))
    assert a is not None
    assert a.payload["op"] == "delete"


def test_map_to_action_sql_query():
    a = map_to_action(ToolCall("run_sql_query", {"sql": "DROP DATABASE prod"}))
    assert a is not None
    assert a.type == "db"


def test_map_to_action_http_request():
    a = map_to_action(ToolCall("fetch_url", {"url": "https://api.example.com/data"}))
    assert a is not None
    assert a.type == "api"
    assert a.payload["method"] == "GET"


def test_map_to_action_returns_none_for_unrecognized():
    a = map_to_action(ToolCall("frobnicate", {"foo": 1, "bar": "baz"}))
    assert a is None


# --- inspect_request gate ---


def test_inspect_forwards_non_tool_calls(tmp_path: Path):
    from ai_firewall.core.guard import Guard
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db")

    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    action, response = inspect_request(msg, guard=g)
    assert action == "forward"
    assert response is None


def test_inspect_blocks_dangerous_shell_call(tmp_path: Path):
    from ai_firewall.core.guard import Guard
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db")

    msg = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "run_shell", "arguments": {"command": "rm -rf /"}},
    }
    action, response = inspect_request(msg, guard=g)
    assert action == "block"
    assert response is not None
    assert response["id"] == 7
    assert response["result"]["isError"] is True
    assert "blocked" in response["result"]["content"][0]["text"].lower()


def test_inspect_blocks_require_approval_in_block_mode(tmp_path: Path):
    from ai_firewall.core.guard import Guard
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db")

    target = tmp_path / "tmp.txt"
    target.write_text("data")
    msg = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": "delete_file", "arguments": {"file_path": str(target)}},
    }
    action, response = inspect_request(msg, guard=g, approval_mode="block")
    # Default file_delete policy is REQUIRE_APPROVAL → block in proxy default mode
    assert action == "block"
    assert response is not None
    assert "REQUIRE_APPROVAL" in response["result"]["content"][0]["text"]


def test_inspect_forwards_safe_call(tmp_path: Path):
    from ai_firewall.core.guard import Guard
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db")

    msg = {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "run_shell", "arguments": {"command": "echo hello"}},
    }
    action, response = inspect_request(msg, guard=g)
    assert action == "forward"
    assert response is None


def test_inspect_forwards_unrecognized_tool_shape(tmp_path: Path):
    from ai_firewall.core.guard import Guard
    g = Guard(audit_path=tmp_path / "audit.jsonl", memory_db_path=tmp_path / "memory.db")

    msg = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "weather_lookup", "arguments": {"city": "Bengaluru"}},
    }
    action, response = inspect_request(msg, guard=g)
    assert action == "forward"
    assert response is None


def test_block_response_shape():
    resp = _build_block_response(42, "matches blocked pattern `rm`")
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 42
    assert resp["result"]["isError"] is True
    assert "rm" in resp["result"]["content"][0]["text"]
