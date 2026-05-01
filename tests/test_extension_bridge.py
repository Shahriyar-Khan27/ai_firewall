"""v0.5.0 — Python ↔ VS Code extension approval bridge."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.approval.extension_bridge import (
    discover_target,
    make_extension_approval,
)
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine.decision import Decision
from ai_firewall.engine.impact import Impact


@pytest.fixture
def sample_action_decision():
    action = Action.shell("rm -rf ./build")
    decision = Decision(
        decision="REQUIRE_APPROVAL",
        reason="risk HIGH",
        intent=IntentType.FILE_DELETE,
        risk=RiskLevel.HIGH,
        impact=Impact(notes=""),
    )
    return action, decision


# ---------------------------------------------------------------------------
# discover_target — port file parsing
# ---------------------------------------------------------------------------


def test_discover_returns_none_when_file_missing(tmp_path: Path):
    assert discover_target(tmp_path / "nope.port") is None


def test_discover_parses_valid_port_file(tmp_path: Path):
    pf = tmp_path / "extension.port"
    pf.write_text(json.dumps({"host": "127.0.0.1", "port": 53219, "token": "abc123", "pid": 999}))
    target = discover_target(pf)
    assert target is not None
    assert target.url == "http://127.0.0.1:53219/approve"
    assert target.token == "abc123"
    assert target.pid == 999


def test_discover_returns_none_for_corrupt_json(tmp_path: Path):
    pf = tmp_path / "extension.port"
    pf.write_text("{not json")
    assert discover_target(pf) is None


def test_discover_returns_none_when_token_missing(tmp_path: Path):
    pf = tmp_path / "extension.port"
    pf.write_text(json.dumps({"port": 53219}))
    assert discover_target(pf) is None


# ---------------------------------------------------------------------------
# Local HTTP listener fixture (mimics the extension's approval server)
# ---------------------------------------------------------------------------


class _FakeExtension(BaseHTTPRequestHandler):
    """Configurable per-test: returns whatever the test sets up."""

    expected_token: str = "test-token"
    response_decision: str = "approve"
    captured_bodies: list[dict] = []
    captured_tokens: list[str] = []
    delay_seconds: float = 0.0
    status_code: int = 200

    def log_message(self, *a, **k):  # quiet
        return

    def do_POST(self):
        if self.delay_seconds:
            import time
            time.sleep(self.delay_seconds)
        token = self.headers.get("X-Firewall-Token", "")
        self.__class__.captured_tokens.append(token)
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        try:
            self.__class__.captured_bodies.append(json.loads(body.decode("utf-8")))
        except Exception:
            self.__class__.captured_bodies.append({})
        if token != self.expected_token:
            self.send_response(401)
            self.end_headers()
            return
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"decision": self.response_decision}).encode("utf-8"))


@pytest.fixture
def fake_extension(tmp_path: Path):
    """Spin up a fake extension HTTP server; write a matching port file."""
    _FakeExtension.captured_bodies = []
    _FakeExtension.captured_tokens = []
    _FakeExtension.expected_token = "test-token"
    _FakeExtension.response_decision = "approve"
    _FakeExtension.status_code = 200
    _FakeExtension.delay_seconds = 0.0
    server = HTTPServer(("127.0.0.1", 0), _FakeExtension)
    port = server.server_address[1]
    port_file = tmp_path / "extension.port"
    port_file.write_text(json.dumps({
        "host": "127.0.0.1",
        "port": port,
        "token": "test-token",
        "pid": 1,
    }))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port_file, _FakeExtension
    finally:
        server.shutdown()
        thread.join(timeout=2)


# ---------------------------------------------------------------------------
# make_extension_approval — round-trip behaviour
# ---------------------------------------------------------------------------


def test_approval_round_trip_approve(fake_extension, sample_action_decision):
    port_file, handler = fake_extension
    handler.response_decision = "approve"
    fn = make_extension_approval(port_file=port_file, fallback_fn=auto_deny)
    action, decision = sample_action_decision
    assert fn(action, decision) is True
    # request body carries action + decision payload
    assert len(handler.captured_bodies) == 1
    body = handler.captured_bodies[0]
    assert body["action"]["type"] == "shell"
    assert body["decision"]["decision"] == "REQUIRE_APPROVAL"
    # token header propagated
    assert handler.captured_tokens == ["test-token"]


def test_approval_round_trip_reject(fake_extension, sample_action_decision):
    port_file, handler = fake_extension
    handler.response_decision = "reject"
    fn = make_extension_approval(port_file=port_file, fallback_fn=auto_deny)
    action, decision = sample_action_decision
    assert fn(action, decision) is False


def test_falls_back_when_port_file_missing(tmp_path: Path, sample_action_decision):
    """No extension configured → fallback path runs."""
    fn = make_extension_approval(port_file=tmp_path / "absent.port", fallback_fn=auto_approve)
    action, decision = sample_action_decision
    assert fn(action, decision) is True


def test_falls_back_when_server_returns_5xx(fake_extension, sample_action_decision):
    port_file, handler = fake_extension
    handler.status_code = 500
    fn = make_extension_approval(port_file=port_file, fallback_fn=auto_approve)
    action, decision = sample_action_decision
    # Server error → fall through to fallback (auto_approve in this test)
    assert fn(action, decision) is True


def test_falls_back_when_token_mismatch(tmp_path: Path, fake_extension, sample_action_decision):
    """Port-file token that doesn't match the server's expected token must fall back, never approve."""
    port_file, handler = fake_extension
    # Rewrite port file with WRONG token
    data = json.loads(port_file.read_text())
    data["token"] = "wrong-token"
    port_file.write_text(json.dumps(data))
    fn = make_extension_approval(port_file=port_file, fallback_fn=auto_deny)
    action, decision = sample_action_decision
    assert fn(action, decision) is False


def test_timeout_falls_back_to_safe_default(fake_extension, sample_action_decision):
    """When the extension takes too long, we deny (or whatever fallback says)."""
    port_file, handler = fake_extension
    handler.delay_seconds = 1.0
    fn = make_extension_approval(
        port_file=port_file,
        fallback_fn=auto_deny,
        timeout_s=0.1,  # forces timeout
    )
    action, decision = sample_action_decision
    assert fn(action, decision) is False
