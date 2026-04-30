"""Phase 3.5b: HTTP execute mode via stdlib urllib.

These tests spin up a local HTTP server in a thread and point the adapter at it,
so we exercise the full request → response → render path without external network.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from ai_firewall.adapters.api_execute import HTTPExecuteAdapter
from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard


class _Handler(BaseHTTPRequestHandler):
    received: list[dict] = []

    def _capture(self, method: str) -> None:
        body_len = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(body_len).decode("utf-8") if body_len else ""
        self.__class__.received.append({
            "method": method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })

    def log_message(self, *args, **kwargs):  # silence test noise
        pass

    def do_GET(self):
        self._capture("GET")
        if self.path == "/json":
            payload = json.dumps({"hello": "world"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/404":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"not found")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

    def do_POST(self):
        self._capture("POST")
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"created":true}')

    def do_DELETE(self):
        self._capture("DELETE")
        self.send_response(204)
        self.end_headers()


@pytest.fixture
def http_server():
    _Handler.received = []
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _Handler
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_get_returns_status_and_body(http_server):
    base, _ = http_server
    adapter = HTTPExecuteAdapter()
    res = adapter.run(Action.api("GET", f"{base}/json"))
    assert res.exit_code == 0
    assert res.executed is True
    assert "HTTP 200" in res.stdout
    assert '"hello": "world"' in res.stdout
    assert "Content-Type: application/json" in res.stdout


def test_404_marks_executed_with_nonzero_exit(http_server):
    base, _ = http_server
    adapter = HTTPExecuteAdapter()
    res = adapter.run(Action.api("GET", f"{base}/404"))
    assert res.executed is True  # the request did go out
    assert res.exit_code == 1
    assert "HTTP 404" in res.stdout
    assert "not found" in res.stdout


def test_post_with_body_actually_sends(http_server):
    base, handler_cls = http_server
    adapter = HTTPExecuteAdapter()
    body = json.dumps({"event": "login", "user": 42})
    res = adapter.run(Action.api("POST", f"{base}/things", body=body, headers={"Content-Type": "application/json"}))
    assert res.exit_code == 0
    assert "HTTP 201" in res.stdout
    # Server actually saw the body:
    received = handler_cls.received[-1]
    assert received["method"] == "POST"
    assert received["body"] == body
    assert received["headers"].get("Content-Type") == "application/json"


def test_delete_request(http_server):
    base, handler_cls = http_server
    adapter = HTTPExecuteAdapter()
    res = adapter.run(Action.api("DELETE", f"{base}/things/42"))
    assert res.exit_code == 0  # 204 is in 200-399
    assert "HTTP 204" in res.stdout
    assert handler_cls.received[-1]["method"] == "DELETE"


def test_unreachable_host_reports_url_error():
    adapter = HTTPExecuteAdapter(timeout=2)
    # Port 1 is unprivileged on most boxes and almost never bound.
    res = adapter.run(Action.api("GET", "http://127.0.0.1:1/"))
    assert res.executed is False
    assert res.exit_code == 1
    assert "URL error" in res.stderr or "timeout" in res.stderr.lower()


def test_blocked_request_does_not_hit_server(http_server):
    base, handler_cls = http_server
    g = Guard(
        approval_fn=auto_deny,
        adapters={"api": HTTPExecuteAdapter()},
    )
    # Cloud-metadata pattern → CRITICAL → REQUIRE_APPROVAL → auto_deny → Blocked.
    # We use the local server for the URL but the metadata IP for the host so
    # url_analysis flags it; the request never goes out.
    with pytest.raises(Blocked):
        g.execute(Action.api("GET", "http://169.254.169.254/latest/meta-data/"))
    assert handler_cls.received == []


def test_approved_request_actually_hits_server(http_server, tmp_path: Path):
    base, handler_cls = http_server
    g = Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_approve,
        adapters={"api": HTTPExecuteAdapter()},
    )
    g.execute(Action.api("GET", f"{base}/anything"))
    assert any(r["method"] == "GET" and r["path"] == "/anything" for r in handler_cls.received)
    rec = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())
    assert rec["executed"] is True
    assert rec["exit_code"] == 0
