"""Feature 6 — SIEM-ready audit sinks."""
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from ai_firewall.audit.logger import AuditLogger
from ai_firewall.audit.sinks import (
    HttpsSink,
    JsonlFileSink,
    SplunkHECSink,
    StdoutSink,
    SyslogSink,
    build_sinks_from_config,
)


# --- JsonlFileSink (default) ---


def test_jsonl_sink_appends_records(tmp_path: Path):
    sink = JsonlFileSink(tmp_path / "audit.jsonl")
    sink.write({"a": 1})
    sink.write({"a": 2})
    sink.close()
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1}


# --- StdoutSink ---


def test_stdout_sink(capsys):
    sink = StdoutSink()
    sink.write({"hello": "world"})
    captured = capsys.readouterr()
    assert json.loads(captured.out.strip()) == {"hello": "world"}


# --- HTTPS sink against a local listener ---


class _CaptureHandler(BaseHTTPRequestHandler):
    captured: list[bytes] = []

    def log_message(self, *a, **k):
        return

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.__class__.captured.append(self.rfile.read(n))
        self.send_response(200)
        self.end_headers()


@pytest.fixture
def http_listener():
    _CaptureHandler.captured = []
    server = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _CaptureHandler
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_https_sink_delivers(http_listener):
    base, handler = http_listener
    sink = HttpsSink(url=f"{base}/webhook", queue_size=8)
    sink.write({"event": "test", "n": 1})
    sink.write({"event": "test", "n": 2})
    sink.close()  # waits for worker

    # Both records should have been delivered
    delivered = [json.loads(b.decode("utf-8")) for b in handler.captured]
    assert len(delivered) == 2
    assert {"n": 1, "event": "test"} in delivered
    assert {"n": 2, "event": "test"} in delivered


def test_https_sink_failure_does_not_crash(http_listener):
    sink = HttpsSink(url="http://127.0.0.1:1/", timeout_s=0.5, queue_size=4)
    # Server doesn't exist; sink must not raise
    sink.write({"event": "lost"})
    sink.close()
    stats = sink.stats()
    assert stats.failed >= 1


def test_https_sink_queue_full_drops(monkeypatch):
    """When the queue overflows, records are dropped, not raised."""
    sink = HttpsSink(url="http://127.0.0.1:1/", timeout_s=2.0, queue_size=1)
    # Stop the worker before writes so the queue actually fills
    sink._stopping.set()
    # Fill + overflow
    sink.write({"a": 1})
    sink.write({"b": 2})  # this one drops
    sink.write({"c": 3})  # this one drops
    assert sink.stats().enqueued >= 1
    assert sink.stats().dropped >= 1


# --- Syslog (UDP) ---


def test_syslog_udp_packet_format():
    """Bind a UDP socket, send one record, parse the packet."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(2.0)
    port = server.getsockname()[1]

    sink = SyslogSink(host="127.0.0.1", port=port, protocol="udp", queue_size=4)
    sink.write({
        "ts": 1700000000.0,
        "risk": "CRITICAL",
        "intent": "FILE_DELETE",
        "rendered": "rm -rf /",
    })

    try:
        data, _addr = server.recvfrom(8192)
        text = data.decode("utf-8")
        # RFC 5424 framing: <pri>1 ts host app procid msgid sd msg
        assert text.startswith("<")
        assert ">1 " in text
        assert "rm -rf /" in text  # message body included
    finally:
        sink.close()
        server.close()


# --- Splunk HEC ---


def test_splunk_hec_envelope(http_listener):
    base, handler = http_listener
    sink = SplunkHECSink(url=f"{base}/services/collector", token="test-token", index="ai_firewall", queue_size=4)
    sink.write({"ts": 1700000000.0, "intent": "SHELL_EXEC", "decision": "ALLOW"})
    sink.close()

    delivered = [json.loads(b.decode("utf-8")) for b in handler.captured]
    assert len(delivered) == 1
    envelope = delivered[0]
    assert envelope["event"]["intent"] == "SHELL_EXEC"
    assert envelope["sourcetype"] == "ai_firewall"
    assert envelope["index"] == "ai_firewall"
    assert envelope["time"] == 1700000000.0


# --- AuditLogger integration with sinks ---


def test_logger_writes_to_extra_sink_alongside_jsonl(tmp_path: Path, http_listener):
    """Records hit the local file AND each configured sink."""
    base, handler = http_listener
    extra = HttpsSink(url=f"{base}/webhook", queue_size=4)
    logger = AuditLogger(tmp_path / "audit.jsonl", sinks=[extra])

    from ai_firewall.adapters.base import ExecutionResult
    from ai_firewall.core.action import Action
    from ai_firewall.engine.decision import Decision
    from ai_firewall.engine.impact import Impact
    from ai_firewall.core.action import IntentType, RiskLevel

    action = Action.shell("echo hi")
    decision = Decision(
        decision="ALLOW", reason="t", intent=IntentType.SHELL_EXEC,
        risk=RiskLevel.LOW, impact=Impact(notes=""),
    )
    logger.log(action, decision)
    logger.close()

    # Local file got the record
    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()[-1]
    assert json.loads(line)["intent"] == "SHELL_EXEC"

    # HTTPS sink got the same record
    assert len(handler.captured) >= 1
    delivered = json.loads(handler.captured[-1].decode("utf-8"))
    assert delivered["intent"] == "SHELL_EXEC"


# --- Factory ---


def test_build_sinks_from_config(tmp_path: Path):
    config = [
        {"type": "jsonl", "path": str(tmp_path / "extra.jsonl")},
        {"type": "stdout"},
        {"type": "https", "url": "http://127.0.0.1:1/"},
    ]
    sinks = build_sinks_from_config(config)
    assert len(sinks) == 3
    assert any(isinstance(s, JsonlFileSink) for s in sinks)
    assert any(isinstance(s, StdoutSink) for s in sinks)
    assert any(isinstance(s, HttpsSink) for s in sinks)
    for s in sinks:
        s.close()


def test_build_sinks_unknown_type_silently_skipped():
    sinks = build_sinks_from_config([{"type": "doesnotexist"}, {"type": "stdout"}])
    assert len(sinks) == 1
    assert isinstance(sinks[0], StdoutSink)
    sinks[0].close()
