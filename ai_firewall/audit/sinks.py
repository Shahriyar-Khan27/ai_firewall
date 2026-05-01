"""Audit-log sinks — pluggable destinations for signed audit records.

Each sink consumes one record at a time. The default sink is `JsonlFileSink`
(the v0.3.x behaviour, preserving on-disk format). Additional sinks stream
the same records to external SIEMs:

  - `StdoutSink`    : pipe into `vector` / `fluent-bit` / a sidecar
  - `SyslogSink`    : RFC 5424 over UDP/TCP
  - `SplunkHECSink` : Splunk HTTP Event Collector
  - `HttpsSink`     : generic HTTPS POST (Datadog, Elastic, custom webhooks)

All non-file sinks are async — each owns a daemon thread + bounded queue so
the firewall's hot path never blocks on a slow downstream.
"""
from __future__ import annotations

import json
import logging
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


log = logging.getLogger("ai_firewall.audit.sinks")


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

class AuditSink(Protocol):
    """Anything that can consume an audit record (already signed if HMAC was on)."""

    def write(self, record: dict[str, Any]) -> None: ...

    def close(self) -> None: ...


# ---------------------------------------------------------------------------
# JSONL file (default — preserves v0.3.x on-disk format)
# ---------------------------------------------------------------------------

class JsonlFileSink:
    """Append-only JSONL file. Synchronous — same as v0.3.x AuditLogger."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    def close(self) -> None:
        # Nothing persistent to release — we open/close per write.
        return


# ---------------------------------------------------------------------------
# Stdout (for piping into vector/fluent-bit)
# ---------------------------------------------------------------------------

class StdoutSink:
    """Write each record as a JSONL line to stdout."""

    def __init__(self, stream=None):
        import sys
        self._stream = stream or sys.stdout
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            try:
                self._stream.write(line)
                self._stream.flush()
            except (BrokenPipeError, OSError):
                pass

    def close(self) -> None:
        return


# ---------------------------------------------------------------------------
# Async base — owns a daemon worker thread + bounded queue
# ---------------------------------------------------------------------------

@dataclass
class _AsyncStats:
    enqueued: int = 0
    delivered: int = 0
    dropped: int = 0
    failed: int = 0


class _AsyncSink:
    """Base class for sinks that talk to a remote service."""

    def __init__(self, queue_size: int = 1024):
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=queue_size)
        self._stats = _AsyncStats()
        self._stopping = threading.Event()
        self._worker = threading.Thread(target=self._run, daemon=True, name=f"audit-sink-{type(self).__name__}")
        self._worker.start()

    def write(self, record: dict[str, Any]) -> None:
        try:
            self._q.put_nowait(record)
            self._stats.enqueued += 1
        except queue.Full:
            self._stats.dropped += 1
            log.warning("audit sink %s queue full — dropping record", type(self).__name__)

    def stats(self) -> _AsyncStats:
        return self._stats

    def close(self) -> None:
        self._stopping.set()
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass
        # Don't block forever on a stuck remote.
        self._worker.join(timeout=2.0)

    def _run(self) -> None:
        # Drain on stop: only exit when the sentinel arrives or the queue
        # is empty AND `_stopping` is set. This way close() doesn't drop
        # records that were enqueued just before it.
        while True:
            try:
                rec = self._q.get(timeout=0.2)
            except queue.Empty:
                if self._stopping.is_set():
                    break
                continue
            if rec is None:
                break
            try:
                self._send(rec)
                self._stats.delivered += 1
            except Exception as e:  # noqa: BLE001 — never let one bad send kill the worker
                self._stats.failed += 1
                log.warning("audit sink %s send failed: %s", type(self).__name__, e)

    # Subclasses override
    def _send(self, record: dict[str, Any]) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Syslog (RFC 5424, UDP or TCP)
# ---------------------------------------------------------------------------

class SyslogSink(_AsyncSink):
    """RFC 5424 syslog over UDP or TCP. Severity mapped from record.risk."""

    _SEV_MAP = {
        "CRITICAL": 2,  # Critical
        "HIGH":     4,  # Warning
        "MEDIUM":   5,  # Notice
        "LOW":      6,  # Informational
    }

    def __init__(
        self,
        host: str = "localhost",
        port: int = 514,
        protocol: str = "udp",
        facility: int = 16,  # local0
        app_name: str = "ai-firewall",
        queue_size: int = 1024,
    ):
        super().__init__(queue_size=queue_size)
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.facility = facility
        self.app_name = app_name
        self._sock: socket.socket | None = None

    def _ensure_socket(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self.protocol == "tcp":
            s = socket.create_connection((self.host, self.port), timeout=5.0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = s
        return s

    def _send(self, record: dict[str, Any]) -> None:
        risk = (record.get("risk") or "MEDIUM").upper()
        sev = self._SEV_MAP.get(risk, 6)
        pri = self.facility * 8 + sev
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.gmtime(record.get("ts", time.time())))
        if not ts.endswith("Z") and not (ts.endswith("00") or ts.endswith("30")):
            ts += "Z"
        host = socket.gethostname() or "-"
        msg = json.dumps(record, ensure_ascii=False)
        # RFC 5424 format: <pri>1 ts host app procid msgid structured-data msg
        line = f"<{pri}>1 {ts} {host} {self.app_name} - - - {msg}\n"
        data = line.encode("utf-8")
        s = self._ensure_socket()
        try:
            if self.protocol == "tcp":
                s.sendall(data)
            else:
                s.sendto(data, (self.host, self.port))
        except OSError:
            # Drop the cached socket — next send will reconnect.
            self._sock = None
            raise

    def close(self) -> None:
        super().close()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Splunk HEC (HTTP Event Collector)
# ---------------------------------------------------------------------------

class SplunkHECSink(_AsyncSink):
    """POST events to Splunk HEC. Token can be provided directly or via env."""

    def __init__(
        self,
        url: str,
        token: str | None = None,
        index: str | None = None,
        sourcetype: str = "ai_firewall",
        verify_tls: bool = True,
        timeout_s: float = 5.0,
        queue_size: int = 1024,
    ):
        super().__init__(queue_size=queue_size)
        self.url = url
        import os
        self.token = token or os.environ.get("AI_FIREWALL_SPLUNK_TOKEN", "")
        self.index = index
        self.sourcetype = sourcetype
        self.verify_tls = verify_tls
        self.timeout_s = timeout_s

    def _send(self, record: dict[str, Any]) -> None:
        envelope: dict[str, Any] = {
            "event": record,
            "sourcetype": self.sourcetype,
            "time": record.get("ts", time.time()),
        }
        if self.index:
            envelope["index"] = self.index
        body = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Splunk {self.token}",
            },
        )
        ctx = None if self.verify_tls else ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=self.timeout_s, context=ctx) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"splunk HEC returned {resp.status}")


# ---------------------------------------------------------------------------
# Generic HTTPS webhook
# ---------------------------------------------------------------------------

class HttpsSink(_AsyncSink):
    """POST each record as JSON to an HTTPS webhook (Datadog, custom SIEM)."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        verify_tls: bool = True,
        timeout_s: float = 5.0,
        queue_size: int = 1024,
    ):
        super().__init__(queue_size=queue_size)
        self.url = url
        self.headers = dict(headers or {})
        self.headers.setdefault("Content-Type", "application/json")
        self.verify_tls = verify_tls
        self.timeout_s = timeout_s

    def _send(self, record: dict[str, Any]) -> None:
        body = json.dumps(record, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, method="POST", headers=self.headers)
        ctx = None if self.verify_tls else ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=self.timeout_s, context=ctx) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"https sink returned {resp.status}")


# ---------------------------------------------------------------------------
# Factory: build sinks from a dict (loaded from sinks.toml or similar)
# ---------------------------------------------------------------------------

def build_sinks_from_config(config: list[dict[str, Any]]) -> list[AuditSink]:
    """Translate a list of sink configs into instantiated sinks.

    Example config:
        [
          {"type": "jsonl", "path": "logs/audit.jsonl"},
          {"type": "syslog", "host": "siem.internal", "port": 514, "protocol": "udp"},
          {"type": "splunk", "url": "https://hec.splunk.example/services/collector",
           "token_env": "SPLUNK_TOKEN", "index": "ai_firewall"},
          {"type": "https", "url": "https://siem.example/webhook",
           "headers": {"Authorization": "Bearer …"}},
          {"type": "stdout"}
        ]
    """
    sinks: list[AuditSink] = []
    for entry in config or []:
        kind = (entry.get("type") or "").lower()
        if kind == "jsonl":
            sinks.append(JsonlFileSink(entry["path"]))
        elif kind == "syslog":
            sinks.append(SyslogSink(
                host=entry.get("host", "localhost"),
                port=int(entry.get("port", 514)),
                protocol=entry.get("protocol", "udp"),
                facility=int(entry.get("facility", 16)),
            ))
        elif kind == "splunk":
            import os
            token = entry.get("token") or os.environ.get(entry.get("token_env", "") or "", "")
            sinks.append(SplunkHECSink(
                url=entry["url"],
                token=token,
                index=entry.get("index"),
                sourcetype=entry.get("sourcetype", "ai_firewall"),
                verify_tls=bool(entry.get("verify_tls", True)),
            ))
        elif kind == "https":
            sinks.append(HttpsSink(
                url=entry["url"],
                headers=entry.get("headers") or {},
                verify_tls=bool(entry.get("verify_tls", True)),
            ))
        elif kind == "stdout":
            sinks.append(StdoutSink())
    return sinks
