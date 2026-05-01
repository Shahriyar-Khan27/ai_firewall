from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from ai_firewall.adapters.base import ExecutionResult
from ai_firewall.core.action import Action
from ai_firewall.engine.decision import Decision


class AuditLogger:
    """Append-only JSONL audit log with optional HMAC signing and external sinks.

    Each record is a JSON object. When `hmac_key` is provided (or auto-
    discovered), every record carries a `signature` field — HMAC-SHA256 over
    the canonical JSON (sorted keys, no whitespace, signature field excluded).

    By default the local JSONL file at `path` is the only sink. Pass `sinks`
    to add SIEM destinations (syslog, Splunk HEC, generic HTTPS webhook, …).
    The local file write stays synchronous so the on-disk record is durable
    before `log()` returns; remote sinks run on daemon threads with bounded
    queues, never blocking the firewall's hot path.

    A fresh log file gets a header record on first write so verifiers can
    check the key fingerprint matches before validating subsequent rows.
    """

    def __init__(
        self,
        path: Path,
        *,
        hmac_key: bytes | None = None,
        sinks: list | None = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

        self._hmac_key = hmac_key if hmac_key is not None else _resolve_hmac_key()

        # Default sinks = the local file. Callers can override with `sinks`.
        # When `sinks` is given but doesn't contain a JsonlFileSink for `path`,
        # we still write to the local file for compatibility with existing
        # `guard audit verify <path>` tooling.
        from ai_firewall.audit.sinks import JsonlFileSink, AuditSink  # noqa: F401
        if sinks is None:
            self._sinks: list = [JsonlFileSink(self.path)]
        else:
            self._sinks = list(sinks)
            if not any(isinstance(s, JsonlFileSink) for s in self._sinks):
                self._sinks.insert(0, JsonlFileSink(self.path))

        # Write the header once per log file so a verifier can confirm the key.
        if self._hmac_key is not None and not self.path.exists():
            self._write_header()

    def log(
        self,
        action: Action,
        decision: Decision,
        result: ExecutionResult | None = None,
        *,
        approved: bool | None = None,
    ) -> None:
        record = {
            "ts": time.time(),
            "action_id": action.id,
            "type": action.type,
            "rendered": _render(action),
            "intent": decision.intent.value,
            "risk": decision.risk.name,
            "decision": decision.decision,
            "reason": decision.reason,
            "impact": decision.impact.to_dict(),
            "approved": approved,
            "executed": bool(result and result.executed),
            "exit_code": result.exit_code if result else None,
        }
        if self._hmac_key is not None:
            record["signature"] = _sign(record, self._hmac_key)
        self._broadcast(record)

    def _broadcast(self, record: dict) -> None:
        """Send a record to every configured sink. Never raises."""
        for sink in self._sinks:
            try:
                sink.write(record)
            except Exception as e:  # noqa: BLE001
                import logging
                logging.getLogger("ai_firewall.audit").warning(
                    "audit sink %s failed: %s", type(sink).__name__, e
                )

    def _write_header(self) -> None:
        assert self._hmac_key is not None
        header = {
            "event": "init",
            "ts": time.time(),
            "key_fingerprint": _fingerprint(self._hmac_key),
            "version": 1,
        }
        header["signature"] = _sign(header, self._hmac_key)
        self._broadcast(header)

    def close(self) -> None:
        """Flush + close every sink. Safe to call multiple times."""
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Key resolution + signing helpers
# ---------------------------------------------------------------------------

_DEFAULT_KEY_PATH = Path.home() / ".ai-firewall" / "audit.key"


def _resolve_hmac_key() -> bytes | None:
    """Look for an HMAC key in env, then in ~/.ai-firewall/audit.key.

    HMAC signing is **opt-in**. If neither source provides a key, we return
    None and the logger writes unsigned records (v0.2.x-compatible behaviour).
    Users explicitly bootstrap signing via `guard audit init-key` or by
    setting AI_FIREWALL_AUDIT_KEY=<hex>.
    """
    env = os.environ.get("AI_FIREWALL_AUDIT_KEY")
    if env:
        try:
            # Hex-encoded key in the env var
            return bytes.fromhex(env.strip())
        except ValueError:
            return env.encode("utf-8")

    if _DEFAULT_KEY_PATH.exists():
        try:
            raw = _DEFAULT_KEY_PATH.read_bytes().strip()
        except OSError:
            return None
        # The key file is hex-encoded by `audit init-key`; if decoding fails,
        # fall back to using the raw bytes as the key.
        try:
            return bytes.fromhex(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return raw

    return None


def generate_and_persist_key(path: Path | None = None) -> Path:
    """Generate a fresh 32-byte HMAC key and persist it (hex-encoded, 0600)."""
    target = Path(path) if path else _DEFAULT_KEY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    target.write_bytes(key.hex().encode("utf-8"))
    try:
        os.chmod(target, 0o600)
    except (OSError, NotImplementedError):
        # Windows: chmod 0o600 is a no-op; user-homedir perms are sufficient.
        pass
    return target


def _canonical_bytes(record: dict) -> bytes:
    """Return canonical JSON bytes for signing: sorted keys, no whitespace,
    `signature` field excluded if present."""
    payload = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(record: dict, key: bytes) -> str:
    return hmac.new(key, _canonical_bytes(record), hashlib.sha256).hexdigest()


def _fingerprint(key: bytes) -> str:
    """Public, log-able fingerprint of the key. First 16 hex chars of SHA-256."""
    return hashlib.sha256(key).hexdigest()[:16]


def _render(action: Action) -> str:
    if action.type == "shell":
        return str(action.payload.get("cmd", ""))
    if action.type == "file":
        return f"{action.payload.get('op', '')} {action.payload.get('path', '')}".strip()
    if action.type == "db":
        return str(action.payload.get("sql", ""))
    if action.type == "api":
        return f"{action.payload.get('method', 'GET')} {action.payload.get('url', '')}".strip()
    return ""
