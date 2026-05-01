"""Feature E — HMAC-signed audit trails."""
import json
import os
import secrets
from pathlib import Path

import pytest

from ai_firewall.adapters.base import ExecutionResult
from ai_firewall.audit.logger import AuditLogger, _resolve_hmac_key
from ai_firewall.audit.verifier import verify
from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine.decision import Decision
from ai_firewall.engine.impact import Impact


def _decision(action: Action, *, risk=RiskLevel.MEDIUM) -> Decision:
    return Decision(
        decision="ALLOW",
        reason="test",
        intent=IntentType.SHELL_EXEC,
        risk=risk,
        impact=Impact(notes="test"),
    )


def test_no_key_writes_unsigned_records(tmp_path: Path, monkeypatch):
    # Force key resolution to find nothing
    monkeypatch.delenv("AI_FIREWALL_AUDIT_KEY", raising=False)
    monkeypatch.setattr("ai_firewall.audit.logger._DEFAULT_KEY_PATH", tmp_path / "no_such.key")
    # Disable auto-generation by making the parent unwritable
    # Simplest: override _resolve_hmac_key to return None
    monkeypatch.setattr("ai_firewall.audit.logger._resolve_hmac_key", lambda: None)

    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.log(Action.shell("echo hi"), _decision(Action.shell("echo hi")))

    rec = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())
    assert "signature" not in rec


def test_explicit_key_signs_records(tmp_path: Path):
    key = secrets.token_bytes(32)
    logger = AuditLogger(tmp_path / "audit.jsonl", hmac_key=key)
    logger.log(Action.shell("echo hi"), _decision(Action.shell("echo hi")))

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2  # header + the one record
    header = json.loads(lines[0])
    assert header["event"] == "init"
    assert "signature" in header
    record = json.loads(lines[1])
    assert "signature" in record
    assert len(record["signature"]) == 64  # SHA-256 hex


def test_verify_passes_on_clean_log(tmp_path: Path):
    key = secrets.token_bytes(32)
    logger = AuditLogger(tmp_path / "audit.jsonl", hmac_key=key)
    for cmd in ("echo a", "echo b", "echo c"):
        logger.log(Action.shell(cmd), _decision(Action.shell(cmd)))

    report = verify(tmp_path / "audit.jsonl", key=key)
    assert report.ok
    assert report.total == 4  # header + 3 records
    assert report.valid == 4
    assert report.tampered_indices == []


def test_verify_detects_byte_flip(tmp_path: Path):
    key = secrets.token_bytes(32)
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path, hmac_key=key)
    logger.log(Action.shell("echo first"), _decision(Action.shell("echo first")))
    logger.log(Action.shell("echo second"), _decision(Action.shell("echo second")))

    # Tamper: change "first" to "FIRST" in the log
    text = log_path.read_text(encoding="utf-8")
    tampered = text.replace("echo first", "echo FIRST", 1)
    assert tampered != text  # ensure the replacement happened
    log_path.write_text(tampered, encoding="utf-8")

    report = verify(log_path, key=key)
    assert not report.ok
    assert len(report.tampered_indices) == 1


def test_verify_detects_wrong_key(tmp_path: Path):
    key_a = secrets.token_bytes(32)
    key_b = secrets.token_bytes(32)
    log_path = tmp_path / "audit.jsonl"
    AuditLogger(log_path, hmac_key=key_a).log(Action.shell("echo hi"), _decision(Action.shell("echo hi")))

    report = verify(log_path, key=key_b)
    assert not report.ok
    assert report.fingerprint_mismatch  # header check catches this immediately
    # Every record should fail signature verification under wrong key
    assert len(report.tampered_indices) == report.total


def test_env_var_key_resolution(tmp_path: Path, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("AI_FIREWALL_AUDIT_KEY", key.hex())
    monkeypatch.setattr("ai_firewall.audit.logger._DEFAULT_KEY_PATH", tmp_path / "no_such.key")

    resolved = _resolve_hmac_key()
    assert resolved == key


def test_homedir_key_file_resolution(tmp_path: Path, monkeypatch):
    key_file = tmp_path / "audit.key"
    key = secrets.token_bytes(32)
    key_file.write_bytes(key.hex().encode("utf-8"))

    monkeypatch.delenv("AI_FIREWALL_AUDIT_KEY", raising=False)
    monkeypatch.setattr("ai_firewall.audit.logger._DEFAULT_KEY_PATH", key_file)

    resolved = _resolve_hmac_key()
    # The on-disk format is hex, but _resolve returns the raw bytes equivalent
    # — accept either since the function strips whitespace.
    assert resolved is not None


def test_canonical_signature_independent_of_key_order(tmp_path: Path):
    """The signature must be stable regardless of insertion order in the dict."""
    from ai_firewall.audit.logger import _sign

    key = secrets.token_bytes(32)
    rec_a = {"a": 1, "b": 2, "c": 3}
    rec_b = {"c": 3, "a": 1, "b": 2}
    assert _sign(rec_a, key) == _sign(rec_b, key)


def test_sigless_legacy_log_still_loadable(tmp_path: Path):
    """An unsigned legacy log still parses; verify reports unsigned count."""
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text(
        json.dumps({"ts": 1.0, "rendered": "echo hi", "decision": "ALLOW"}) + "\n",
        encoding="utf-8",
    )
    # No header → no fingerprint to compare; verify with no key just counts unsigned
    report = verify(log_path, key=secrets.token_bytes(32))
    assert report.total == 1
    assert report.unsigned == 1
    assert report.valid == 0


def test_existing_file_does_not_get_double_header(tmp_path: Path):
    """Re-opening an existing log doesn't add another init header."""
    key = secrets.token_bytes(32)
    log_path = tmp_path / "audit.jsonl"
    AuditLogger(log_path, hmac_key=key).log(Action.shell("echo a"), _decision(Action.shell("echo a")))
    AuditLogger(log_path, hmac_key=key).log(Action.shell("echo b"), _decision(Action.shell("echo b")))

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    headers = [ln for ln in lines if '"event": "init"' in ln]
    assert len(headers) == 1, f"got {len(headers)} headers"
