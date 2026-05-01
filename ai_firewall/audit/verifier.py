"""Audit-log verification.

Reads a JSONL audit log and confirms every record's HMAC signature still
validates against the configured key. Reports tampered or unsigned records.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ai_firewall.audit.logger import _canonical_bytes, _fingerprint, _resolve_hmac_key, _sign


@dataclass
class VerifyReport:
    total: int = 0
    valid: int = 0
    unsigned: int = 0
    tampered_indices: list[int] = field(default_factory=list)
    malformed_indices: list[int] = field(default_factory=list)
    header_key_fingerprint: str | None = None
    fingerprint_mismatch: bool = False

    @property
    def ok(self) -> bool:
        return (
            not self.tampered_indices
            and not self.malformed_indices
            and not self.fingerprint_mismatch
        )


def verify(path: Path | str, key: bytes | None = None) -> VerifyReport:
    """Verify every record in `path`. Returns a structured report.

    Resolution: if `key` is None, falls back to the same env / ~/.ai-firewall
    discovery the AuditLogger uses.
    """
    p = Path(path)
    report = VerifyReport()
    if not p.exists():
        return report

    if key is None:
        key = _resolve_hmac_key()
    if key is None:
        # No key available — every record will appear unsigned.
        for line in _iter_lines(p):
            report.total += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                report.malformed_indices.append(report.total - 1)
                continue
            if "signature" not in rec:
                report.unsigned += 1
            else:
                # We have a sig but no key — treat as tampered (untrustable)
                report.tampered_indices.append(report.total - 1)
        return report

    expected_fp = _fingerprint(key)

    for idx, line in enumerate(_iter_lines(p)):
        report.total += 1
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            report.malformed_indices.append(idx)
            continue

        # Header record: stash and compare key fingerprint.
        if rec.get("event") == "init":
            report.header_key_fingerprint = rec.get("key_fingerprint")
            if report.header_key_fingerprint and report.header_key_fingerprint != expected_fp:
                report.fingerprint_mismatch = True

        sig = rec.get("signature")
        if not sig:
            report.unsigned += 1
            continue

        expected_sig = _sign(rec, key)
        if hmac_compare(sig, expected_sig):
            report.valid += 1
        else:
            report.tampered_indices.append(idx)

    return report


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string compare (don't leak via early return)."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= ord(x) ^ ord(y)
    return diff == 0


def _iter_lines(p: Path):
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line
