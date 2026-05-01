"""PII (Personally Identifiable Information) scanner.

Sibling to `secret_scan.py` — same shape, different patterns. Detects:
  - email addresses
  - US Social Security numbers (validated against publicly-known invalid blocks)
  - credit card numbers (Luhn-validated to cut false positives)
  - phone numbers (E.164 + common US formats)
  - IBAN-style international bank account numbers
  - high-entropy tokens >= 32 chars (catch-all for opaque IDs)

Used by:
  - `Action.api` body + headers via impact._api_impact (auto-applies, alongside secret_scan)
  - `guard scan "<text>"` for ad-hoc one-off use ("did I just paste a key?")
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Patterns — major / minor severity per type
# ---------------------------------------------------------------------------

# Email address — standard RFC-ish pattern (intentionally permissive on TLDs)
_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"
)

# US SSN — three groups separated by hyphens, no all-zero areas/groups
_SSN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Credit card-ish — 13-19 digits with optional spaces/hyphens. Luhn check below.
_CC_CANDIDATE = re.compile(r"\b(?:\d[\s\-]?){12,18}\d\b")

# E.164 phone (international form)
_PHONE_E164 = re.compile(r"(?<!\d)\+\d{1,3}[\s\-]?\d{4,14}(?!\d)")

# US-formatted phone: (123) 456-7890, 123-456-7890
_PHONE_US = re.compile(r"(?<!\d)\(?[2-9]\d{2}\)?[\s\-]\d{3}[\s\-]\d{4}(?!\d)")

# IBAN — country code (2) + check digits (2) + 11-30 alphanumeric chars
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

# High-entropy opaque tokens (catch-all for things like access tokens, bearer
# tokens, session keys). Heuristic only — flagged as "minor" so it doesn't
# completely overwhelm a scan.
_HIGH_ENTROPY = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


_SEV_RANK = {"none": 0, "minor": 1, "major": 2, "critical": 3}


@dataclass(frozen=True)
class PIIFindings:
    findings: tuple[str, ...]
    severity: str  # "none" | "minor" | "major" | "critical"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(text: str) -> PIIFindings:
    """Best-effort PII detection. Never raises."""
    if not text:
        return PIIFindings((), "none")

    findings: list[str] = []
    severity = "none"

    # Email
    emails = set(_EMAIL.findall(text))
    if emails:
        findings.append(f"PII: email address ({len(emails)} found)")
        severity = _bump(severity, "major")

    # SSN
    ssns = set(_SSN.findall(text))
    if ssns:
        findings.append(f"PII: US SSN detected ({len(ssns)} found)")
        severity = _bump(severity, "critical")

    # Credit cards (Luhn)
    cc_hits = []
    for m in _CC_CANDIDATE.findall(text):
        digits = re.sub(r"\D", "", m)
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            cc_hits.append(digits)
    if cc_hits:
        findings.append(f"PII: credit-card number ({len(set(cc_hits))} Luhn-valid)")
        severity = _bump(severity, "critical")

    # Phone numbers
    phones = set(_PHONE_E164.findall(text)) | set(_PHONE_US.findall(text))
    if phones:
        findings.append(f"PII: phone number ({len(phones)} found)")
        severity = _bump(severity, "major")

    # IBAN — `[A-Z]{2}\d{2}` country/check prefix is strong specificity already.
    # Filter to known country-code prefixes to cut false positives from random
    # alphanumeric blobs that happen to start with two letters + two digits.
    iban_country_codes = {
        "AD", "AE", "AT", "AZ", "BA", "BE", "BG", "BH", "BR", "BY", "CH", "CR",
        "CY", "CZ", "DE", "DK", "DO", "EE", "EG", "ES", "FI", "FO", "FR", "GB",
        "GE", "GI", "GL", "GR", "GT", "HR", "HU", "IE", "IL", "IS", "IT", "JO",
        "KW", "KZ", "LB", "LC", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK",
        "MR", "MT", "MU", "NL", "NO", "PK", "PL", "PS", "PT", "QA", "RO", "RS",
        "SA", "SC", "SE", "SI", "SK", "SM", "ST", "SV", "TL", "TN", "TR", "UA",
        "VA", "VG", "XK",
    }
    ibans = [c for c in _IBAN.findall(text) if c[:2] in iban_country_codes]
    if ibans:
        findings.append(f"PII: IBAN account number ({len(set(ibans))} found)")
        severity = _bump(severity, "critical")

    # High-entropy opaque tokens — minor signal only, and only if nothing
    # bigger already fired (avoid spammy findings)
    if not findings:
        big = [
            t for t in _HIGH_ENTROPY.findall(text)
            if _shannon_entropy(t) > 3.5
        ]
        if big:
            findings.append(f"PII: high-entropy opaque token(s) ({len(set(big))} found)")
            severity = _bump(severity, "minor")

    return PIIFindings(findings=tuple(findings), severity=severity)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _luhn_valid(digits: str) -> bool:
    """Luhn checksum for credit-card validation. Cuts ~90% of false positives."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _shannon_entropy(s: str) -> float:
    """Approximate entropy in bits/char. Hex strings ≈ 4.0; base64 ≈ 5.0+."""
    if not s:
        return 0.0
    from collections import Counter
    import math

    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _bump(current: str, new: str) -> str:
    return new if _SEV_RANK[new] > _SEV_RANK[current] else current
