from __future__ import annotations

import re
from dataclasses import dataclass


# Known token shapes. Each entry: (label, regex, severity).
# Patterns favour high-confidence matches; we'd rather underflag than alarm on
# every base64-looking string in a request body.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("AWS secret access key (assignment)",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "critical"),
    ("GitHub PAT (ghp_)", re.compile(r"ghp_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub OAuth token (gho_)", re.compile(r"gho_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub user-to-server token (ghu_)", re.compile(r"ghu_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub server-to-server token (ghs_)", re.compile(r"ghs_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub refresh token (ghr_)", re.compile(r"ghr_[A-Za-z0-9]{36,}"), "critical"),
    ("Slack token", re.compile(r"xox[abposr]-[A-Za-z0-9-]{10,}"), "critical"),
    ("Stripe live key", re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "critical"),
    ("Stripe restricted key", re.compile(r"rk_live_[A-Za-z0-9]{24,}"), "critical"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical"),
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}"), "major"),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "critical"),
    ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "major"),
]

# High-signal field names whose presence alone is suspicious in a request body.
# We require a value to follow (`= "..."` or `: "..."`) so plain mentions in prose don't trigger.
# The value may be a quoted string with any content (≥6 chars) OR an unquoted token (≥8 chars
# of base64/identifier-style chars).
_FIELD_RE = re.compile(
    r"""(?ix)
    (?:^|[\s,{;\[])
    ["']?
    (
        password | passwd | pwd
      | api[_-]?key
      | secret(?:[_-]?key)?
      | access[_-]?token
      | refresh[_-]?token
      | private[_-]?key
      | client[_-]?secret
      | bearer
    )
    ["']?
    \s*[:=]\s*
    (?:
        ['"][^'"\n]{6,}['"]
      | [A-Za-z0-9+/=_\-]{8,}
    )
    """
)

_SEV_RANK = {"none": 0, "minor": 1, "major": 2, "critical": 3}


@dataclass(frozen=True)
class SecretFindings:
    findings: tuple[str, ...]
    severity: str  # "none" | "major" | "critical"


def scan(text: str) -> SecretFindings:
    """Best-effort secret detection. Returns labelled findings + max severity."""
    if not text:
        return SecretFindings((), "none")

    seen: dict[str, str] = {}  # label → severity (dedupe by label)

    for label, pat, sev in _PATTERNS:
        if pat.search(text):
            seen[label] = sev

    for match in _FIELD_RE.finditer(text):
        field = match.group(1).lower().replace("-", "_").replace("__", "_")
        label = f"sensitive field assignment: `{field}`"
        # Keep the highest sev we've seen for this label; default to major.
        if label not in seen:
            seen[label] = "major"

    if not seen:
        return SecretFindings((), "none")

    # Use distinct phrasing per severity so the risk analyzer can match them
    # precisely without forcing every leak up to CRITICAL.
    findings_list: list[str] = []
    for label, sev in seen.items():
        if sev == "critical":
            findings_list.append(f"high-confidence secret leak: {label}")
        else:
            findings_list.append(f"possible secret in payload: {label}")
    findings = tuple(findings_list)
    severity = max(seen.values(), key=lambda s: _SEV_RANK[s])
    return SecretFindings(findings=findings, severity=severity)
