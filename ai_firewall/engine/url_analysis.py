from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse


_DESTRUCTIVE_METHODS = {"DELETE"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "MERGE"}
_READ_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

_SAFE_SCHEMES = {"http", "https"}
_LOCAL_SCHEMES = {"file", "ftp", "data", "javascript", "gopher"}

_METADATA_HOSTS = {
    "169.254.169.254",      # AWS / GCP / Azure metadata
    "metadata.google.internal",
    "metadata.azure.com",
}

_SECRET_PARAM_KEYS = re.compile(
    r"^(api[_-]?key|apikey|token|access[_-]?token|secret|password|auth)$",
    re.IGNORECASE,
)

_DESTRUCTIVE_PATH_HINTS = (
    "/admin/",
    "/delete",
    "/destroy",
    "/reset",
    "/wipe",
    "/purge",
    "/drop",
)


@dataclass(frozen=True)
class UrlAnalysis:
    method: str
    scheme: str
    host: str
    port: int | None
    path: str
    has_userinfo: bool
    is_private_ip: bool
    is_metadata_host: bool
    is_unsafe_scheme: bool
    secret_query_params: tuple[str, ...]
    destructive_path: bool
    findings: tuple[str, ...]
    severity: str  # "none" | "minor" | "major" | "critical"
    parse_ok: bool


def analyze(method: str, url: str) -> UrlAnalysis:
    """Best-effort URL classification. Never raises."""
    method = (method or "GET").upper()

    if not url or not url.strip():
        return UrlAnalysis(
            method=method, scheme="", host="", port=None, path="",
            has_userinfo=False, is_private_ip=False, is_metadata_host=False,
            is_unsafe_scheme=False, secret_query_params=(), destructive_path=False,
            findings=("empty URL",), severity="major", parse_ok=False,
        )

    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return UrlAnalysis(
            method=method, scheme="", host="", port=None, path="",
            has_userinfo=False, is_private_ip=False, is_metadata_host=False,
            is_unsafe_scheme=False, secret_query_params=(), destructive_path=False,
            findings=("URL failed to parse",), severity="major", parse_ok=False,
        )

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path or ""
    findings: list[str] = []
    severity = "none"

    has_userinfo = bool(parsed.username or parsed.password)
    if has_userinfo:
        findings.append("URL embeds credentials in userinfo (user:pass@host)")
        severity = _bump(severity, "major")

    is_unsafe_scheme = False
    if not scheme:
        findings.append("URL has no scheme")
        severity = _bump(severity, "minor")
    elif scheme in _LOCAL_SCHEMES:
        is_unsafe_scheme = True
        findings.append(f"non-HTTP scheme `{scheme}` — possible LFI/exfil")
        severity = _bump(severity, "major")
    elif scheme not in _SAFE_SCHEMES:
        is_unsafe_scheme = True
        findings.append(f"unusual scheme `{scheme}`")
        severity = _bump(severity, "minor")

    is_private_ip = _is_private(host)
    if is_private_ip:
        findings.append(f"host `{host}` is private/loopback — possible SSRF")
        severity = _bump(severity, "major")

    is_metadata_host = host in _METADATA_HOSTS or (host == "169.254.169.254")
    if is_metadata_host:
        findings.append(f"host `{host}` is a cloud metadata endpoint — credential exfil risk")
        severity = _bump(severity, "critical")

    secret_params: list[str] = []
    if parsed.query:
        for k, _v in parse_qsl(parsed.query, keep_blank_values=True):
            if _SECRET_PARAM_KEYS.match(k):
                secret_params.append(k)
        if secret_params:
            findings.append(f"secrets in query string: {', '.join(secret_params)}")
            severity = _bump(severity, "major")

    destructive_path = any(hint in path.lower() for hint in _DESTRUCTIVE_PATH_HINTS)
    if destructive_path and method in _WRITE_METHODS | _DESTRUCTIVE_METHODS:
        findings.append("destructive-sounding URL path")
        severity = _bump(severity, "major")

    return UrlAnalysis(
        method=method,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        has_userinfo=has_userinfo,
        is_private_ip=is_private_ip,
        is_metadata_host=is_metadata_host,
        is_unsafe_scheme=is_unsafe_scheme,
        secret_query_params=tuple(secret_params),
        destructive_path=destructive_path,
        findings=tuple(findings),
        severity=severity,
        parse_ok=True,
    )


def primary_intent(method: str) -> str:
    """Reduce HTTP method to API_READ / API_WRITE / API_DESTRUCTIVE."""
    method = (method or "GET").upper()
    if method in _DESTRUCTIVE_METHODS:
        return "API_DESTRUCTIVE"
    if method in _WRITE_METHODS:
        return "API_WRITE"
    if method in _READ_METHODS:
        return "API_READ"
    return "API_WRITE"  # unknown verbs: treat conservatively


def _is_private(host: str) -> bool:
    if not host:
        return False
    if host in {"localhost", "ip6-localhost", "ip6-loopback"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


_RANK = {"none": 0, "minor": 1, "major": 2, "critical": 3}


def _bump(current: str, new: str) -> str:
    return new if _RANK[new] > _RANK[current] else current
