from __future__ import annotations

import os
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ai_firewall.core.action import Action, IntentType
from ai_firewall.engine import (
    code_analysis,
    diff as diff_mod,
    git_check,
    package_registry,
    pii_scan,
    secret_scan,
    sql_analysis,
    url_analysis,
)
from ai_firewall.parser.shell_ast import parse as parse_shell_ast

_POSIX_SHLEX = os.name != "nt"


@dataclass(frozen=True)
class Impact:
    files_affected: int = 0
    bytes_affected: int = 0
    paths: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""
    diff: str = ""
    lines_added: int = 0
    lines_removed: int = 0
    code_findings: tuple[str, ...] = field(default_factory=tuple)
    git: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["paths"] = list(self.paths)
        d["code_findings"] = list(self.code_findings)
        return d

    def summary(self) -> str:
        if self.files_affected == 0 and not self.notes and not self.code_findings and not self.git:
            return "no measurable impact"
        parts = []
        if self.files_affected:
            parts.append(f"{self.files_affected} file(s)")
        if self.bytes_affected:
            parts.append(_human_bytes(self.bytes_affected))
        if self.lines_added or self.lines_removed:
            parts.append(f"+{self.lines_added}/-{self.lines_removed} lines")
        if self.notes:
            parts.append(self.notes)
        return ", ".join(parts) if parts else "no measurable impact"


def estimate(action: Action, intent: IntentType, *, base_cwd: Path | None = None) -> Impact:
    """Best-effort dry-run. Never executes the action."""
    cwd = base_cwd or Path(action.context.get("cwd") or Path.cwd())

    if intent is IntentType.FILE_DELETE:
        targets = _delete_targets(action, cwd)
        base = _walk_impact(targets)
        git = git_check.inspect(targets, cwd) if targets else {}
        if git:
            return _replace(base, git=git)
        return base

    if intent in (IntentType.FILE_WRITE, IntentType.CODE_MODIFY):
        return _write_impact(action, cwd)

    if intent is IntentType.FILE_READ:
        path = _resolve(action.payload.get("path"), cwd)
        if path and path.exists() and path.is_file():
            return Impact(files_affected=1, bytes_affected=path.stat().st_size, paths=(str(path),))
        return Impact(notes="reads a file")

    if intent in (IntentType.DB_READ, IntentType.DB_WRITE, IntentType.DB_DESTRUCTIVE):
        return _db_impact(action)

    # Shell actions get the SBOM + egress impact regardless of which intent
    # the AST classifier picked (curl is API_READ but action.type is "shell";
    # we still want url_analysis findings on the curl URL).
    if action.type == "shell":
        return _shell_impact(action)

    if intent in (IntentType.API_READ, IntentType.API_WRITE, IntentType.API_DESTRUCTIVE):
        return _api_impact(action)

    if intent is IntentType.NETWORK_EGRESS and action.type == "shell":
        return _shell_impact(action)

    return Impact(notes="impact not modelled for this intent")


def _shell_impact(action: Action) -> Impact:
    """Surface SBOM and egress findings for shell commands.

    Two channels:
      - `pip / npm / yarn / cargo / gem install <pkg>` → registry validation
      - `curl / wget <URL>` → run the URL through url_analysis (same gate as `guard api`)
    """
    cmd = (action.payload.get("cmd") or "").strip()
    if not cmd:
        return Impact()

    parsed = parse_shell_ast(cmd)
    findings: list[str] = []
    paths: list[str] = []

    for ec in parsed.commands:
        verb = (ec.verb or "").lower()
        args_list = list(ec.args)

        # SBOM channel
        manager, packages = package_registry.extract_packages(ec.verb, args_list)
        if manager and packages:
            for pkg in packages:
                paths.append(f"{manager}:{pkg}")
                try:
                    result = package_registry.verify(pkg, manager)
                except Exception:
                    continue
                if result.typosquat_of:
                    findings.append(
                        f"package install: '{pkg}' is one edit away from popular package "
                        f"'{result.typosquat_of}' (possible typosquat / hallucinated name)"
                    )
                elif result.checked and not result.exists:
                    findings.append(
                        f"package install: '{pkg}' not found on {manager} registry "
                        f"(hallucinated name?)"
                    )
            continue

        # Egress channel: curl / wget / etc.
        from ai_firewall.engine.intent import (
            _HTTP_EGRESS_VERBS,
            _RAW_NETWORK_VERBS,
            _FILE_TRANSFER_VERBS,
            _extract_egress_url,
            _http_method_from_curl_args,
        )
        if verb in _HTTP_EGRESS_VERBS:
            url = _extract_egress_url(verb, args_list)
            if url:
                method = _http_method_from_curl_args(args_list)
                paths.append(f"{method} {url}")
                a = url_analysis.analyze(method, url)
                findings.extend(a.findings)
            else:
                findings.append(f"egress: {verb} called without an http(s) URL — possibly using stdin / config")
            continue

        if verb in _RAW_NETWORK_VERBS or verb in _FILE_TRANSFER_VERBS:
            target = " ".join(args_list[:4])
            paths.append(f"{verb} {target}")
            findings.append(
                f"raw network egress: `{verb}` opens a non-HTTP socket — bypasses url_analysis gating"
            )
            continue

    if not findings and not paths:
        return Impact()

    notes = ", ".join(paths[:6]) if paths else ""
    return Impact(
        files_affected=0,
        bytes_affected=0,
        paths=tuple(paths[:8]),
        notes=notes,
        code_findings=tuple(findings),
    )


def _api_impact(action: Action) -> Impact:
    method = action.payload.get("method") or "GET"
    url = action.payload.get("url") or ""
    a = url_analysis.analyze(method, url)
    if a.parse_ok:
        notes = f"{a.method} {a.scheme}://{a.host}{a.path or ''}".rstrip()
    else:
        notes = "URL did not parse"
    body = action.payload.get("body") or ""
    bytes_affected = len(body.encode("utf-8")) if isinstance(body, str) else 0

    # Scan body and Authorization-style headers for leaked secrets.
    findings = list(a.findings)
    headers = action.payload.get("headers") or {}
    auth_header_text = "\n".join(
        f"{k}: {v}" for k, v in headers.items() if k.lower() in {"authorization", "x-api-key", "x-auth-token"}
    )
    scan_target = "\n".join(filter(None, [body if isinstance(body, str) else "", auth_header_text]))
    if scan_target:
        sec = secret_scan.scan(scan_target)
        findings.extend(sec.findings)
        # DLP: PII scanner runs on the same text. Findings phrased "PII: ..."
        # so risk.apply_impact can route them via the existing major/critical signal lists.
        pii = pii_scan.scan(scan_target)
        findings.extend(pii.findings)

    return Impact(
        files_affected=0,
        bytes_affected=bytes_affected,
        paths=(a.host,) if a.host else (),
        notes=notes,
        code_findings=tuple(findings),
    )


def _db_impact(action: Action) -> Impact:
    sql = action.payload.get("sql") or ""
    dialect = action.payload.get("dialect", "generic")
    a = sql_analysis.analyze(sql, dialect=dialect)
    notes = (
        f"{', '.join(a.statements)} on {', '.join(a.tables) or 'no tables resolved'}"
        if a.parse_ok
        else "SQL did not parse"
    )
    # We reuse code_findings as the generic "structured findings" channel,
    # so the existing risk/prompt/audit plumbing surfaces SQL findings too.
    return Impact(
        files_affected=0,
        bytes_affected=0,
        paths=tuple(a.tables[:8]),
        notes=notes,
        code_findings=a.findings,
    )


def _write_impact(action: Action, cwd: Path) -> Impact:
    path = _resolve(action.payload.get("path"), cwd)
    if path is None:
        return Impact(notes="path unknown")

    new_content = action.payload.get("content") or ""
    new_bytes = len(new_content.encode("utf-8"))
    exists = path.exists() and path.is_file()
    notes = "overwrites existing file" if exists else "creates new file"

    diff_res = diff_mod.compute(path, new_content)

    old_text = ""
    if exists:
        try:
            old_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            old_text = ""
    findings = code_analysis.analyze(path, old_text, new_content)

    git = git_check.inspect([path], cwd)

    return Impact(
        files_affected=1,
        bytes_affected=max(new_bytes, path.stat().st_size) if exists else new_bytes,
        paths=(str(path),),
        notes=notes,
        diff=diff_res.diff,
        lines_added=diff_res.lines_added,
        lines_removed=diff_res.lines_removed,
        code_findings=findings.findings,
        git=git,
    )


def _replace(base: Impact, **changes) -> Impact:
    data = {
        "files_affected": base.files_affected,
        "bytes_affected": base.bytes_affected,
        "paths": base.paths,
        "notes": base.notes,
        "diff": base.diff,
        "lines_added": base.lines_added,
        "lines_removed": base.lines_removed,
        "code_findings": base.code_findings,
        "git": base.git,
    }
    data.update(changes)
    return Impact(**data)


def _delete_targets(action: Action, cwd: Path) -> list[Path]:
    if action.type == "file":
        p = _resolve(action.payload.get("path"), cwd)
        return [p] if p else []

    cmd = action.payload.get("cmd") or ""
    try:
        tokens = shlex.split(cmd, posix=_POSIX_SHLEX)
    except ValueError:
        tokens = cmd.split()
    # drop the leading verb(s) and flags
    targets: list[Path] = []
    seen_verb = False
    for tok in tokens:
        if not seen_verb:
            if tok.lower() in {"sudo", "doas"}:
                continue
            seen_verb = True
            continue
        if tok.startswith("-"):
            continue
        # expand globs relative to cwd
        if any(ch in tok for ch in "*?[]"):
            try:
                matches = list(cwd.glob(tok))
            except (OSError, ValueError):
                matches = []
            targets.extend(matches)
        else:
            p = _resolve(tok, cwd)
            if p is not None:
                targets.append(p)
    return targets


def _walk_impact(paths: list[Path]) -> Impact:
    files = 0
    total = 0
    seen: list[str] = []
    for p in paths:
        if not p.exists():
            seen.append(str(p))
            continue
        seen.append(str(p))
        if p.is_file():
            files += 1
            try:
                total += p.stat().st_size
            except OSError:
                pass
        elif p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file():
                    files += 1
                    try:
                        total += sub.stat().st_size
                    except OSError:
                        pass
    return Impact(files_affected=files, bytes_affected=total, paths=tuple(seen[:8]))


def _resolve(raw: str | None, cwd: Path) -> Path | None:
    if not raw:
        return None
    p = Path(raw)
    if not p.is_absolute():
        p = cwd / p
    return p


def _human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}"
        f /= 1024
    return f"{n} B"
