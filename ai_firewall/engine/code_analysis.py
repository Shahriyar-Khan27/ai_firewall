from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

_AUTH_KEYWORDS = (
    "auth",
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "api_key",
    "apikey",
    "private_key",
    "encrypt",
    "decrypt",
    "permission",
    "authorize",
    "authenticate",
)

_TEST_PATH_RE = re.compile(r"(^|[\\/])(tests?|__tests__)([\\/]|$)|(^|[\\/])test_[^\\/]+\.py$|_test\.py$", re.IGNORECASE)


@dataclass(frozen=True)
class CodeFindings:
    findings: tuple[str, ...]
    severity: str  # "none" | "minor" | "major"


def analyze(path: Path | None, old_text: str, new_text: str) -> CodeFindings:
    """Compare old vs proposed file content and surface risky patterns.

    Returns findings + a coarse severity. Best-effort — never raises on
    syntax errors; falls back to text-only checks.
    """
    findings: list[str] = []
    severity = "none"

    is_test_file = bool(path and _TEST_PATH_RE.search(str(path)))
    if is_test_file:
        findings.append("edits a test file")
        severity = _bump(severity, "minor")

    # Auth-keyword detection works for any text file.
    auth_hits = _auth_hits(old_text, new_text)
    if auth_hits:
        findings.append(f"touches sensitive identifiers: {', '.join(sorted(auth_hits)[:5])}")
        severity = _bump(severity, "major")

    # AST-based checks: only meaningful for Python sources.
    if path is not None and str(path).endswith(".py"):
        ast_findings, ast_sev = _python_ast_findings(old_text, new_text)
        findings.extend(ast_findings)
        severity = _bump(severity, ast_sev)

    if old_text and not new_text.strip():
        findings.append("replaces file with empty content")
        severity = _bump(severity, "major")

    return CodeFindings(findings=tuple(findings), severity=severity)


def _auth_hits(old_text: str, new_text: str) -> set[str]:
    text = (old_text or "") + "\n" + (new_text or "")
    text_lower = text.lower()
    return {kw for kw in _AUTH_KEYWORDS if kw in text_lower}


def _python_ast_findings(old_text: str, new_text: str) -> tuple[list[str], str]:
    findings: list[str] = []
    severity = "none"

    old_tree = _parse(old_text)
    new_tree = _parse(new_text)
    if old_tree is None and new_tree is None:
        return findings, severity
    if new_tree is None:
        findings.append("proposed content has Python syntax errors")
        return findings, "major"

    old_funcs = _top_level_names(old_tree, ast.FunctionDef) | _top_level_names(old_tree, ast.AsyncFunctionDef)
    new_funcs = _top_level_names(new_tree, ast.FunctionDef) | _top_level_names(new_tree, ast.AsyncFunctionDef)
    old_classes = _top_level_names(old_tree, ast.ClassDef)
    new_classes = _top_level_names(new_tree, ast.ClassDef)

    removed_funcs = sorted(old_funcs - new_funcs)
    removed_classes = sorted(old_classes - new_classes)
    removed_tests = [n for n in removed_funcs if n.startswith("test_")]

    if removed_tests:
        findings.append(f"removes test function(s): {', '.join(removed_tests[:5])}")
        severity = _bump(severity, "major")
    elif removed_funcs:
        findings.append(f"removes function(s): {', '.join(removed_funcs[:5])}")
        severity = _bump(severity, "major")

    if removed_classes:
        findings.append(f"removes class(es): {', '.join(removed_classes[:5])}")
        severity = _bump(severity, "major")

    return findings, severity


def _parse(source: str) -> ast.AST | None:
    if not source:
        return None
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _top_level_names(tree: ast.AST, kind: type) -> set[str]:
    if not isinstance(tree, ast.Module):
        return set()
    return {node.name for node in tree.body if isinstance(node, kind)}


_RANK = {"none": 0, "minor": 1, "major": 2}


def _bump(current: str, new: str) -> str:
    return new if _RANK[new] > _RANK[current] else current
