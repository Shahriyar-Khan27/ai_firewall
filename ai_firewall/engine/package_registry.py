"""SBOM-style validation for AI-suggested package installs.

When an AI runs `pip install <pkg>`, `npm install <pkg>`, etc., it sometimes
hallucinates a name or asks for a typosquat that a malicious actor already
registered. This module checks the public registry to verify the package
actually exists, plus a lightweight Levenshtein check against a frozen list
of popular packages to catch one-character squats.

Lookups are cached in `~/.ai-firewall/registry-cache.sqlite` (TTL 24h) so
repeated installs across a session don't hammer the registries.

All network calls are best-effort:
  - on a network failure, we return `RegistryResult(checked=False, ...)`
    and skip the typosquat check rather than fail-closed (a slow-but-real
    registry shouldn't make the firewall block legitimate work).
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal


Manager = Literal["npm", "pypi", "cargo", "rubygems"]


@dataclass(frozen=True)
class RegistryResult:
    name: str
    manager: Manager
    exists: bool                # confirmed present on registry?
    checked: bool               # did we successfully reach the registry?
    typosquat_of: str | None    # name of a popular package this is one-edit away from
    cached: bool = False        # served from local cache?


_DEFAULT_DB_PATH = Path.home() / ".ai-firewall" / "registry-cache.sqlite"
_DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class _Cache:
    """Tiny SQLite-backed cache for registry lookups."""

    def __init__(self, path: Path | None = None, ttl_seconds: int = _DEFAULT_TTL_SECONDS):
        self.path = Path(path) if path is not None else _DEFAULT_DB_PATH
        self.ttl_seconds = ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS lookups (
                manager TEXT NOT NULL,
                name    TEXT NOT NULL,
                exists_ INTEGER NOT NULL,   -- 1 = exists, 0 = absent
                checked_at REAL NOT NULL,
                PRIMARY KEY (manager, name)
            );
            """
        )
        self._conn.commit()

    def get(self, manager: Manager, name: str) -> bool | None:
        row = self._conn.execute(
            "SELECT exists_, checked_at FROM lookups WHERE manager=? AND name=?",
            (manager, name),
        ).fetchone()
        if row is None:
            return None
        exists_, checked_at = row
        if time.time() - checked_at > self.ttl_seconds:
            return None
        return bool(exists_)

    def put(self, manager: Manager, name: str, exists: bool) -> None:
        self._conn.execute(
            """
            INSERT INTO lookups (manager, name, exists_, checked_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(manager, name) DO UPDATE SET
                exists_ = excluded.exists_,
                checked_at = excluded.checked_at
            """,
            (manager, name, 1 if exists else 0, time.time()),
        )
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_CACHE: _Cache | None = None


def _cache() -> _Cache:
    global _DEFAULT_CACHE
    if _DEFAULT_CACHE is None:
        _DEFAULT_CACHE = _Cache()
    return _DEFAULT_CACHE


def verify(
    name: str,
    manager: Manager,
    *,
    cache: _Cache | None = None,
    timeout_s: float = 4.0,
    popular_packages: dict[str, list[str]] | None = None,
) -> RegistryResult:
    """Check whether `name` exists on `manager`'s public registry."""
    name = (name or "").strip()
    if not name:
        return RegistryResult(name=name, manager=manager, exists=False, checked=False, typosquat_of=None)

    c = cache if cache is not None else _cache()
    cached_exists = c.get(manager, name)
    if cached_exists is not None:
        squat = _typosquat_of(name, manager, popular_packages)
        return RegistryResult(
            name=name,
            manager=manager,
            exists=cached_exists,
            checked=True,
            typosquat_of=squat,
            cached=True,
        )

    url = _registry_url(manager, name)
    if url is None:
        return RegistryResult(name=name, manager=manager, exists=False, checked=False, typosquat_of=None)

    exists, checked = _http_exists(url, timeout_s=timeout_s)
    if checked:
        c.put(manager, name, exists)
    squat = _typosquat_of(name, manager, popular_packages)
    return RegistryResult(
        name=name,
        manager=manager,
        exists=exists,
        checked=checked,
        typosquat_of=squat,
        cached=False,
    )


def _registry_url(manager: Manager, name: str) -> str | None:
    if manager == "npm":
        # npm registry serves a JSON document for valid package names
        return f"https://registry.npmjs.org/{urllib.parse.quote(name)}"
    if manager == "pypi":
        return f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    if manager == "cargo":
        return f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}"
    if manager == "rubygems":
        return f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json"
    return None


def _http_exists(url: str, *, timeout_s: float) -> tuple[bool, bool]:
    """GET the registry URL. Return (exists, checked)."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "ai-execution-firewall"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (200 <= resp.status < 300, True)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (False, True)
        # 5xx / 403 / etc. — registry was reached but didn't tell us cleanly
        return (False, False)
    except (urllib.error.URLError, TimeoutError, OSError):
        return (False, False)


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------

def _typosquat_of(
    name: str,
    manager: Manager,
    popular: dict[str, list[str]] | None = None,
) -> str | None:
    """If `name` is one Levenshtein edit away from a popular package, return that package."""
    if popular is None:
        popular = _load_popular_packages()
    candidates = popular.get(manager) or []
    if not candidates or not name:
        return None
    n = name.lower()
    if n in candidates:
        return None
    for cand in candidates:
        if abs(len(cand) - len(n)) > 1:
            continue
        if _edit_distance_le_1(n, cand):
            return cand
    return None


def _edit_distance_le_1(a: str, b: str) -> bool:
    """Return True iff `a` and `b` differ by at most one insertion, deletion,
    substitution, OR adjacent-character transposition (Damerau-Levenshtein ≤ 1).

    Transpositions matter for typosquat detection — `djnago` and `requets`
    are common AI hallucinations that pure Levenshtein at distance ≤ 1 misses.
    """
    if a == b:
        return False  # exact matches aren't typosquats

    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False

    # Same length — also check for an adjacent-char transposition
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True  # one substitution
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            if a[i] == b[j] and a[j] == b[i]:
                return True  # adjacent transposition
        return False

    # Different lengths by 1 — one insertion or deletion
    short, long_ = (a, b) if la < lb else (b, a)
    i = j = 0
    diffs = 0
    while i < len(short) and j < len(long_):
        if short[i] != long_[j]:
            diffs += 1
            if diffs > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return diffs <= 1


def _load_popular_packages() -> dict[str, list[str]]:
    """Load the shipped frozen list of popular packages per manager."""
    path = Path(__file__).resolve().parent.parent / "config" / "popular_packages.json"
    try:
        return {k: [n.lower() for n in v] for k, v in json.loads(path.read_text(encoding="utf-8")).items()}
    except (OSError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# Convenience: extract package list from a `pip install …` / `npm install …` command
# ---------------------------------------------------------------------------

# Args we should skip when reading off of `pip install`, `npm install`, etc.
_SKIP_ARGS = {
    "-r", "--requirement",
    "-c", "--constraint",
    "-e", "--editable",
    "--upgrade", "-U",
    "--user",
    "--no-deps",
    "--quiet", "-q",
    "--verbose", "-v",
    "-D", "--dev", "--save-dev",
    "--global", "-g",
    "--save", "--save-optional",
    "--exact",
    "--prod", "--production",
    "--no-save",
    "--frozen-lockfile",
}


def extract_packages(verb: str, args: Iterable[str]) -> tuple[Manager | None, list[str]]:
    """Inspect a parsed shell command (e.g. `pip install <args>`) and return
    (manager, [package_names]). Returns (None, []) for non-installer verbs.

    Handles common shapes:
      pip install foo bar==1.2.3 baz
      pip3 install foo
      npm install foo bar
      yarn add foo
      pnpm add foo
      uv add foo
      cargo install foo
      gem install foo
    """
    verb = (verb or "").lower()
    args = list(args or [])
    if not args:
        return (None, [])

    manager: Manager | None = None
    sub = args[0].lower() if args else ""

    if verb in ("pip", "pip3", "uv") and sub in ("install", "add"):
        manager = "pypi"
    elif verb in ("npm", "pnpm", "bun") and sub in ("install", "i", "add"):
        manager = "npm"
    elif verb == "yarn" and sub in ("add", "install"):
        manager = "npm"
    elif verb == "cargo" and sub == "install":
        manager = "cargo"
    elif verb == "gem" and sub == "install":
        manager = "rubygems"

    if manager is None:
        return (None, [])

    pkgs: list[str] = []
    skip_next = False
    flag_with_value = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable"}
    for tok in args[1:]:
        if skip_next:
            skip_next = False
            continue
        if not tok or tok.startswith("-"):
            if tok in flag_with_value:
                skip_next = True
            continue
        # Skip URLs and local paths
        if tok.startswith(("http://", "https://", "file://", "git+", "./", "../", "/")):
            continue

        # Version-spec strip. npm scoped packages start with `@scope/name` and
        # may carry a version with a SECOND `@`: `@scope/name@1.0`. Don't split
        # the leading `@`.
        if tok.startswith("@"):
            second_at = tok.find("@", 1)
            if second_at > 0:
                tok = tok[:second_at]
        else:
            for sep in ("==", ">=", "<=", "~=", "!=", ">", "<", "@"):
                if sep in tok:
                    tok = tok.split(sep, 1)[0]
                    break

        # Validate: package names should be non-empty, no path-like content.
        # Scoped npm packages (`@scope/name`) are valid and contain a single `/`.
        # Reject anything that looks like a filesystem path (already filtered
        # by the URL/path skip above for `./`, `../`, leading `/`, etc.).
        if not tok:
            continue
        if tok.lstrip("@") == "":
            continue  # bare `@` or `@@` is not a package
        # Tolerate one `/` for npm scoped packages; reject deeper paths
        if tok.count("/") > 1:
            continue
        if "/" in tok and not tok.startswith("@"):
            continue  # `foo/bar` without `@` is a path, not a package
        pkgs.append(tok)

    return (manager, pkgs)


