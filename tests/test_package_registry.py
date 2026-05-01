"""Feature 1 — AI SBOM validation (typosquat / hallucinated package detection)."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_firewall.engine import package_registry as pr
from ai_firewall.engine.package_registry import (
    RegistryResult,
    _Cache,
    _edit_distance_le_1,
    _typosquat_of,
    extract_packages,
    verify,
)


# --- Edit distance helper ---


@pytest.mark.parametrize("a,b,expected", [
    ("requests", "requets", True),     # one deletion
    ("requests", "reqests", True),     # one deletion
    ("requests", "reuqests", True),    # one substitution at position
    ("requests", "requestss", True),   # one insertion
    ("requests", "requests", False),   # exact = NOT a typosquat
    ("requests", "django", False),     # too different
    ("react", "reactt", True),
    ("abc", "xyz", False),
    ("", "a", True),
])
def test_edit_distance_le_1(a, b, expected):
    assert _edit_distance_le_1(a, b) is expected


# --- Typosquat detection ---


def test_typosquat_catches_one_edit_squats():
    popular = {"pypi": ["requests", "django", "numpy"]}
    assert _typosquat_of("requets", "pypi", popular) == "requests"  # transposition
    assert _typosquat_of("djnago", "pypi", popular) == "django"     # transposition
    assert _typosquat_of("nupy", "pypi", popular) == "numpy"        # one deletion
    assert _typosquat_of("xyz", "pypi", popular) is None            # truly unrelated
    assert _typosquat_of("flask", "pypi", popular) is None          # not in popular list
    assert _typosquat_of("requireeeeest", "pypi", popular) is None  # too many edits from requests


def test_typosquat_ignores_exact_popular():
    popular = {"pypi": ["requests"]}
    assert _typosquat_of("requests", "pypi", popular) is None


def test_typosquat_ignores_random_unique_names():
    popular = {"pypi": ["requests", "django"]}
    assert _typosquat_of("totally-unrelated-package-xyz", "pypi", popular) is None


def test_typosquat_per_manager():
    popular = {"npm": ["react"], "pypi": ["requests"]}
    # `reactt` typosquats `react` only on npm
    assert _typosquat_of("reactt", "npm", popular) == "react"
    assert _typosquat_of("reactt", "pypi", popular) is None  # popular[pypi] doesn't include react


# --- Argument parser ---


def test_extract_pip_install():
    mgr, pkgs = extract_packages("pip", ["install", "requests", "numpy==1.24.0"])
    assert mgr == "pypi"
    assert pkgs == ["requests", "numpy"]


def test_extract_pip_skips_requirements_file():
    mgr, pkgs = extract_packages("pip", ["install", "-r", "reqs.txt", "extra-pkg"])
    assert pkgs == ["extra-pkg"]


def test_extract_pip_skips_local_paths():
    mgr, pkgs = extract_packages("pip", ["install", "./local", "remote-pkg"])
    assert pkgs == ["remote-pkg"]


def test_extract_npm_install_scoped():
    mgr, pkgs = extract_packages("npm", ["install", "@types/node", "react"])
    assert mgr == "npm"
    assert pkgs == ["@types/node", "react"]


def test_extract_npm_strips_version_after_scoped():
    mgr, pkgs = extract_packages("npm", ["install", "@types/node@18.0.0"])
    assert pkgs == ["@types/node"]


def test_extract_yarn_add():
    mgr, pkgs = extract_packages("yarn", ["add", "lodash"])
    assert mgr == "npm"
    assert pkgs == ["lodash"]


def test_extract_cargo_install():
    mgr, pkgs = extract_packages("cargo", ["install", "ripgrep"])
    assert mgr == "cargo"
    assert pkgs == ["ripgrep"]


def test_extract_non_installer_returns_empty():
    mgr, pkgs = extract_packages("echo", ["hello"])
    assert mgr is None
    assert pkgs == []


def test_extract_pip_strips_flags():
    mgr, pkgs = extract_packages("pip", ["install", "--upgrade", "pip", "--user", "setuptools"])
    assert pkgs == ["pip", "setuptools"]


# --- Cache ---


def test_cache_records_and_returns_recent(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite")
    assert cache.get("pypi", "requests") is None
    cache.put("pypi", "requests", True)
    assert cache.get("pypi", "requests") is True
    cache.close()


def test_cache_returns_none_after_ttl(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite", ttl_seconds=0)  # immediately stale
    cache.put("pypi", "requests", True)
    assert cache.get("pypi", "requests") is None
    cache.close()


# --- Verify (with mocked HTTP) ---


def test_verify_uses_cache(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite")
    cache.put("pypi", "requests", True)

    # Mock _http_exists so we can detect if the network was hit
    with patch("ai_firewall.engine.package_registry._http_exists") as mock:
        mock.return_value = (True, True)
        result = verify("requests", "pypi", cache=cache)
        assert mock.call_count == 0  # served entirely from cache
    assert result.exists is True
    assert result.cached is True
    cache.close()


def test_verify_network_404_records_absent(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite")
    with patch("ai_firewall.engine.package_registry._http_exists") as mock:
        mock.return_value = (False, True)  # checked, doesn't exist
        result = verify("hallucinated-pkg-xyz123", "pypi", cache=cache)
    assert result.exists is False
    assert result.checked is True
    cache.close()


def test_verify_network_failure_does_not_block(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite")
    with patch("ai_firewall.engine.package_registry._http_exists") as mock:
        mock.return_value = (False, False)  # network unreachable
        result = verify("requests", "pypi", cache=cache)
    assert result.checked is False
    cache.close()


def test_verify_typosquat_set_when_close_to_popular(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite")
    with patch("ai_firewall.engine.package_registry._http_exists") as mock:
        mock.return_value = (True, True)  # registry says it exists (squatter registered it)
        result = verify("requets", "pypi", cache=cache)
    assert result.typosquat_of == "requests"
    cache.close()


def test_verify_empty_name_returns_safely(tmp_path: Path):
    cache = _Cache(tmp_path / "cache.sqlite")
    result = verify("", "pypi", cache=cache)
    assert result.checked is False
    cache.close()


# --- popular packages JSON ---


def test_popular_packages_json_loads():
    """Sanity: the shipped JSON is valid and contains all 4 managers."""
    path = Path(pr.__file__).resolve().parent.parent / "config" / "popular_packages.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "pypi" in data
    assert "npm" in data
    assert "cargo" in data
    assert "rubygems" in data
    # A few sanity entries
    assert "requests" in data["pypi"]
    assert "react" in data["npm"]
