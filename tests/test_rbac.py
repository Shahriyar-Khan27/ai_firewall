"""Feature 5 — Fine-grained RBAC."""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_firewall.approval.cli_prompt import auto_approve
from ai_firewall.config.guard_toml import (
    GuardToml,
    Role,
    glob_match,
    load,
)
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.engine.rbac import RBACEngine, resolve_identity


# ---------------------------------------------------------------------------
# Glob matcher
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path,pattern,expected", [
    ("/home/u/.ssh/id_rsa", "**/.ssh/**", True),
    ("/home/u/.ssh/id_rsa", "~/.ssh/**", False),  # ~ not the same user, but home expand happens on the *pattern*
    ("./src/foo.py", "./**", True),
    ("./src/foo.py", "**/*.py", True),
    ("src/foo/bar.py", "src/**", True),
    ("src/foo/bar.py", "src/*", False),  # single * doesn't cross /
    ("src/foo.py", "src/*.py", True),
    ("a/b/c", "a/**/c", True),
    ("a/c", "a/**/c", True),  # ** matches zero components too
    ("a/b/c/d/e", "a/**/e", True),
    ("a/b/c", "x/**", False),
    ("foo/credentials.json", "**/credentials*", True),
    ("foo/bar/credentials.toml", "**/credentials*", True),
    ("foo/credentials/x.txt", "**/credentials*", False),  # last-component match
])
def test_glob_match(path: str, pattern: str, expected: bool):
    assert glob_match(path, pattern) is expected


def test_glob_match_normalizes_backslashes():
    assert glob_match("C:\\Users\\u\\.ssh\\id_rsa", "**/.ssh/**") is True


def test_glob_match_empty_inputs():
    assert glob_match("", "**") is False
    assert glob_match("foo", "") is False


# ---------------------------------------------------------------------------
# guard.toml loading + role inheritance
# ---------------------------------------------------------------------------


def _write_toml(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_load_basic_roles(tmp_path: Path):
    cfg_path = tmp_path / "guard.toml"
    _write_toml(cfg_path, """
        [identity]
        default_role = "dev"

        [roles.dev]
        allow_intents = ["*"]
        deny_files = ["~/.ssh/**"]

        [roles.admin]
        allow_intents = ["*"]
    """)
    cfg = load([cfg_path])
    assert cfg.default_role == "dev"
    assert "dev" in cfg.roles
    assert "admin" in cfg.roles
    assert cfg.roles["dev"].deny_files == ("~/.ssh/**",)


def test_load_role_inheritance(tmp_path: Path):
    cfg_path = tmp_path / "guard.toml"
    _write_toml(cfg_path, """
        [roles.dev]
        allow_intents = ["*"]
        deny_files = ["~/.ssh/**"]

        [roles."dev-junior"]
        inherits = "dev"
        deny_intents = ["FILE_DELETE", "DB_DESTRUCTIVE"]
    """)
    cfg = load([cfg_path])
    junior = cfg.roles["dev-junior"]
    # Inherits parent's deny_files
    assert junior.deny_files == ("~/.ssh/**",)
    # Adds its own deny_intents
    assert "FILE_DELETE" in junior.deny_intents


def test_load_returns_default_when_no_files():
    cfg = load([])
    assert cfg.default_role == "dev"
    assert cfg.roles == {}


def test_load_handles_corrupt_toml(tmp_path: Path):
    bad = tmp_path / "guard.toml"
    bad.write_text("not = valid = toml", encoding="utf-8")
    cfg = load([bad])
    # Skips the bad file silently
    assert cfg.default_role == "dev"


def test_load_inheritance_cycle_short_circuits(tmp_path: Path):
    cfg_path = tmp_path / "guard.toml"
    _write_toml(cfg_path, """
        [roles.a]
        inherits = "b"

        [roles.b]
        inherits = "a"
        deny_intents = ["FILE_DELETE"]
    """)
    # Should not blow up the stack.
    cfg = load([cfg_path])
    assert "a" in cfg.roles
    assert "b" in cfg.roles


def test_per_project_overrides_user(tmp_path: Path):
    user = tmp_path / "user.toml"
    project = tmp_path / "proj.toml"
    _write_toml(user, """
        [roles.dev]
        deny_files = ["~/.ssh/**"]
    """)
    _write_toml(project, """
        [roles.dev]
        deny_files = ["**/secrets/**"]
    """)
    cfg = load([user, project])
    # Project-level overrides user-level for the same field.
    assert cfg.roles["dev"].deny_files == ("**/secrets/**",)


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


def test_resolve_identity_cli_wins():
    cfg = GuardToml(default_role="ops")
    assert resolve_identity(cfg, cli_role="admin", env={}) == "admin"


def test_resolve_identity_env_beats_default():
    cfg = GuardToml(default_role="ops")
    assert resolve_identity(cfg, cli_role=None, env={"AI_FIREWALL_ROLE": "qa"}) == "qa"


def test_resolve_identity_default_role():
    cfg = GuardToml(default_role="ops")
    assert resolve_identity(cfg, cli_role=None, env={}) == "ops"


def test_resolve_identity_built_in_fallback():
    cfg = GuardToml()
    assert resolve_identity(cfg, cli_role=None, env={}) == "dev"


# ---------------------------------------------------------------------------
# RBACEngine — intent / path / mcp checks
# ---------------------------------------------------------------------------


def test_engine_unknown_role_allows_everything():
    """No roles configured = passthrough (RBAC effectively disabled)."""
    eng = RBACEngine(GuardToml())
    v = eng.check(Action.shell("rm -rf ./build"), "anything")
    assert v.decision == "ALLOW"


def test_engine_blocks_denied_intent():
    cfg = GuardToml(roles={
        "dev-junior": Role(
            name="dev-junior",
            allow_intents=("*",),
            deny_intents=("FILE_DELETE",),
        ),
    })
    eng = RBACEngine(cfg)
    v = eng.check(Action.shell("rm -rf ./build"), "dev-junior")
    assert v.decision == "DENY"
    assert "FILE_DELETE" in v.reason
    assert "dev-junior" in v.reason


def test_engine_allows_other_intents_for_denied_role():
    cfg = GuardToml(roles={
        "dev-junior": Role(
            name="dev-junior",
            allow_intents=("*",),
            deny_intents=("FILE_DELETE",),
        ),
    })
    eng = RBACEngine(cfg)
    v = eng.check(Action.shell("echo hello"), "dev-junior")
    assert v.decision == "ALLOW"


def test_engine_whitelist_intents_only_allows_listed():
    cfg = GuardToml(roles={
        "read-only": Role(
            name="read-only",
            allow_intents=("FILE_READ", "DB_READ"),
        ),
    })
    eng = RBACEngine(cfg)
    assert eng.check(Action.file("read", "/x"), "read-only").decision == "ALLOW"
    assert eng.check(Action.shell("echo hi"), "read-only").decision == "DENY"


def test_engine_deny_files_takes_precedence(tmp_path: Path):
    cfg = GuardToml(roles={
        "dev": Role(
            name="dev",
            allow_intents=("*",),
            allow_files=("**",),
            deny_files=("**/.ssh/**",),
        ),
    })
    eng = RBACEngine(cfg)
    v = eng.check(Action.file("read", "/home/u/.ssh/id_rsa"), "dev")
    assert v.decision == "DENY"
    assert ".ssh" in v.reason


def test_engine_allow_files_whitelist():
    cfg = GuardToml(roles={
        "scoped": Role(
            name="scoped",
            allow_intents=("*",),
            allow_files=("/srv/projects/**",),
        ),
    })
    eng = RBACEngine(cfg)
    assert eng.check(Action.file("read", "/srv/projects/foo.txt"), "scoped").decision == "ALLOW"
    assert eng.check(Action.file("read", "/etc/passwd"), "scoped").decision == "DENY"


def test_engine_mcp_tool_deny():
    cfg = GuardToml(roles={
        "dev": Role(
            name="dev",
            allow_intents=("*",),
            deny_mcp_tools=("postgres-prod",),
        ),
    })
    eng = RBACEngine(cfg)
    action = Action.api(method="POST", url="https://x.example/api")
    object.__setattr__(action, "context", {"mcp_tool": "postgres-prod"})
    v = eng.check(action, "dev")
    assert v.decision == "DENY"
    assert "postgres-prod" in v.reason


# ---------------------------------------------------------------------------
# Guard integration — verifies the full pipeline wiring
# ---------------------------------------------------------------------------


def _guard_with_toml(tmp_path: Path, toml_body: str, role: str | None = None) -> Guard:
    cfg_path = tmp_path / "guard.toml"
    _write_toml(cfg_path, toml_body)
    return Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_approve,
        enable_memory=False,
        enable_inheritance=False,
        enable_governance=False,
        guard_toml_path=cfg_path,
        role=role,
    )


def test_guard_blocks_dev_junior_file_delete(tmp_path: Path):
    g = _guard_with_toml(tmp_path, """
        [roles.dev]
        allow_intents = ["*"]

        [roles."dev-junior"]
        inherits = "dev"
        deny_intents = ["FILE_DELETE"]
    """, role="dev-junior")

    target = tmp_path / "build.tmp"
    target.write_text("data")

    with pytest.raises(Blocked) as ei:
        g.execute(Action.file("delete", str(target)))
    assert "rbac" in ei.value.decision.reason
    assert "dev-junior" in ei.value.decision.reason
    assert target.exists()


def test_guard_admin_role_passes_rbac(tmp_path: Path):
    g = _guard_with_toml(tmp_path, """
        [roles.admin]
        allow_intents = ["*"]
    """, role="admin")
    res = g.execute(Action.shell("echo hi", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"


def test_guard_disabled_rbac_skips_check(tmp_path: Path):
    cfg_path = tmp_path / "guard.toml"
    _write_toml(cfg_path, """
        [roles.dev]
        deny_intents = ["SHELL_EXEC"]
    """)
    # enable_rbac=False should let SHELL_EXEC through despite the deny
    g = Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_approve,
        enable_memory=False,
        enable_inheritance=False,
        enable_governance=False,
        guard_toml_path=cfg_path,
        enable_rbac=False,
        role="dev",
    )
    res = g.execute(Action.shell("echo hi", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"


def test_guard_no_toml_file_passes_through(tmp_path: Path):
    """No guard.toml = RBAC is a no-op even with enable_rbac=True."""
    g = Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_approve,
        enable_memory=False,
        enable_inheritance=False,
        enable_governance=False,
        guard_toml_path=tmp_path / "missing.toml",
        role="anything",
    )
    res = g.execute(Action.shell("echo hi", cwd=str(tmp_path)))
    assert res.decision.decision == "ALLOW"
