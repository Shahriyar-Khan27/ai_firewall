from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine.policy import PolicyEngine


def _engine():
    return PolicyEngine.from_default()


def test_rm_rf_root_blocked():
    eng = _engine()
    v = eng.evaluate(Action.shell("rm -rf /"), IntentType.FILE_DELETE, RiskLevel.CRITICAL)
    assert v.verdict == "BLOCK"


def test_fork_bomb_blocked():
    eng = _engine()
    v = eng.evaluate(Action.shell(":(){ :|:& };:"), IntentType.SHELL_EXEC, RiskLevel.CRITICAL)
    assert v.verdict == "BLOCK"


def test_file_delete_always_requires_approval():
    eng = _engine()
    v = eng.evaluate(Action.file("delete", "/tmp/x"), IntentType.FILE_DELETE, RiskLevel.LOW)
    assert v.verdict == "REQUIRE_APPROVAL"


def test_etc_write_blocked_by_glob():
    eng = _engine()
    v = eng.evaluate(Action.file("write", "/etc/passwd"), IntentType.FILE_WRITE, RiskLevel.HIGH)
    assert v.verdict == "BLOCK"


def test_shell_high_risk_requires_approval():
    eng = _engine()
    v = eng.evaluate(Action.shell("rm -rf ./build"), IntentType.FILE_DELETE, RiskLevel.HIGH)
    assert v.verdict in {"REQUIRE_APPROVAL", "BLOCK"}


def test_safe_shell_allowed():
    eng = _engine()
    v = eng.evaluate(Action.shell("echo hello"), IntentType.SHELL_EXEC, RiskLevel.MEDIUM)
    assert v.verdict == "ALLOW"


def test_code_modify_medium_requires_approval():
    eng = _engine()
    v = eng.evaluate(Action.file("write", "src/app.py"), IntentType.CODE_MODIFY, RiskLevel.MEDIUM)
    assert v.verdict == "REQUIRE_APPROVAL"
