from ai_firewall.core.action import Action, IntentType, RiskLevel
from ai_firewall.engine import intent as intent_mod
from ai_firewall.engine import risk


def _score(action: Action) -> RiskLevel:
    intent = intent_mod.classify(action)
    return risk.score(action, intent)


def test_rm_rf_root_is_critical():
    assert _score(Action.shell("rm -rf /")) is RiskLevel.CRITICAL


def test_rm_rf_etc_is_critical():
    assert _score(Action.shell("rm -rf /etc")) is RiskLevel.CRITICAL


def test_rm_rf_local_dir_is_high():
    assert _score(Action.shell("rm -rf ./build")) is RiskLevel.HIGH


def test_sudo_is_critical():
    assert _score(Action.shell("sudo apt install foo")) is RiskLevel.CRITICAL


def test_echo_is_medium():
    assert _score(Action.shell("echo hi")) is RiskLevel.MEDIUM


def test_cat_is_low():
    assert _score(Action.shell("cat README.md")) is RiskLevel.LOW


def test_file_write_normal_is_low():
    assert _score(Action.file("write", "notes.txt")) is RiskLevel.LOW


def test_code_modify_is_medium():
    assert _score(Action.file("write", "src/app.py")) is RiskLevel.MEDIUM
