from ai_firewall.core.action import Action, IntentType
from ai_firewall.engine import intent


def test_shell_rm_classified_as_file_delete():
    assert intent.classify(Action.shell("rm -rf ./build")) is IntentType.FILE_DELETE


def test_shell_redirect_classified_as_file_write():
    assert intent.classify(Action.shell("echo hi > out.txt")) is IntentType.FILE_WRITE


def test_shell_cat_classified_as_file_read():
    assert intent.classify(Action.shell("cat README.md")) is IntentType.FILE_READ


def test_shell_other_is_shell_exec():
    assert intent.classify(Action.shell("echo hello")) is IntentType.SHELL_EXEC


def test_sudo_unwraps_to_inner_command():
    assert intent.classify(Action.shell("sudo rm -rf /tmp/x")) is IntentType.FILE_DELETE


def test_file_op_delete():
    assert intent.classify(Action.file("delete", "/tmp/x")) is IntentType.FILE_DELETE


def test_file_write_to_code_file_is_code_modify():
    assert intent.classify(Action.file("write", "src/app.py")) is IntentType.CODE_MODIFY


def test_file_write_to_text_is_file_write():
    assert intent.classify(Action.file("write", "notes.txt")) is IntentType.FILE_WRITE


def test_feature_flags_recursive_and_force():
    flags = intent.feature_flags(Action.shell("rm -rf /tmp/x"))
    assert flags["recursive"] and flags["force"]


def test_feature_flags_system_path():
    flags = intent.feature_flags(Action.shell("rm -rf /etc"))
    assert flags["system_path"]


def test_feature_flags_sudo():
    flags = intent.feature_flags(Action.shell("sudo apt install foo"))
    assert flags["sudo_or_admin"]


def test_feature_flags_wildcard():
    flags = intent.feature_flags(Action.shell("rm /tmp/*.log"))
    assert flags["wildcard"]
