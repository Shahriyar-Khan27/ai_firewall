from pathlib import Path

from ai_firewall.core.action import Action, IntentType
from ai_firewall.engine import impact


def test_delete_single_file_counts_one(tmp_path: Path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"hello world")
    action = Action(type="file", payload={"op": "delete", "path": str(f)}, context={"cwd": str(tmp_path)})
    imp = impact.estimate(action, IntentType.FILE_DELETE)
    assert imp.files_affected == 1
    assert imp.bytes_affected == len(b"hello world")


def test_delete_directory_walks_recursively(tmp_path: Path):
    d = tmp_path / "proj"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_bytes(b"abcd")
    (d / "sub" / "b.txt").write_bytes(b"xy")
    action = Action.shell(f"rm -rf {d}", cwd=str(tmp_path))
    imp = impact.estimate(action, IntentType.FILE_DELETE)
    assert imp.files_affected == 2
    assert imp.bytes_affected == 6


def test_delete_glob_expands(tmp_path: Path):
    (tmp_path / "x.log").write_bytes(b"123")
    (tmp_path / "y.log").write_bytes(b"4567")
    (tmp_path / "z.txt").write_bytes(b"xx")
    action = Action.shell("rm *.log", cwd=str(tmp_path))
    imp = impact.estimate(action, IntentType.FILE_DELETE)
    assert imp.files_affected == 2
    assert imp.bytes_affected == 7


def test_write_existing_file_marks_overwrite(tmp_path: Path):
    f = tmp_path / "notes.txt"
    f.write_bytes(b"old content")
    action = Action(type="file", payload={"op": "write", "path": str(f), "content": "new"}, context={"cwd": str(tmp_path)})
    imp = impact.estimate(action, IntentType.FILE_WRITE)
    assert imp.files_affected == 1
    assert "overwrites" in imp.notes


def test_summary_renders_human_readable(tmp_path: Path):
    (tmp_path / "a").write_bytes(b"x" * 2048)
    action = Action.shell(f"rm {tmp_path / 'a'}", cwd=str(tmp_path))
    imp = impact.estimate(action, IntentType.FILE_DELETE)
    s = imp.summary()
    assert "1 file" in s and "KB" in s
