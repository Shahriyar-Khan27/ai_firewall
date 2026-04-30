from pathlib import Path

from ai_firewall.engine import diff


def test_new_file_diff_has_no_old_lines(tmp_path: Path):
    target = tmp_path / "new.txt"
    res = diff.compute(target, "hello\nworld\n")
    assert res.lines_added == 2
    assert res.lines_removed == 0
    assert "+hello" in res.diff
    assert "/dev/null" in res.diff


def test_overwrite_diff_counts_added_and_removed(tmp_path: Path):
    target = tmp_path / "f.py"
    target.write_text("a = 1\nb = 2\n", encoding="utf-8")
    res = diff.compute(target, "a = 1\nb = 99\nc = 3\n")
    assert res.lines_added == 2
    assert res.lines_removed == 1
    assert "-b = 2" in res.diff
    assert "+b = 99" in res.diff
    assert "+c = 3" in res.diff


def test_huge_diff_is_truncated(tmp_path: Path):
    target = tmp_path / "big.txt"
    target.write_text("\n".join(f"old{i}" for i in range(500)) + "\n", encoding="utf-8")
    new = "\n".join(f"new{i}" for i in range(500)) + "\n"
    res = diff.compute(target, new)
    assert "truncated" in res.diff
