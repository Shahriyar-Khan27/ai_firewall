"""Phase 3.5: SQLite execute mode."""
import json
import sqlite3
from pathlib import Path

import pytest

from ai_firewall.adapters.db_execute import SQLiteExecuteAdapter
from ai_firewall.approval.cli_prompt import auto_approve, auto_deny
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard


def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO users (id, name) VALUES (1, 'alice'), (2, 'bob');
        """
    )
    conn.commit()
    conn.close()
    return db


def test_select_returns_rows(tmp_path: Path):
    db = _make_db(tmp_path)
    adapter = SQLiteExecuteAdapter(str(db))
    res = adapter.run(Action.db("SELECT id, name FROM users ORDER BY id"))
    assert res.exit_code == 0
    assert res.executed is True
    assert "alice" in res.stdout
    assert "bob" in res.stdout
    assert res.stdout.startswith("id\tname\n")


def test_insert_reports_rowcount(tmp_path: Path):
    db = _make_db(tmp_path)
    adapter = SQLiteExecuteAdapter(str(db))
    res = adapter.run(Action.db("INSERT INTO users(id, name) VALUES (3, 'carol')"))
    assert res.exit_code == 0
    assert "1 row(s) affected" in res.stdout
    # Persisted to disk:
    conn = sqlite3.connect(db)
    n = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    conn.close()
    assert n == 3


def test_delete_with_where_persists(tmp_path: Path):
    db = _make_db(tmp_path)
    adapter = SQLiteExecuteAdapter(str(db))
    res = adapter.run(Action.db("DELETE FROM users WHERE id = 1"))
    assert res.exit_code == 0
    assert "1 row(s) affected" in res.stdout
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT id FROM users").fetchall()
    conn.close()
    assert rows == [(2,)]


def test_invalid_sql_returns_error(tmp_path: Path):
    db = _make_db(tmp_path)
    adapter = SQLiteExecuteAdapter(str(db))
    res = adapter.run(Action.db("SELECT * FROM nonexistent_table"))
    assert res.exit_code == 1
    assert "sqlite error" in res.stderr


def test_connection_url_form(tmp_path: Path):
    db = _make_db(tmp_path)
    adapter = SQLiteExecuteAdapter(f"sqlite:///{db}")
    res = adapter.run(Action.db("SELECT count(*) FROM users"))
    assert res.exit_code == 0
    assert "2" in res.stdout


def test_action_context_overrides_adapter_default(tmp_path: Path):
    db1 = _make_db(tmp_path)
    db2 = tmp_path / "other.sqlite"
    sqlite3.connect(db2).execute("CREATE TABLE t(x)").connection.commit()
    adapter = SQLiteExecuteAdapter(str(db1))
    # Action carries its own connection — should hit db2, not db1.
    action = Action.db("SELECT name FROM sqlite_master WHERE type='table'", connection=str(db2))
    res = adapter.run(action)
    assert res.exit_code == 0
    assert "users" not in res.stdout
    assert "t" in res.stdout


def test_approved_destructive_actually_runs_through_guard(tmp_path: Path):
    db = _make_db(tmp_path)
    g = Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_approve,
        adapters={"db": SQLiteExecuteAdapter(str(db))},
    )
    g.execute(Action.db("DELETE FROM users WHERE id = 2"))
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT id FROM users").fetchall()
    conn.close()
    assert rows == [(1,)]


def test_blocked_destructive_does_not_run(tmp_path: Path):
    db = _make_db(tmp_path)
    g = Guard(
        audit_path=tmp_path / "audit.jsonl",
        approval_fn=auto_deny,
        adapters={"db": SQLiteExecuteAdapter(str(db))},
    )
    with pytest.raises(Blocked):
        g.execute(Action.db("DROP DATABASE prod"))  # caught by db_destructive.blocked regex
    # DB unchanged:
    conn = sqlite3.connect(db)
    n = conn.execute("SELECT count(*) FROM users").fetchone()[0]
    conn.close()
    assert n == 2


def test_audit_records_executed_true_after_approval(tmp_path: Path):
    db = _make_db(tmp_path)
    audit = tmp_path / "audit.jsonl"
    g = Guard(
        audit_path=audit,
        approval_fn=auto_approve,
        adapters={"db": SQLiteExecuteAdapter(str(db))},
    )
    g.execute(Action.db("DELETE FROM users WHERE id = 1"))
    rec = json.loads(audit.read_text(encoding="utf-8").strip())
    assert rec["executed"] is True
    assert rec["exit_code"] == 0
    assert rec["intent"] == "DB_DESTRUCTIVE"
