from __future__ import annotations

import sqlite3
from pathlib import Path

from ai_firewall.adapters.base import ExecutionAdapter, ExecutionResult
from ai_firewall.core.action import Action


_MAX_OUTPUT_BYTES = 4096
_MAX_ROWS = 100


class SQLiteExecuteAdapter(ExecutionAdapter):
    """Real-execution DB adapter, SQLite only.

    Opt-in via `guard sql … --execute --connection <path>`. The firewall has
    already passed policy by the time this runs; this adapter just executes the
    SQL and captures the result for the audit log.

    Connection forms accepted:
      - `sqlite:///abs/path/db.sqlite`     (URL form, absolute path)
      - `sqlite:./relative/db.sqlite`      (URL form, relative)
      - `sqlite::memory:`                  (in-memory)
      - bare path or `:memory:`            (no scheme — treated as sqlite)
    """

    def __init__(self, connection: str):
        self.connection = connection
        self._db_target = _parse_connection(connection)

    def run(self, action: Action) -> ExecutionResult:
        sql = (action.payload.get("sql") or "").strip()
        if not sql:
            return ExecutionResult(exit_code=2, stderr="empty SQL", executed=False)

        # Connection in action.context overrides the adapter's default if present.
        target = _parse_connection(action.context.get("connection") or self.connection)
        try:
            conn = sqlite3.connect(target, isolation_level=None)  # autocommit
        except sqlite3.Error as e:
            return ExecutionResult(exit_code=1, stderr=f"sqlite connect failed: {e}", executed=False)

        try:
            cur = conn.cursor()
            multi = _looks_multi_statement(sql)
            try:
                if multi:
                    cur.executescript(sql)
                else:
                    cur.execute(sql)
            except sqlite3.Error as e:
                return ExecutionResult(exit_code=1, stderr=f"sqlite error: {e}", executed=True)

            rendered = _render_result(cur, multi=multi)
            return ExecutionResult(
                exit_code=0,
                stdout=rendered,
                stderr="",
                executed=True,
                note="executed via SQLiteExecuteAdapter",
            )
        finally:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def _looks_multi_statement(sql: str) -> bool:
    """Return True if `sql` contains more than one statement (semicolon mid-string)."""
    stripped = sql.strip().rstrip(";")
    return ";" in stripped


def _parse_connection(spec: str) -> str:
    """Translate the connection spec into something sqlite3.connect understands."""
    if not spec:
        raise ValueError("empty connection spec")
    if spec == ":memory:" or spec == "sqlite::memory:":
        return ":memory:"
    if spec.startswith("sqlite:///"):
        return spec[len("sqlite:///"):] or ":memory:"
    if spec.startswith("sqlite:"):
        return spec[len("sqlite:"):] or ":memory:"
    # Bare path.
    return str(Path(spec))


def _render_result(cursor: sqlite3.Cursor, *, multi: bool) -> str:
    if multi:
        return "ok (multi-statement script executed)\n"
    if cursor.description:
        cols = [d[0] for d in cursor.description]
        rows = cursor.fetchmany(_MAX_ROWS)
        lines = ["\t".join(cols)]
        for row in rows:
            lines.append("\t".join(_safe(c) for c in row))
        if len(rows) >= _MAX_ROWS:
            lines.append(f"… (truncated at {_MAX_ROWS} rows)")
        text = "\n".join(lines) + "\n"
    else:
        rc = cursor.rowcount
        text = f"{rc} row(s) affected\n" if rc >= 0 else "ok\n"
    if len(text) > _MAX_OUTPUT_BYTES:
        text = text[:_MAX_OUTPUT_BYTES] + "\n… (output truncated)\n"
    return text


def _safe(value: object) -> str:
    if value is None:
        return ""
    s = str(value)
    return s.replace("\t", "    ").replace("\n", "\\n")
