from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp


@dataclass(frozen=True)
class SqlAnalysis:
    statements: tuple[str, ...]          # statement kinds: SELECT, INSERT, UPDATE, DELETE, DROP, ...
    tables: tuple[str, ...]              # table names referenced (best-effort)
    findings: tuple[str, ...]            # human-readable findings
    severity: str                        # "none" | "minor" | "major" | "critical"
    parse_ok: bool


_DESTRUCTIVE = {"DROP", "TRUNCATE", "DELETE"}
_WRITE = {"INSERT", "UPDATE", "MERGE", "REPLACE"}
_READ = {"SELECT", "WITH", "DESCRIBE", "SHOW", "EXPLAIN"}
_DDL = {"CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME"}
_PRIVILEGE = {"GRANT", "REVOKE"}


def analyze(sql: str, dialect: str = "generic") -> SqlAnalysis:
    """Parse SQL with sqlglot and surface risky patterns. Best-effort; never raises."""
    if not sql or not sql.strip():
        return SqlAnalysis((), (), ("empty SQL",), "none", parse_ok=False)

    parsed: list[exp.Expression] = []
    try:
        # `parse` returns a list (statements separated by semicolons).
        sg_dialect = None if dialect in (None, "", "generic") else dialect
        parsed = [s for s in sqlglot.parse(sql, read=sg_dialect) if s is not None]
    except sqlglot.errors.ParseError:
        return SqlAnalysis(
            (),
            (),
            ("SQL failed to parse — treat as opaque/unknown",),
            "major",
            parse_ok=False,
        )

    if not parsed:
        return SqlAnalysis((), (), ("no statements found",), "none", parse_ok=True)

    statements: list[str] = []
    tables: list[str] = []
    findings: list[str] = []
    severity = "none"

    if len(parsed) > 1:
        findings.append(f"multiple statements ({len(parsed)}) in one batch")
        severity = _bump(severity, "minor")

    for stmt in parsed:
        kind = _statement_kind(stmt)
        statements.append(kind)
        for tbl in _referenced_tables(stmt):
            if tbl and tbl not in tables:
                tables.append(tbl)

        if kind == "DROP":
            target = _drop_target(stmt)
            findings.append(f"DROP {target} — irreversible schema change")
            severity = _bump(severity, "critical" if target in {"DATABASE", "SCHEMA"} else "major")
        elif kind == "TRUNCATE":
            findings.append("TRUNCATE — wipes all rows from table(s)")
            severity = _bump(severity, "major")
        elif kind == "DELETE":
            if not _has_where(stmt):
                findings.append("DELETE without WHERE — affects all rows")
                severity = _bump(severity, "critical")
            else:
                severity = _bump(severity, "major")
        elif kind == "UPDATE":
            if not _has_where(stmt):
                findings.append("UPDATE without WHERE — rewrites all rows")
                severity = _bump(severity, "critical")
            else:
                severity = _bump(severity, "minor")
        elif kind == "ALTER":
            findings.append("ALTER — schema change")
            severity = _bump(severity, "major")
        elif kind in _PRIVILEGE:
            findings.append(f"{kind} — privilege change")
            severity = _bump(severity, "major")

    return SqlAnalysis(
        statements=tuple(statements),
        tables=tuple(tables),
        findings=tuple(findings),
        severity=severity,
        parse_ok=True,
    )


def primary_intent(statements: tuple[str, ...]) -> str:
    """Reduce a sequence of statement kinds to the most-severe intent.

    Returns one of: DB_READ, DB_WRITE, DB_DESTRUCTIVE, DB_UNKNOWN.
    """
    if not statements:
        return "DB_UNKNOWN"
    if any(s in _DESTRUCTIVE or s in _PRIVILEGE or s == "ALTER" or s == "CREATE" for s in statements):
        # DDL + privilege ops + DELETE/TRUNCATE/DROP → destructive class
        return "DB_DESTRUCTIVE"
    if any(s in _WRITE for s in statements):
        return "DB_WRITE"
    if all(s in _READ for s in statements):
        return "DB_READ"
    return "DB_WRITE"


def _statement_kind(stmt: exp.Expression) -> str:
    if isinstance(stmt, exp.Select):
        return "SELECT"
    if isinstance(stmt, exp.Insert):
        return "INSERT"
    if isinstance(stmt, exp.Update):
        return "UPDATE"
    if isinstance(stmt, exp.Delete):
        return "DELETE"
    if isinstance(stmt, exp.Drop):
        return "DROP"
    if isinstance(stmt, exp.Alter):
        return "ALTER"
    if isinstance(stmt, exp.Create):
        return "CREATE"
    if isinstance(stmt, exp.Merge):
        return "MERGE"
    # sqlglot parses TRUNCATE as TruncateTable (not Command/Drop).
    if type(stmt).__name__ == "TruncateTable":
        return "TRUNCATE"
    if isinstance(stmt, exp.Command):
        # sqlglot maps unknown verbs to Command(this='VERB', ...).
        verb = (getattr(stmt, "this", "") or "").upper()
        if verb:
            return verb
    # Fall back to class name uppercased.
    return type(stmt).__name__.upper()


def _has_where(stmt: exp.Expression) -> bool:
    where = stmt.args.get("where")
    return where is not None


def _drop_target(stmt: exp.Expression) -> str:
    kind = (stmt.args.get("kind") or "").upper() if isinstance(stmt, exp.Drop) else ""
    return kind or "TABLE"


def _referenced_tables(stmt: exp.Expression) -> list[str]:
    names: list[str] = []
    for tbl in stmt.find_all(exp.Table):
        try:
            names.append(tbl.name)
        except Exception:
            continue
    return names


_RANK = {"none": 0, "minor": 1, "major": 2, "critical": 3}


def _bump(current: str, new: str) -> str:
    return new if _RANK[new] > _RANK[current] else current
