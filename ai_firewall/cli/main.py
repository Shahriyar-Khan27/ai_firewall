from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml

from ai_firewall.approval.cli_prompt import auto_approve, auto_deny, prompt_user
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.parser.action_parser import parse_argv, parse_shell_string

cli = typer.Typer(help="AI Execution Firewall — gate AI-generated actions before they run.", no_args_is_help=True)
policy_app = typer.Typer(help="Inspect or validate policy rule files.", no_args_is_help=True)
cli.add_typer(policy_app, name="policy")


def _make_guard(
    rules: Optional[Path],
    audit: Optional[Path],
    *,
    auto_approve_flag: bool = False,
    auto_deny_flag: bool = False,
) -> Guard:
    if auto_approve_flag and auto_deny_flag:
        typer.secho("--auto-approve and --auto-deny are mutually exclusive", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    if auto_approve_flag:
        approval_fn = auto_approve
    elif auto_deny_flag:
        approval_fn = auto_deny
    else:
        approval_fn = prompt_user
    return Guard(
        rules_path=rules,
        audit_path=audit or Path("logs/audit.jsonl"),
        approval_fn=approval_fn,
    )


@cli.command()
def run(
    command: str = typer.Argument(..., help="Shell command to evaluate and (if approved) run."),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Path to a custom rules YAML file."),
    audit: Optional[Path] = typer.Option(None, "--audit", help="Path to the audit log."),
    auto_approve_flag: bool = typer.Option(False, "--auto-approve", help="Skip the interactive prompt; treat REQUIRE_APPROVAL as approved. For non-interactive callers (e.g. the VS Code extension after a user click)."),
    auto_deny_flag: bool = typer.Option(False, "--auto-deny", help="Skip the interactive prompt; treat REQUIRE_APPROVAL as denied. For dry-run / CI use."),
):
    """Evaluate a shell command and execute it if policy allows."""
    guard = _make_guard(rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag)
    action = parse_shell_string(command)
    try:
        result = guard.execute(action)
    except Blocked as exc:
        typer.secho(f"[FIREWALL] {exc.decision.decision}: {exc.decision.reason}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=126)
    sys.stdout.write(result.execution.stdout)
    sys.stderr.write(result.execution.stderr)
    raise typer.Exit(code=result.execution.exit_code)


@cli.command()
def eval(
    command: str = typer.Argument(..., help="Shell command to evaluate (no execution)."),
    rules: Optional[Path] = typer.Option(None, "--rules"),
):
    """Evaluate a command and print the Decision JSON. Does not execute."""
    guard = Guard(rules_path=rules, audit_path=Path("logs/audit.jsonl"))
    action = parse_shell_string(command)
    decision = guard.evaluate(action)
    typer.echo(json.dumps(decision.to_dict(), indent=2))


@cli.command()
def wrap(
    argv: list[str] = typer.Argument(..., help="Argv form. Use `--` before the command to disambiguate."),
    rules: Optional[Path] = typer.Option(None, "--rules"),
    audit: Optional[Path] = typer.Option(None, "--audit"),
    auto_approve_flag: bool = typer.Option(False, "--auto-approve"),
    auto_deny_flag: bool = typer.Option(False, "--auto-deny"),
):
    """Argv form of `run` — avoids double shell parsing."""
    guard = _make_guard(rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag)
    action = parse_argv(argv)
    try:
        result = guard.execute(action)
    except Blocked as exc:
        typer.secho(f"[FIREWALL] {exc.decision.decision}: {exc.decision.reason}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=126)
    sys.stdout.write(result.execution.stdout)
    sys.stderr.write(result.execution.stderr)
    raise typer.Exit(code=result.execution.exit_code)


@cli.command()
def sql(
    query: str = typer.Argument(..., help="SQL query to evaluate."),
    dialect: str = typer.Option("generic", "--dialect", help="SQL dialect (generic, postgres, mysql, sqlite, ...)."),
    rules: Optional[Path] = typer.Option(None, "--rules"),
    audit: Optional[Path] = typer.Option(None, "--audit"),
    auto_approve_flag: bool = typer.Option(False, "--auto-approve"),
    auto_deny_flag: bool = typer.Option(False, "--auto-deny"),
    evaluate_only: bool = typer.Option(False, "--evaluate-only", help="Print Decision JSON; do not record an audit row."),
):
    """Evaluate a SQL query through the firewall (analyze-only — never executes)."""
    action = Action.db(query, dialect=dialect)
    if evaluate_only:
        guard = Guard(rules_path=rules, audit_path=Path("logs/audit.jsonl"))
        decision = guard.evaluate(action)
        typer.echo(json.dumps(decision.to_dict(), indent=2))
        return
    guard = _make_guard(rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag)
    try:
        result = guard.execute(action)
    except Blocked as exc:
        typer.secho(f"[FIREWALL] {exc.decision.decision}: {exc.decision.reason}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=126)
    sys.stdout.write(result.execution.stdout)
    sys.stderr.write(result.execution.stderr)
    raise typer.Exit(code=result.execution.exit_code)


@cli.command()
def api(
    method: str = typer.Argument(..., help="HTTP method: GET, POST, PUT, PATCH, DELETE, ..."),
    url: str = typer.Argument(..., help="Target URL."),
    body: Optional[str] = typer.Option(None, "--body", help="Optional request body."),
    rules: Optional[Path] = typer.Option(None, "--rules"),
    audit: Optional[Path] = typer.Option(None, "--audit"),
    auto_approve_flag: bool = typer.Option(False, "--auto-approve"),
    auto_deny_flag: bool = typer.Option(False, "--auto-deny"),
    evaluate_only: bool = typer.Option(False, "--evaluate-only", help="Print Decision JSON; do not record an audit row."),
):
    """Evaluate an HTTP request through the firewall (analyze-only — never makes the request)."""
    action = Action.api(method, url, body=body)
    if evaluate_only:
        guard = Guard(rules_path=rules, audit_path=Path("logs/audit.jsonl"))
        decision = guard.evaluate(action)
        typer.echo(json.dumps(decision.to_dict(), indent=2))
        return
    guard = _make_guard(rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag)
    try:
        result = guard.execute(action)
    except Blocked as exc:
        typer.secho(f"[FIREWALL] {exc.decision.decision}: {exc.decision.reason}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=126)
    sys.stdout.write(result.execution.stdout)
    sys.stderr.write(result.execution.stderr)
    raise typer.Exit(code=result.execution.exit_code)


@policy_app.command("show")
def policy_show(rules: Optional[Path] = typer.Option(None, "--rules")):
    """Print the effective ruleset as YAML."""
    guard = Guard(rules_path=rules, audit_path=Path("logs/audit.jsonl"))
    typer.echo(yaml.safe_dump(guard.policy.rules, sort_keys=False))


@policy_app.command("lint")
def policy_lint(file: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False)):
    """Validate that a rules YAML file loads cleanly."""
    try:
        with file.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        typer.secho(f"invalid YAML: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if not isinstance(data, dict):
        typer.secho("rules file must be a mapping at top level", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"ok — {len(data)} sections")


if __name__ == "__main__":
    cli()
