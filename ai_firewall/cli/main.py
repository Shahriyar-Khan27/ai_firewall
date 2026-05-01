from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml

from ai_firewall.adapters.api_execute import HTTPExecuteAdapter
from ai_firewall.adapters.db_execute import SQLiteExecuteAdapter
from ai_firewall.approval.cli_prompt import auto_approve, auto_deny, prompt_user
from ai_firewall.core.action import Action
from ai_firewall.core.guard import Blocked, Guard
from ai_firewall.parser.action_parser import parse_argv, parse_shell_string

# On Windows the default stdout encoding is cp1252, which can't render arrows,
# bullets, or non-Latin row content from query/response output. Force UTF-8 with
# replace-errors so guard never crashes mid-write on non-ASCII.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

cli = typer.Typer(help="AI Execution Firewall — gate AI-generated actions before they run.", no_args_is_help=True)
policy_app = typer.Typer(help="Inspect or validate policy rule files.", no_args_is_help=True)
audit_app = typer.Typer(help="Inspect and verify the audit JSONL log.", no_args_is_help=True)
cli.add_typer(policy_app, name="policy")
cli.add_typer(audit_app, name="audit")


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
    dryrun: bool = typer.Option(False, "--dryrun", help="Run the command in a Docker sandbox first; show the file diff instead of touching the real disk."),
    sandbox_image: str = typer.Option("alpine:latest", "--sandbox-image", help="Docker image to use for --dryrun."),
):
    """Evaluate a shell command and execute it if policy allows."""
    guard = _make_guard(rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag)
    if dryrun:
        from ai_firewall.adapters.sandbox import DockerSandboxAdapter
        guard.adapters["shell"] = DockerSandboxAdapter(image=sandbox_image)
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
def scan(
    text: str = typer.Argument(..., help="Text to scan for leaked secrets and PII."),
    json_output: bool = typer.Option(False, "--json", help="Emit findings as JSON instead of human-readable lines."),
):
    """Scan text for leaked secrets and PII (emails, SSNs, credit cards, IBANs, …).

    Useful as a paste-time check: did I just put a real key into a chat box?
    Exits 0 on clean / minor; exits 1 on major / critical.
    """
    from ai_firewall.engine import pii_scan, secret_scan

    sec = secret_scan.scan(text)
    pii = pii_scan.scan(text)
    all_findings = list(sec.findings) + list(pii.findings)
    severity = sec.severity if _sev_rank(sec.severity) >= _sev_rank(pii.severity) else pii.severity

    if json_output:
        typer.echo(json.dumps({"severity": severity, "findings": all_findings}, indent=2))
    else:
        if not all_findings:
            typer.echo("clean — no secrets or PII detected.")
        else:
            typer.secho(f"severity: {severity}", fg=_sev_colour(severity), bold=True)
            for f in all_findings:
                typer.echo(f"  - {f}")
    raise typer.Exit(code=0 if severity in ("none", "minor") else 1)


def _sev_rank(s: str) -> int:
    return {"none": 0, "minor": 1, "major": 2, "critical": 3}.get(s, 0)


def _sev_colour(s: str) -> str:
    return {
        "critical": typer.colors.RED,
        "major": typer.colors.YELLOW,
        "minor": typer.colors.CYAN,
        "none": typer.colors.GREEN,
    }.get(s, typer.colors.WHITE)


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
    execute: bool = typer.Option(False, "--execute", help="Run the query against --connection if approved (SQLite only)."),
    connection: Optional[str] = typer.Option(None, "--connection", help="SQLite connection (path, sqlite:///path, or :memory:)."),
):
    """Evaluate a SQL query through the firewall.

    Default: analyze-only — firewall never touches a DB.
    With `--execute --connection <sqlite-path>`: runs the approved query.
    """
    if execute and not connection:
        typer.secho("--execute requires --connection", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    action = Action.db(query, dialect=dialect, connection=connection if execute else None)

    if evaluate_only:
        guard = Guard(rules_path=rules, audit_path=Path("logs/audit.jsonl"))
        decision = guard.evaluate(action)
        typer.echo(json.dumps(decision.to_dict(), indent=2))
        return

    custom_adapters = {"db": SQLiteExecuteAdapter(connection)} if execute else None
    guard = _make_guard(
        rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag
    )
    if custom_adapters:
        guard.adapters.update(custom_adapters)
    try:
        result = guard.execute(action)
    except Blocked as exc:
        typer.secho(f"[FIREWALL] {exc.decision.decision}: {exc.decision.reason}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=126)
    sys.stdout.write(result.execution.stdout)
    sys.stderr.write(result.execution.stderr)
    raise typer.Exit(code=result.execution.exit_code)


mcp_app = typer.Typer(help="Run / install the firewall as an MCP server or proxy.", no_args_is_help=False, invoke_without_command=True)
cli.add_typer(mcp_app, name="mcp")


@mcp_app.callback(invoke_without_command=True)
def _mcp_default(ctx: typer.Context) -> None:
    """Default action for `guard mcp` (no subcommand) is to launch the MCP server."""
    if ctx.invoked_subcommand is None:
        # Re-implement the v0.2 behaviour inline so `guard mcp` still works.
        try:
            from ai_firewall.mcp_server import main as run_server
        except ImportError:
            typer.secho(
                "MCP server requires the `mcp` package: pip install 'ai-execution-firewall[mcp]'",
                fg=typer.colors.RED, err=True,
            )
            raise typer.Exit(code=1)
        run_server()


@mcp_app.command("server")
def mcp_server() -> None:
    """Launch the MCP server over stdio (same as bare `guard mcp`)."""
    try:
        from ai_firewall.mcp_server import main as run_server
    except ImportError:
        typer.secho(
            "MCP server requires the `mcp` package: pip install 'ai-execution-firewall[mcp]'",
            fg=typer.colors.RED, err=True,
        )
        raise typer.Exit(code=1)
    run_server()


@mcp_app.command("scan")
def mcp_scan(
    workspace: Optional[Path] = typer.Option(None, "--workspace", help="Project root to scan in addition to global configs."),
):
    """List MCP servers configured in known host configs (Claude Code / Cursor / Continue)."""
    from ai_firewall.discovery.mcp_detector import discover_workspace_paths, scan
    extra = discover_workspace_paths(workspace) if workspace else None
    entries = scan(extra_paths=extra)
    if not entries:
        typer.echo("(no MCP servers found in known configs)")
        return
    for e in entries:
        marker = "[wrapped]" if e.wrapped else "[unwrapped]"
        typer.echo(f"{marker:12} {e.host:12} {e.name:25} {e.config_path}")
        if e.wrapped and e.upstream_command:
            typer.echo(f"             upstream: {e.upstream_command} {' '.join(e.upstream_args)}")


@mcp_app.command("install")
def mcp_install(
    name: str = typer.Argument(..., help="Server name to wrap (must match a key in mcpServers)."),
    workspace: Optional[Path] = typer.Option(None, "--workspace", help="Project root to scan in addition to global configs."),
    guard_cmd: str = typer.Option("guard", "--guard-cmd", help="Path to the guard binary (default: 'guard' from PATH)."),
):
    """Wrap a single MCP server with the firewall proxy. Edits the host config in place."""
    from ai_firewall.discovery.mcp_detector import discover_workspace_paths, install, scan, write_servers
    import json as _json

    extra = discover_workspace_paths(workspace) if workspace else None
    entries = scan(extra_paths=extra)
    matches = [e for e in entries if e.name == name]
    if not matches:
        typer.secho(f"no MCP server named '{name}' found", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if len(matches) > 1:
        typer.secho(f"'{name}' is configured in {len(matches)} places — refusing to install ambiguously", fg=typer.colors.RED, err=True)
        for e in matches:
            typer.echo(f"  - {e.config_path}")
        raise typer.Exit(code=1)

    e = matches[0]
    if e.wrapped:
        typer.echo(f"'{name}' is already wrapped — nothing to do.")
        return

    # Load the file fresh, swap just this one server's spec, write back.
    data = _json.loads(e.config_path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or {}
    servers[name] = install(e, guard_cmd=guard_cmd)
    write_servers(e.config_path, servers)
    typer.echo(f"wrapped '{name}' in {e.config_path}")


@mcp_app.command("uninstall")
def mcp_uninstall(
    name: str = typer.Argument(..., help="Server name to unwrap."),
    workspace: Optional[Path] = typer.Option(None, "--workspace"),
):
    """Restore a previously-wrapped MCP server to its original spec."""
    from ai_firewall.discovery.mcp_detector import discover_workspace_paths, scan, uninstall, write_servers
    import json as _json

    extra = discover_workspace_paths(workspace) if workspace else None
    entries = scan(extra_paths=extra)
    matches = [e for e in entries if e.name == name and e.wrapped]
    if not matches:
        typer.secho(f"no wrapped MCP server named '{name}' found", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    e = matches[0]
    spec = uninstall(e)
    if spec is None:
        typer.secho("could not recover original command (config malformed?)", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    data = _json.loads(e.config_path.read_text(encoding="utf-8"))
    servers = data.get("mcpServers") or {}
    servers[name] = spec
    write_servers(e.config_path, servers)
    typer.echo(f"unwrapped '{name}' in {e.config_path}")


@cli.command(name="mcp-proxy", help="(Internal) stdio proxy that routes MCP traffic through the firewall.")
def mcp_proxy_cmd(
    upstream_cmd: str = typer.Option(..., "--upstream-cmd"),
    upstream_arg: Optional[list[str]] = typer.Option(None, "--upstream-arg"),
    firewall_wrapped: bool = typer.Option(False, "--firewall-wrapped", help="Marker for self-detection."),
    approval: str = typer.Option(
        os.environ.get("AI_FIREWALL_PROXY_APPROVAL", "block"),
        "--approval",
        help="Behaviour on REQUIRE_APPROVAL: 'block' (default) or 'approve'.",
    ),
):
    from ai_firewall.proxy.mcp_proxy import run_proxy
    rc = run_proxy(
        upstream_cmd=upstream_cmd,
        upstream_args=list(upstream_arg or []),
        approval_mode=approval,
    )
    raise typer.Exit(code=rc)


@cli.command()
def api(
    method: str = typer.Argument(..., help="HTTP method: GET, POST, PUT, PATCH, DELETE, ..."),
    url: str = typer.Argument(..., help="Target URL."),
    body: Optional[str] = typer.Option(None, "--body", help="Optional request body (scanned for leaked secrets)."),
    header: Optional[list[str]] = typer.Option(None, "--header", "-H", help="Request header in `Name: value` form. Repeat for multiple."),
    rules: Optional[Path] = typer.Option(None, "--rules"),
    audit: Optional[Path] = typer.Option(None, "--audit"),
    auto_approve_flag: bool = typer.Option(False, "--auto-approve"),
    auto_deny_flag: bool = typer.Option(False, "--auto-deny"),
    evaluate_only: bool = typer.Option(False, "--evaluate-only", help="Print Decision JSON; do not record an audit row."),
    execute: bool = typer.Option(False, "--execute", help="Actually issue the HTTP request via urllib if approved (default: analyze-only)."),
    timeout: float = typer.Option(15.0, "--timeout", help="Per-request timeout in seconds when --execute is set."),
):
    """Evaluate an HTTP request through the firewall.

    Default: analyze-only — firewall never makes the request.
    With `--execute`: issues the request via urllib once policy approves.
    """
    headers: dict[str, str] = {}
    for raw in header or []:
        if ":" in raw:
            k, _, v = raw.partition(":")
            headers[k.strip()] = v.strip()
    action = Action.api(method, url, body=body, headers=headers or None)
    if evaluate_only:
        guard = Guard(rules_path=rules, audit_path=Path("logs/audit.jsonl"))
        decision = guard.evaluate(action)
        typer.echo(json.dumps(decision.to_dict(), indent=2))
        return
    guard = _make_guard(rules, audit, auto_approve_flag=auto_approve_flag, auto_deny_flag=auto_deny_flag)
    if execute:
        guard.adapters["api"] = HTTPExecuteAdapter(timeout=timeout)
    try:
        result = guard.execute(action)
    except Blocked as exc:
        typer.secho(f"[FIREWALL] {exc.decision.decision}: {exc.decision.reason}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=126)
    sys.stdout.write(result.execution.stdout)
    sys.stderr.write(result.execution.stderr)
    raise typer.Exit(code=result.execution.exit_code)


@audit_app.command("init-key")
def audit_init_key(
    path: Optional[Path] = typer.Option(None, "--path", help="Where to write the key (default: ~/.ai-firewall/audit.key)."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing key file."),
):
    """Generate a fresh HMAC key for signing future audit records."""
    from ai_firewall.audit.logger import _DEFAULT_KEY_PATH, generate_and_persist_key

    target = path or _DEFAULT_KEY_PATH
    if target.exists() and not force:
        typer.secho(
            f"key already exists at {target} — use --force to overwrite",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)
    written = generate_and_persist_key(target)
    typer.echo(f"wrote audit HMAC key to {written}")
    typer.echo("future audit records written by `guard run/sql/api ...` will be HMAC-SHA256 signed.")


@audit_app.command("verify")
def audit_verify(
    path: Path = typer.Argument(..., exists=True, help="Path to the audit JSONL file."),
    key_hex: Optional[str] = typer.Option(None, "--key", help="HMAC key (hex). Default: env / ~/.ai-firewall/audit.key."),
):
    """Verify every record's HMAC signature in an audit log."""
    from ai_firewall.audit.verifier import verify
    key = bytes.fromhex(key_hex) if key_hex else None
    report = verify(path, key=key)
    typer.echo(json.dumps({
        "total": report.total,
        "valid": report.valid,
        "unsigned": report.unsigned,
        "tampered_indices": report.tampered_indices,
        "malformed_indices": report.malformed_indices,
        "header_key_fingerprint": report.header_key_fingerprint,
        "fingerprint_mismatch": report.fingerprint_mismatch,
        "ok": report.ok,
    }, indent=2))
    raise typer.Exit(code=0 if report.ok else 1)


@audit_app.command("show")
def audit_show(
    path: Path = typer.Argument(..., exists=True, help="Path to the audit JSONL file."),
    since: Optional[str] = typer.Option(None, "--since", help="Show only records newer than this duration (e.g. 1h, 24h, 7d)."),
    tampered_only: bool = typer.Option(False, "--tampered-only", help="Show only records that fail HMAC verification."),
):
    """Print recent audit records in human-readable form."""
    from ai_firewall.audit.verifier import verify
    import re as _re
    import time as _time

    cutoff = None
    if since:
        m = _re.fullmatch(r"(\d+)([smhd])", since.strip().lower())
        if not m:
            typer.secho("--since must look like 5m / 2h / 7d", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        n, unit = int(m.group(1)), m.group(2)
        seconds = n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        cutoff = _time.time() - seconds

    report = verify(path) if tampered_only else None
    tampered_set = set(report.tampered_indices) if report else None

    with path.open("r", encoding="utf-8") as fh:
        for idx, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event") == "init":
                continue
            if cutoff and rec.get("ts", 0) < cutoff:
                continue
            if tampered_only and idx not in tampered_set:
                continue
            ts = rec.get("ts", 0)
            kind = rec.get("type", "?")
            decision = rec.get("decision", "?")
            risk = rec.get("risk", "?")
            rendered = (rec.get("rendered") or "")[:80]
            tamper = " [TAMPERED]" if tampered_set and idx in tampered_set else ""
            typer.echo(f"{_time.strftime('%Y-%m-%d %H:%M:%S', _time.localtime(ts))}  {kind:5}  {decision:18}  {risk:8}  {rendered}{tamper}")


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
