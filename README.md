<div align="center">

<img src="assets/logo.png" alt="AI Execution Firewall" width="120" height="120" />

# AI Execution Firewall

[![PyPI](https://img.shields.io/pypi/v/ai-execution-firewall.svg)](https://pypi.org/project/ai-execution-firewall/)
[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/sk-dev-ai.ai-execution-firewall.svg?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml)

**Deterministic safety layer between AI agents and real systems.**
Gate shell commands, file edits, SQL queries, and HTTP requests through a policy pipeline before they execute.

</div>

```
AI → Action → Firewall → Decision → Execution
```

The firewall classifies intent, scores risk, applies YAML rules, simulates impact (unified diff for code, SQL AST findings, git context, SSRF / leaked-secret detection for URLs), and returns one of `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`. Every decision is appended to an audit log.

In v0.3.0 the firewall fades into the background for routine work: it remembers which commands you've approved, inherits permissions from what you just typed in your own terminal, parses commands semantically (catches `echo "<base64>" | base64 -d | sh` as the decoded `rm -rf /`), and runs destructive commands in a Docker dry-run sandbox before touching real disk.

## Install

**Python package** ([PyPI](https://pypi.org/project/ai-execution-firewall/)):

```bash
pip install ai-execution-firewall
```

**VS Code extension** ([Marketplace](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)):

> VS Code → Extensions panel → search **"AI Execution Firewall"** → Install

Or from the command line:

```bash
code --install-extension sk-dev-ai.ai-execution-firewall
```

**Standalone binary** (no Python required) — download `guard-{linux,macos,macos-arm64,windows}` from the [latest release](https://github.com/Shahriyar-Khan27/ai_firewall/releases/latest) and put it on your PATH.

For development (editable install with test deps):

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall
pip install -e ".[dev]"
```

## The smart-flow UX (new in v0.3.0)

The firewall used to prompt on every risky action. Users would turn it off after a week. v0.3.0 replaces that with a layered flow that gets quieter the more you use it:

| Step | Behaviour |
|---|---|
| 1 | **Silent pass** for safe (`git status`, `ls`, `echo`) — never prompts |
| 2 | **Memory match** → auto-approve repeats of previously-OK actions in the same project, with a quiet status-bar toast |
| 3 | **Permission inheritance** → auto-approve when the user just ran the same command themselves in the last 5 min |
| 4 | **Semantic detection** — even `echo "<b64>" \| base64 -d \| sh` is seen as `rm -rf /` (bashlex AST + decoders) |
| 5 | **Sandbox replay** (opt-in) — `--dryrun` runs in Docker first, shows file diff, then asks |
| 6 | **Auto-block** for unambiguous malice (`rm -rf /`, fork bombs, `DROP DATABASE prod`) |
| 7 | **Approve / reject** prompt as the last-resort fallback |

The result: the firewall stays out of your way for the 95% of routine work, and only interrupts when there's something genuinely worth your eyes.

## Quickstart

### CLI

```bash
# Shell
guard eval "rm -rf /"                          # → BLOCK (no execution)
guard run  "echo hello"                         # → ALLOW, executes
guard run  "rm ./tmp.txt"                       # → REQUIRE_APPROVAL, prompts y/N
guard run  "rm -rf ./build" --dryrun            # → Docker sandbox: shows file diff, then asks

# Obfuscation? Caught.
guard eval 'echo "cm0gLXJmIC8=" | base64 -d | sh'   # → CRITICAL · BLOCK · decoded as rm -rf /

# SQL (analyze-only by default — never touches your DB)
guard sql "SELECT * FROM users"                 # → ALLOW · LOW
guard sql "DELETE FROM users"                   # → CRITICAL (no WHERE) · REQUIRE_APPROVAL
guard sql "DROP DATABASE prod"                  # → BLOCK
guard sql "DELETE FROM users WHERE id=1" --execute --connection ./app.sqlite

# HTTP (analyze-only by default — never makes the request)
guard api GET https://api.example.com/users
guard api GET http://169.254.169.254/           # → CRITICAL (cloud metadata SSRF)
guard api POST https://api.example.com/log --body '{"k":"AKIAIOSFODNN7EXAMPLE"}'
                                                # → CRITICAL (AWS key in body)

# MCP integration (auto-detect & wrap MCP servers in any host config)
guard mcp scan                                  # list every configured MCP server
guard mcp install fetch                         # wrap an upstream MCP server with the firewall
guard mcp uninstall fetch                       # restore the original config

# Audit log: signed + verifiable (opt-in HMAC)
guard audit init-key                            # generate ~/.ai-firewall/audit.key
guard audit verify ./logs/audit.jsonl           # tampered-byte detection across the log
guard audit show ./logs/audit.jsonl --since 1h --tampered-only

guard policy show                               # print the effective ruleset
```

### Python SDK

```python
from ai_firewall import Guard, Action

guard = Guard()  # smart-flow on by default — memory + inheritance enabled
result = guard.execute(Action.shell("echo hello"))
print(result.decision.decision, result.execution.exit_code)
```

`Action.file(...)`, `Action.db(...)`, `Action.api(...)` cover the other three action types. The constructor takes `enable_memory=False` / `enable_inheritance=False` for strict-mode environments where automation should never be silent.

### Shell hook

```bash
source scripts/guard-shell-hook.sh   # wraps rm, mv, dd, chmod, chown
```

### Auto-mode AI tools (Claude Code, Cursor, Continue.dev, Zed)

The flows above all require deliberate routing. That's not enough when an AI agent runs unattended in **auto-accept mode** — the agent doesn't ask first.

#### Claude Code — PreToolUse hook (intercepts every Bash / Write / Edit call)

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

#### MCP — wrap any MCP-capable host (Claude Code, Cursor, Continue, Zed, Cline, …)

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

**Automatic** — let the firewall scan and wrap your existing MCP servers:

```bash
guard mcp scan                # list what's configured
guard mcp install fetch       # rewrites the mcp.json to route 'fetch' through the firewall
```

After wrapping, every `tools/call` JSON-RPC request from the host runs through `Guard.evaluate` first. BLOCK and REQUIRE_APPROVAL responses are returned to the host as tool errors — the upstream MCP server is never reached for risky calls. Heuristic argument-shape mapping handles the common conventions (`command`, `file_path`, `sql`, `url`).

### VS Code extension

After installing from the Marketplace, the **Command Palette** (Ctrl+Shift+P) gives you seven commands under `AI Firewall:`

- **Run Shell Command…** / **Evaluate Selected Text as Shell Command**
- **Evaluate SQL Query…** / **Evaluate Selected Text as SQL**
- **Evaluate HTTP Request…**
- **Show Effective Policy**
- **Show Recent Secret-DB Activity** *(new in v0.3.0 — passive watcher for `state.vscdb` modifications)*

Risky actions open a themed approval webview with the risk badge, intent / decision pills, findings list, git context, and a syntax-coloured unified diff. Smart-flow auto-approvals (memory or inheritance match) instead surface a quiet status-bar toast — no webview, no friction. See [vscode-extension/README.md](vscode-extension/README.md) for build / debug / packaging instructions.

## Pipeline

Every `guard.execute(action)` call runs:

1. **Intent classifier** — bashlex AST / SQL parse / URL parse → one of `FILE_DELETE | FILE_WRITE | FILE_READ | SHELL_EXEC | CODE_MODIFY | DB_READ | DB_WRITE | DB_DESTRUCTIVE | API_READ | API_WRITE | API_DESTRUCTIVE`. Multi-command shells take the worst of every effective command; obfuscation (base64/hex/printf decoding) bumps a baseline HIGH risk regardless of what's inside.
2. **Risk analyzer** — table lookup on intent + feature flags → `LOW | MEDIUM | HIGH | CRITICAL`
3. **Policy engine** — YAML rules → `ALLOW | BLOCK | REQUIRE_APPROVAL` (first pass)
4. **Impact engine** — best-effort dry-run:
   - **Files**: glob expansion, file stat, **unified diff**, **AST findings** (removed funcs / tests, auth identifiers), **git context** (uncommitted, untracked, gitignored)
   - **SQL**: `sqlglot` AST → DELETE/UPDATE without WHERE, DROP DATABASE/SCHEMA/TABLE, TRUNCATE, GRANT/REVOKE, multiple statements
   - **HTTP**: cloud metadata endpoints, private/loopback hosts (SSRF), URL credentials, secrets in query string, non-HTTP schemes, destructive paths; body + Authorization-header secret scanning (AWS / GitHub / Slack / Stripe / Google / Anthropic / OpenAI / PEM keys / JWTs)
5. **Risk bump** — impact findings can raise risk and re-trigger policy
6. **Smart-flow** *(new in v0.3.0)* — when policy says REQUIRE_APPROVAL, check **inheritance** (did the user just run an equivalent command in their own terminal?) and **memory** (have they approved this kind of thing in this project before?). Either match downgrades to ALLOW with a status-bar toast. BLOCK is never downgraded.
7. **Decision engine** — combines verdict + risk + impact

`BLOCK` raises immediately. `REQUIRE_APPROVAL` invokes the approval function (CLI prompt or VS Code webview). `ALLOW` runs through the matching adapter.

Every evaluated action is appended to `logs/audit.jsonl` — optionally HMAC-SHA256 signed (see `guard audit init-key`).

## Adapters

| Action type | Default adapter | Opt-in execute adapter |
|---|---|---|
| `shell` | `ShellAdapter` (subprocess) | `DockerSandboxAdapter` via `--dryrun` (Feature F) |
| `file` | `FileAdapter` (pathlib) | — |
| `db` | `DBAnalyzeAdapter` — never opens a DB | `SQLiteExecuteAdapter` via `--execute --connection <sqlite-path>` |
| `api` | `APIAnalyzeAdapter` — never sends a request | `HTTPExecuteAdapter` via `--execute` (stdlib `urllib`) |

DB and API default to **analyze-only** so the firewall never touches your database or network unless you explicitly opt in. Sandbox dry-run is opt-in for shell and runs your command in a disposable container against a snapshot of the workdir, then surfaces the file diff before letting you confirm.

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

**Shipped (v0.3.0):**

- **Phase 1**: shell + filesystem, rule-based classifier, CLI prompt approval, CLI / SDK / shell-hook surfaces.
- **Phase 2**: unified diff for code edits, AST-aware risk findings, git-aware impact, VS Code extension with webview approval UI.
- **Phase 3**: SQL gating via `sqlglot`, HTTP gating via stdlib `urllib`, secret-scanning of request bodies and Authorization-style headers, opt-in execute adapters for SQLite and HTTP.
- **v0.3.0 — smart-flow & distribution**:
  - Semantic command parsing (bashlex) with obfuscation decoding
  - Approved-pattern memory (project-scoped, risk-gated, ≥0.8 Jaccard)
  - Permission inheritance from bash / zsh / fish / PowerShell history
  - HMAC-SHA256-signed audit trails + `guard audit verify`
  - Docker sandbox replay (`--dryrun`)
  - MCP transparent proxy with auto-detect (`guard mcp install/uninstall`)
  - PyInstaller standalone binary (no Python prerequisite)
  - VS Code passive Cursor secret-DB watcher

**Out / future:**

- Postgres / MySQL execute adapters (currently SQLite only)
- Firecracker / gVisor sandbox backends (Docker first)
- Cloud control plane / web dashboard
- Team policy distribution

## Tests

```bash
pytest -q
```

277 tests + 1 skipped (Docker round-trip skips when no daemon). CI runs the full suite on Python 3.11 / 3.12 / 3.13 on every push, plus PyInstaller binary builds on tag push.

## Release flow

Pushing a tag matching `v*` automatically:
1. runs the full test matrix on GitHub Actions,
2. builds sdist + wheel,
3. publishes to PyPI via Trusted Publishing (no API token in CI),
4. builds standalone PyInstaller binaries for Linux / macOS / macOS-arm64 / Windows and attaches them to the GitHub release.

```bash
# Bump version in pyproject.toml + add CHANGELOG entry, commit, then:
git tag -a v0.3.1 -m "v0.3.1"
git push --tags
# PyPI is updated within ~60 seconds; binaries within ~5 minutes.
```

VS Code Marketplace publishing is currently manual — re-build the `.vsix` (`npx vsce package --no-yarn` from `vscode-extension/`) and upload via the [Marketplace publisher manage page](https://marketplace.visualstudio.com/manage/publishers/sk-dev-ai).

## Links

- **PyPI**: https://pypi.org/project/ai-execution-firewall/
- **VS Code Marketplace**: https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall
- **GitHub releases**: https://github.com/Shahriyar-Khan27/ai_firewall/releases
- **CHANGELOG**: [CHANGELOG.md](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
