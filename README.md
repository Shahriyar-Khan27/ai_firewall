# AI Execution Firewall

[![PyPI](https://img.shields.io/pypi/v/ai-execution-firewall.svg)](https://pypi.org/project/ai-execution-firewall/)
[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/sk-dev-ai.ai-execution-firewall.svg?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Shahriyar-Khan27/ai_firewall/actions/workflows/ci.yml)

A control layer that intercepts AI-generated actions — **shell commands, file edits, SQL queries, HTTP requests** — and gates them through a deterministic policy pipeline before they execute.

```
AI → Action → Firewall → Decision → Execution
```

The firewall classifies intent, scores risk, applies YAML rules, simulates impact (unified diff for code, AST findings, git context, SSRF / leaked-secret detection for URLs), and returns one of `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`. Every decision is appended to an audit log.

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

For development (editable install with test deps):

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall
pip install -e ".[dev]"
```

## Quickstart

### CLI

```bash
# Shell
guard eval "rm -rf /"                     # → BLOCK (no execution)
guard run  "echo hello"                    # → ALLOW, executes
guard run  "rm ./tmp.txt"                  # → REQUIRE_APPROVAL, prompts y/N

# SQL (analyze-only by default — never touches your DB)
guard sql "SELECT * FROM users"            # → ALLOW · LOW
guard sql "DELETE FROM users"              # → REQUIRE_APPROVAL · CRITICAL (no WHERE)
guard sql "DROP DATABASE prod"             # → BLOCK
# Opt-in execute mode against a real SQLite DB:
guard sql "DELETE FROM users WHERE id=1" --execute --connection ./app.sqlite

# HTTP (analyze-only by default — never makes the request)
guard api GET https://api.example.com/users    # → ALLOW
guard api GET http://169.254.169.254/          # → CRITICAL (cloud metadata SSRF)
guard api POST https://api.example.com/log --body '{"k":"AKIAIOSFODNN7EXAMPLE"}'
                                                #  → CRITICAL (AWS key in body)
# Opt-in execute mode (issues request via stdlib urllib):
guard api POST https://api.example.com/things --body '{"x":1}' --execute

guard policy show                          # print effective ruleset
```

### Python SDK

```python
from ai_firewall import Guard, Action

guard = Guard()
result = guard.execute(Action.shell("echo hello"))
print(result.decision.decision, result.execution.exit_code)
```

`Action.file(...)`, `Action.db(...)`, `Action.api(...)` cover the other three action types.

### Shell hook

```bash
source scripts/guard-shell-hook.sh   # wraps rm, mv, dd, chmod, chown
```

### VS Code extension

After installing from the Marketplace, the **Command Palette** (Ctrl+Shift+P) gives you six commands under `AI Firewall:`

- **Run Shell Command…** / **Evaluate Selected Text as Shell Command**
- **Evaluate SQL Query…** / **Evaluate Selected Text as SQL**
- **Evaluate HTTP Request…**
- **Show Effective Policy**

Risky actions open a themed approval webview with the risk badge, intent / decision pills, findings list, git context, and a syntax-coloured unified diff (for code edits). One click to Approve & run, one click to Reject — both record an audit row. See [vscode-extension/README.md](vscode-extension/README.md) for build / debug / packaging instructions.

## Pipeline

Every `guard.execute(action)` call runs:

1. **Intent classifier** — regex / SQL parse / URL parse → one of `FILE_DELETE | FILE_WRITE | FILE_READ | SHELL_EXEC | CODE_MODIFY | DB_READ | DB_WRITE | DB_DESTRUCTIVE | API_READ | API_WRITE | API_DESTRUCTIVE`
2. **Risk analyzer** — table lookup on intent + feature flags → `LOW | MEDIUM | HIGH | CRITICAL`
3. **Policy engine** — YAML rules → `ALLOW | BLOCK | REQUIRE_APPROVAL` (first pass)
4. **Impact engine** — best-effort dry-run:
   - **Files**: glob expansion, file stat, **unified diff**, **AST findings** (removed funcs / tests, auth identifiers), **git context** (uncommitted, untracked, gitignored)
   - **SQL**: `sqlglot` AST → DELETE/UPDATE without WHERE, DROP DATABASE/SCHEMA/TABLE, TRUNCATE, GRANT/REVOKE, multiple statements
   - **HTTP**: cloud metadata endpoints, private/loopback hosts (SSRF), URL credentials, secrets in query string, non-HTTP schemes, destructive paths; body + Authorization-header secret scanning (AWS / GitHub / Slack / Stripe / Google / Anthropic / OpenAI / PEM keys / JWTs)
5. **Risk bump** — impact findings can raise risk and re-trigger policy (e.g. removing a function bumps to HIGH; metadata host bumps to CRITICAL)
6. **Decision engine** — combines verdict + risk + impact

`BLOCK` raises immediately. `REQUIRE_APPROVAL` invokes the approval function (default: interactive CLI prompt; in VS Code: webview button). `ALLOW` runs through the matching adapter.

Every evaluated action is appended to `logs/audit.jsonl`.

## Adapters

| Action type | Default adapter | Opt-in execute adapter |
|---|---|---|
| `shell` | `ShellAdapter` (subprocess) | — (always executes) |
| `file` | `FileAdapter` (pathlib) | — (always executes) |
| `db` | `DBAnalyzeAdapter` — never opens a DB | `SQLiteExecuteAdapter` via `--execute --connection <sqlite-path>` |
| `api` | `APIAnalyzeAdapter` — never sends a request | `HTTPExecuteAdapter` via `--execute` (stdlib `urllib`) |

DB and API default to **analyze-only** so the firewall never touches your database or network unless you explicitly opt in.

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

**Shipped (v0.1.0):**

- **Phase 1**: shell + filesystem, rule-based classifier, CLI prompt approval, CLI / SDK / shell-hook surfaces.
- **Phase 2**: unified diff for code edits, AST-aware risk findings, git-aware impact, VS Code extension with webview approval UI.
- **Phase 3**: SQL gating via `sqlglot`, HTTP gating via stdlib `urllib`, secret-scanning of request bodies and Authorization-style headers, opt-in execute adapters for SQLite and HTTP.

**Out / future:**

- Postgres / MySQL execute adapters (currently SQLite only)
- Sandboxed shell dry-run
- Cloud control plane / web dashboard
- Team policy distribution

## Tests

```bash
pytest -q
```

159 tests across all phases. CI runs on Python 3.11 / 3.12 / 3.13 on every push.

## Release flow

Pushing a tag matching `v*` automatically:
1. runs the full test matrix on GitHub Actions,
2. builds sdist + wheel,
3. publishes to PyPI via Trusted Publishing (no API token in CI).

```bash
# Bump version in pyproject.toml + add CHANGELOG entry, commit, then:
git tag -a v0.1.1 -m "v0.1.1"
git push --tags
# PyPI is updated within ~60 seconds.
```

VS Code Marketplace publishing is currently manual — re-build the `.vsix` (`npx vsce package --no-yarn` from `vscode-extension/`) and upload via the [Marketplace publisher manage page](https://marketplace.visualstudio.com/manage/publishers/sk-dev-ai).

## Links

- **PyPI**: https://pypi.org/project/ai-execution-firewall/
- **VS Code Marketplace**: https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall
- **GitHub releases**: https://github.com/Shahriyar-Khan27/ai_firewall/releases
- **CHANGELOG**: [CHANGELOG.md](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
