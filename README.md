# AI Execution Firewall

A control layer that intercepts AI-generated actions (shell commands, file ops, SQL queries, HTTP requests) and gates them through a deterministic policy pipeline before they execute.

```
AI → Action → Firewall → Decision → Execution
```

## Install

```bash
pip install ai-execution-firewall
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
guard eval "rm -rf /"          # → BLOCK (no execution)
guard run  "echo hello"         # → ALLOW, executes
guard run  "rm ./tmp.txt"       # → REQUIRE_APPROVAL, prompts y/N
guard policy show               # print effective ruleset
```

### Python SDK

```python
from ai_firewall import Guard, Action

guard = Guard()
result = guard.execute(Action.shell("echo hello"))
print(result.decision.decision, result.execution.exit_code)
```

### Shell hook

```bash
source scripts/guard-shell-hook.sh   # wraps rm, mv, dd, chmod, chown
```

### VS Code extension

In-editor approval UI replacing the terminal prompt with a webview that shows risk, findings, git context, and the unified diff. See [vscode-extension/README.md](vscode-extension/README.md) for build + F5 instructions.

```bash
cd vscode-extension && npm install && npm run compile
# then open the folder in VS Code and press F5
```

## Pipeline

Every `guard.execute(action)` call runs:

1. **Intent classifier** — regex on payload → `FILE_DELETE | FILE_WRITE | SHELL_EXEC | CODE_MODIFY | …`
2. **Risk analyzer** — table lookup on intent + feature flags → `LOW | MEDIUM | HIGH | CRITICAL`
3. **Policy engine** — YAML rules → `ALLOW | BLOCK | REQUIRE_APPROVAL`
4. **Impact engine** — dry-run glob expansion, file stat, **unified diff**, **AST findings** (removed funcs/tests, auth identifiers), **git context** (uncommitted, untracked, gitignored)
5. **Risk bump** — impact findings can raise risk and re-trigger policy (e.g. removing a function bumps to HIGH)
6. **Decision engine** — combines verdict + risk + impact

`BLOCK` raises immediately. `REQUIRE_APPROVAL` invokes the approval function (default: interactive CLI prompt). `ALLOW` runs through the matching adapter (`shell` or `file`).

Every evaluated action is appended to `logs/audit.jsonl`.

## Custom rules

Pass `--rules path/to/rules.yaml` (CLI) or `Guard(rules_path=...)` (SDK). See `ai_firewall/config/default_rules.yaml` for the schema:

```yaml
shell_exec:
  blocked:
    - 'rm\s+-rf\s+/'
  require_approval:
    risk_at_or_above: HIGH

file_delete:
  require_approval: true
```

## Scope

**Phase 1** (shipped): shell + filesystem, rule-based classifier, CLI prompt approval, CLI / SDK / shell-hook surfaces.

**Phase 2** (shipped): unified diff for code edits, AST-aware risk findings, git-aware impact, VS Code extension with webview approval UI.

**Out / future**: DB / API adapters, ML classifiers, cloud control plane, web dashboard, sandboxed shell dry-run.

## Tests

```bash
pytest -q
```
