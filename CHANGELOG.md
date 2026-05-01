# Changelog

All notable changes to **ai-execution-firewall** are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
and the project follows [SemVer](https://semver.org/).

## [0.3.0] — 2026-05-01

The "fade into the background" release. v0.2.x worked but prompted on every
risky action. After a week, users would turn it off. v0.3.0 adds memory,
inheritance, semantic parsing, signed audit, MCP auto-wrapping, Docker
dry-runs, a standalone binary, and Cursor secret-DB monitoring.

### Smart-flow core

- **Semantic command parsing** ([ai_firewall/parser/shell_ast.py](ai_firewall/parser/shell_ast.py)).
  bashlex-backed AST, decodes `echo "<b64>" | base64 -d | sh`, resolves
  `RM=rm; $RM -rf /` cross-statement assignments, walks pipelines and
  command/process substitutions. Obfuscation alone bumps risk to HIGH —
  even a benign decoded payload is suspicious because the obfuscation is.
- **Approved-pattern memory** ([ai_firewall/approval/pattern_memory.py](ai_firewall/approval/pattern_memory.py)).
  SQLite at `~/.ai-firewall/memory.db`. Once you approve `npm run build`
  in a project, the firewall stops asking. Strict gating: same project,
  same intent, ≥0.8 Jaccard similarity, and historical risk ≥ current
  risk (so a low-risk approval never auto-approves a higher-risk repeat).
- **Permission inheritance** ([ai_firewall/engine/inheritance.py](ai_firewall/engine/inheritance.py),
  [ai_firewall/history/shell_reader.py](ai_firewall/history/shell_reader.py)).
  Reads bash / zsh / fish / PowerShell history. If you typed an
  equivalent command in your own terminal in the last 5 min, the AI's
  request is auto-approved with a status-bar toast.
- **HMAC-signed audit trails** ([ai_firewall/audit/logger.py](ai_firewall/audit/logger.py),
  [ai_firewall/audit/verifier.py](ai_firewall/audit/verifier.py)).
  Opt-in via `guard audit init-key` or the `AI_FIREWALL_AUDIT_KEY` env
  var. Every record HMAC-SHA256-signed over canonical JSON. New
  subcommands: `guard audit verify` and `guard audit show
  --tampered-only`. Constant-time signature compare.

### MCP transparent proxy (Feature A)

- **MCP detector** ([ai_firewall/discovery/mcp_detector.py](ai_firewall/discovery/mcp_detector.py)).
  Scans `~/.claude/mcp.json`, `~/.cursor/mcp.json`,
  `~/.continue/config.json`, `.mcp.json` in any workspace. Reports
  wrapped vs unwrapped MCP servers.
- **MCP proxy** ([ai_firewall/proxy/mcp_proxy.py](ai_firewall/proxy/mcp_proxy.py)).
  `guard mcp-proxy` is a stdio shim that wraps an upstream MCP server.
  Inspects `tools/call` JSON-RPC requests, runs the proposed action
  through `Guard.evaluate`, and returns a tool-error response (never
  forwarded to the upstream) on BLOCK or REQUIRE_APPROVAL.
  Heuristically maps tool args to Action types so generic MCP tools
  (`run_shell`, `write_file`, `run_sql_query`, `fetch_url`, …) all gate.
- **`guard mcp install/uninstall/scan`** — automate the mcp.json edit so
  users don't have to hand-write the wrapper config.

### Distribution (Feature G)

- **PyInstaller standalone binary**: `scripts/build-standalone.sh` and
  `.bat` produce a single `guard` / `guard.exe` (~30 MB) with no Python
  prerequisite. New CI workflow `.github/workflows/release-binaries.yml`
  runs the matrix on tag push: ubuntu-x86_64, macos-x86_64, macos-arm64,
  windows-x86_64. Each binary is smoke-tested (`guard sql "DROP DATABASE
  prod" --evaluate-only` must BLOCK) before being attached to the GitHub
  release.

### High-trust modes

- **Sandbox replay (Feature F)** ([ai_firewall/adapters/sandbox.py](ai_firewall/adapters/sandbox.py)).
  `guard run "<cmd>" --dryrun` mounts a copy of the workdir into a
  Docker container, runs the command there with `--network none`, then
  diffs the workdir before/after and surfaces the file-change list.
  Refuses on workdirs >50 MB; gracefully reports "Docker unavailable"
  rather than fail-open.
- **Cursor secret-DB watcher (Feature H)**
  ([vscode-extension/src/secret_watcher.ts](vscode-extension/src/secret_watcher.ts)).
  Detection-only, never patches `fs.readFile`. Watches the editor's
  `state.vscdb` (Code/Cursor) for modifications and surfaces a webview
  log via `AI Firewall: Show Recent Secret-DB Activity`.

### VS Code extension polish

- New command **AI Firewall: Show Recent Secret-DB Activity**.
- Smart-flow status-bar toasts: when the firewall auto-approves via memory
  or inheritance, a quiet "$(check) Firewall: auto-approved (learned from
  you)" toast surfaces what just happened. No webview, no friction.

### Numbers

- 269 → 285 tests (16 new across `test_shell_ast`, `test_audit_hmac`,
  `test_pattern_memory`, `test_inheritance`, `test_smart_flow`,
  `test_mcp_proxy`, `test_sandbox`).
- New top-level deps: `bashlex>=0.18`. `pyinstaller` is a build-time
  extra (CI only).

## [0.2.0] — 2026-04-30

The "auto-mode" release. The firewall now intercepts AI agents that execute on their own — not just users who deliberately route commands through it.

### Added

- **Claude Code `PreToolUse` hook** ([scripts/claude-code-pretooluse.py](scripts/claude-code-pretooluse.py)). Reads Claude Code's tool-call JSON on stdin, evaluates the action through `Guard`, and refuses anything BLOCK or REQUIRE_APPROVAL by exiting 2 with a structured reason. Works in auto-accept / `--dangerously-skip-permissions` mode because Claude Code hooks always fire. Covers `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`.
- **MCP server** ([ai_firewall/mcp_server.py](ai_firewall/mcp_server.py)). FastMCP-based server exposing `firewall_run_shell`, `firewall_run_sql`, `firewall_run_api`, `firewall_run_file`, `firewall_evaluate_shell`, `firewall_show_policy`. Launch with `guard mcp` (stdio transport). Wire into any MCP host (Claude Code, Cursor, Continue.dev, Zed, Cline) so the AI's actions route through the firewall instead of its built-in tools.
- **`guard mcp` CLI subcommand** to launch the MCP server.
- **`mcp` optional install extra**: `pip install "ai-execution-firewall[mcp]"`.
- **23 new tests** (9 covering the hook script via subprocess, 14 covering the MCP tool functions). Total: 182 passing.

### Why this matters

Until now, the firewall only saw actions you deliberately wrapped (`guard run …`, the SDK, the VS Code command palette). That's the wrong threat model for AI tools running unattended in auto-mode. v0.2.0 adds the two integration paths that catch unattended agent actions before they execute:

- The **Claude Code hook** is the most direct — it intercepts Claude Code's own tools without needing the AI to use anything different. Drop it into `settings.json` and you're done.
- The **MCP server** is the broader, vendor-neutral path. Any MCP-aware AI tool can be configured to prefer our wrapped tools over its built-ins.

Both default to **safer-than-not**: `REQUIRE_APPROVAL` is treated as a block, so an unattended agent can't silently coerce its way to execution.

## [0.1.1] — 2026-04-30

### Changed
- **README polish.** Lead with both install paths (PyPI + VS Code Marketplace), add status badges, expand the Quickstart with `guard sql` and `guard api` examples, document opt-in `--execute` mode for SQL and HTTP, and update the Pipeline section to list the DB_* / API_* intents and secret scanning that were already shipped in 0.1.0 but undocumented in the README.
- New "Adapters" table making the analyze-only-by-default behaviour explicit.
- New "Release flow" section documenting the auto-publish-on-tag CI.

No code changes.

## [0.1.0] — 2026-04-30

First public release. Available on PyPI as
[`ai-execution-firewall`](https://pypi.org/project/ai-execution-firewall/).

### Pipeline (Phase 1)

- `Action` model: `Action.shell(...)`, `Action.file(...)`, `Action.db(...)`,
  `Action.api(...)`.
- 5-stage pipeline: **intent classifier → risk analyzer → policy engine →
  impact engine → decision engine**, orchestrated by `Guard`.
- YAML-driven `PolicyEngine` with per-intent `blocked` / `blocked_paths` /
  `require_approval` / `allowed` rules. Default rules ship with the package.
- JSONL audit log; one record per evaluated action (allowed, blocked, or
  approval-required).
- Integration surfaces:
  - **CLI** (`guard`) — `run`, `eval`, `wrap`, `sql`, `api`, `policy`.
  - **Python SDK** — `from ai_firewall import Guard, Action`.
  - **Bash/zsh shell hook** — wraps `rm`, `mv`, `dd`, `chmod`, `chown` via
    `scripts/guard-shell-hook.sh`.

### Code-aware impact (Phase 2)

- **Unified diff** for `FILE_WRITE` / `CODE_MODIFY` actions, truncated for
  prompt-friendliness.
- **AST-aware findings** for Python code edits: removed top-level
  functions/classes, removed test functions, sensitive identifiers
  (auth/password/token/...), syntax errors, empty replacements.
- **Git-aware impact**: detects gitignored / untracked / uncommitted-changes
  paths via `git status --porcelain` and `git check-ignore`.
- **VS Code extension** with three commands (`Run Shell Command…`,
  `Evaluate SQL Query…`, `Evaluate HTTP Request…`), themed approval
  webview, status bar item, output channel, and three settings.

### DB safety (Phase 3a)

- `sqlglot`-backed `engine/sql_analysis.py` classifies SQL statements
  and surfaces:
  - `DELETE` / `UPDATE` without `WHERE` → CRITICAL
  - `DROP DATABASE` / `DROP SCHEMA` → blocked by default rules
  - `DROP TABLE` / `TRUNCATE` → REQUIRE_APPROVAL
  - `GRANT` / `REVOKE` → privilege change finding
  - Multiple statements in one batch → minor finding
- Intents `DB_READ`, `DB_WRITE`, `DB_DESTRUCTIVE`.
- `DBAnalyzeAdapter` (default) never executes the query — firewall stays
  out of the DB connection path.
- `SQLiteExecuteAdapter` (opt-in via `guard sql --execute --connection
  <path>`) actually runs approved queries against SQLite. Returns row
  data, rowcount, or DDL acknowledgement; truncates output for the
  audit log.

### API safety (Phase 3b)

- `engine/url_analysis.py` classifies HTTP requests and surfaces:
  - Cloud metadata endpoints (`169.254.169.254`, GCP, Azure) → CRITICAL
  - Private/loopback hosts (RFC 1918) → SSRF finding, HIGH
  - URL-embedded credentials (`https://user:pass@host/`) → HIGH
  - Secrets in query string (`?api_key=`, `?token=`, ...) → HIGH
  - Non-HTTP schemes (`file://`, `javascript:`, ...) → HIGH
  - Destructive paths on POST/PUT/PATCH/DELETE (`/admin/`, `/delete`,
    ...) → HIGH
- Intents `API_READ`, `API_WRITE`, `API_DESTRUCTIVE`.
- `engine/secret_scan.py` scans request body and `Authorization`-style
  headers for AWS/GitHub/Slack/Stripe/Google/Anthropic/OpenAI tokens, PEM
  private keys, JWTs, and quoted password/api_key/secret field
  assignments. Critical-tier hits push risk to CRITICAL; major-tier hits
  push to HIGH.
- `APIAnalyzeAdapter` (default) never makes the request.
- `HTTPExecuteAdapter` (opt-in via `guard api --execute`) issues approved
  requests via stdlib `urllib`. Captures status, headers (truncated),
  and body (truncated to 4 KB).

### Distribution

- PyPI: `pip install ai-execution-firewall` — Python ≥ 3.11.
- VS Code extension: build a `.vsix` with `npx vsce package` from
  `vscode-extension/` and install via "Install from VSIX…".

### Tests

- 159 tests covering every engine stage, every adapter, both analyze and
  execute modes, the CLI surface, and integration flows.
