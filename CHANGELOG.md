# Changelog

All notable changes to **ai-execution-firewall** are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
and the project follows [SemVer](https://semver.org/).

## [0.5.0] — 2026-05-01

The "active interceptor" release. Until now the VS Code extension was a
passive Command Palette tool — useful when you remembered to invoke it.
v0.5.0 wires the extension into the AI tools running alongside it
(Claude Code via the PreToolUse hook, every MCP-aware host via the
existing transparent proxy), and ends the v0.4.x compromise where the
firewall would auto-deny REQUIRE_APPROVAL silently. Now the user gets
the actual Decision in a webview and clicks Approve / Reject.

### New: Approval bridge (Python ↔ extension)

- `ai_firewall/approval/extension_bridge.py` — `make_extension_approval()`
  builds an `ApprovalFn` that POSTs the Decision to a localhost
  endpoint the extension binds. Token-authenticated via
  `~/.ai-firewall/extension.port`, 30s default timeout, falls back to
  `auto_deny` on any error so a crashed extension never makes hooks
  *less* safe than today.
- New env value `AI_FIREWALL_HOOK_APPROVAL=prompt` in the Claude Code
  PreToolUse hook script — defers to the extension webview, falls back
  to safe-default BLOCK when no extension is reachable. `block` and
  `allow` are unchanged.

### New CLI subcommands

- `guard mcp scan --json` emits structured output (mcp_servers list +
  Claude Code hook installed-status). Used by the extension's
  auto-detect on first activation.
- `guard mcp install-hook` writes the PreToolUse hook into
  `~/.claude/settings.json` (idempotent, preserves unrelated entries,
  refuses to overwrite invalid JSON, atomic temp+rename).
- `guard mcp uninstall-hook` reverses install-hook, drops empty
  scaffolding, no-ops on missing file.
- `guard audit show --json` emits records as a JSON array (with
  `tampered: true` markers). `--limit N` slices to the N most-recent
  matched records. The path argument is now optional; falls back to
  `AI_FIREWALL_AUDIT_PATH` or `./logs/audit.jsonl`. A missing file
  returns `[]` in JSON mode.

### Tests

- 452 → 457 (+5 audit-show-json, +8 mcp install/uninstall-hook,
  +10 extension-bridge, +1 hook prompt-mode case, +1 mcp scan json).
  Counted from v0.4.1: 433 → 457 (+24 across the v0.5.0 work).

## [0.4.1] — 2026-05-01

### Changed

- **`guard scan` reads stdin** when called with `-` or no positional
  argument. The 0.4.0 form `guard scan "<text>"` still works, but
  `cat ./prompt.txt | guard scan -` and `echo $env:CLIPBOARD | guard scan`
  are now the ergonomic path for multi-line content (chat messages,
  error logs, code snippets) — no more fighting Windows PowerShell's
  quoting rules. Empty stdin exits 2 with a helpful message.
- `.gitignore` now ignores `*.tmp.*` so an editor that crashes
  mid-rename (which leaves files like `guard.py.tmp.<pid>.<ts>` behind)
  doesn't pollute `git status`.

### Tests

- 428 → 433 (5 new for the `guard scan` argument / stdin / empty-input
  behaviours).

## [0.4.0] — 2026-05-01

The "enterprise round" release. v0.3.x made the firewall pleasant for one
developer with one repo; v0.4.0 is the seven things that move it from
"useful CLI" to "deployable in a regulated org": SBOM validation, DLP for
prompts, network egress control, role-based access control, behavior
analytics, SIEM-ready audit sinks, and cost & resource governance.

### Detection extensions (Stage 1)

- **AI SBOM validation** ([ai_firewall/engine/package_registry.py](ai_firewall/engine/package_registry.py)).
  When `pip install <pkg>`, `npm install <pkg>`, `cargo install <pkg>`, or
  `gem install <pkg>` runs, the firewall verifies the package against the
  public registry (PyPI / npm / crates.io / RubyGems). Unknown packages →
  CRITICAL ("not found on registry"). Damerau-Levenshtein edit-distance
  check against a frozen top-100 popular-package list catches typosquats
  like `requets` (vs `requests`) or `djnago` (vs `django`) → HIGH.
  24-hour SQLite cache at `~/.ai-firewall/registry-cache.sqlite`.
- **AI-native DLP** ([ai_firewall/engine/pii_scan.py](ai_firewall/engine/pii_scan.py)).
  Bolt-on PII scanner that mirrors the existing `secret_scan.py` shape —
  same regex-table-with-severity pattern. Detects email, US SSN (with
  invalid-block filter), Luhn-validated credit cards, E.164/US phone
  numbers, IBAN (country-code whitelisted), and a high-entropy fallback
  for unknown 32+ char tokens. Wired into `_api_impact()` so HTTP request
  bodies and headers are scanned. New `guard scan "<text>"` CLI for
  ad-hoc paste-time checks.
- **Network egress control** ([ai_firewall/engine/intent.py](ai_firewall/engine/intent.py)).
  Shell parser now recognises `curl`, `wget`, `httpie`, `nc`, `telnet`,
  `socat`, `scp`, `rsync`, `sftp`, `ftp`. HTTP-ish verbs route through
  the same `url_analysis` gate as `guard api`, so `curl
  http://169.254.169.254/` BLOCKs at CRITICAL just like `guard api GET
  ...`. Raw-socket / file-transfer verbs classify as new
  `IntentType.NETWORK_EGRESS` (always HIGH baseline, always confirms).

### Audit + governance (Stage 2)

- **SIEM-ready audit sinks** ([ai_firewall/audit/sinks.py](ai_firewall/audit/sinks.py)).
  Pluggable destinations alongside the local JSONL: `JsonlFileSink`
  (default, sync), `StdoutSink` (for piping into vector / fluent-bit),
  `SyslogSink` (RFC 5424 over UDP/TCP, severity from `record.risk`),
  `SplunkHECSink` (HEC envelope, token via env), and `HttpsSink` (generic
  webhook for Datadog / Elastic / custom). All non-file sinks own a
  daemon thread + bounded queue so a slow downstream never blocks the
  firewall's hot path. `build_sinks_from_config()` factory for
  declarative `[[sink]]` config.
- **Cost & resource governance** ([ai_firewall/engine/governance.py](ai_firewall/engine/governance.py)).
  Three enforcements all reading the audit log via a 24h-cached
  `RollingCounter`: rate limits per intent (e.g. >20 file deletes in
  60s), loop detection (same normalized command repeated >5× in 10s),
  and an API spend ceiling (proxied by request-body bytes per 24h).
  Verdicts return BLOCK before the policy stage so a runaway loop can't
  slip through smart-flow. New `guard governance status` CLI shows
  current counters and remaining budget.

### Identity + analytics (Stage 3)

- **Fine-grained RBAC** ([ai_firewall/config/guard_toml.py](ai_firewall/config/guard_toml.py),
  [ai_firewall/engine/rbac.py](ai_firewall/engine/rbac.py)). New
  `~/.ai-firewall/guard.toml` (and per-project `.guard.toml` override).
  Roles support intent allow/deny lists, file-glob allow/deny, MCP-tool
  allow/deny, and `inherits = "<role>"`. Custom glob matcher with `**`
  recursive support so `~/.ssh/**` and `**/credentials*` work
  cross-platform. Identity priority: `--as <role>` flag →
  `AI_FIREWALL_ROLE` env → `[identity].default_role` from guard.toml →
  `"dev"`. RBAC runs FIRST in `Guard.evaluate()`; DENY is a final BLOCK.
- **Behavior analytics** ([ai_firewall/engine/behavior.py](ai_firewall/engine/behavior.py)).
  Three rule-based anomaly heuristics — no ML, no new persistent state.
  `rate_burst` (per-intent count threshold within a window), `rate_spike`
  (last hour rate >Nx 24h median, requires 6h baseline), and
  `quiet_hour` (intent appearing in a historically-zero hour-of-day,
  guarded by both total-actions and distinct-hours minima to avoid
  sparse-history false positives). Behavior runs LAST and only ever
  *downgrades* an ALLOW into REQUIRE_APPROVAL — never escalates BLOCK or
  upgrades approval. New `guard behavior status` CLI.

### Infra

- `Guard` now honours `AI_FIREWALL_AUDIT_PATH` env var for the default
  audit log, so subprocess hooks and MCP servers can be redirected
  in tests without code changes. `guard eval` and `guard api
  --evaluate-only` accept `--audit` for deterministic test runs.
  Per-test fixture in `conftest.py` auto-isolates the user-level
  `guard.toml`, the MCP server's audit log, the memory DB, and the
  HMAC key.

### Numbers

- 285 → 428 tests (+143 across `test_package_registry`, `test_pii_scan`,
  `test_egress`, `test_audit_sinks`, `test_governance`, `test_rbac`,
  `test_behavior`).
- No new top-level deps. `tomllib` (3.11+ stdlib) handles guard.toml.

## [0.3.1] — 2026-05-01

### Changed
- README polish: hero logo, smart-flow UX section, full v0.3.0 quickstart (`--dryrun`, `mcp scan/install`, `audit init-key/verify`), updated Adapters and Scope sections, refreshed test count (277). Logo image now uses an absolute GitHub raw URL so it renders correctly on PyPI as well as on the GitHub repo page.

No code changes.

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
