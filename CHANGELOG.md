# Changelog

All notable changes to **ai-execution-firewall** are documented here. The
format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
and the project follows [SemVer](https://semver.org/).

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
