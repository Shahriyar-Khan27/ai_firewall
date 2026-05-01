# Changelog

All notable changes to the **AI Execution Firewall** VS Code extension.

## [0.5.1] — 2026-05-01

Documentation-only patch release. The extension's TypeScript source is unchanged from v0.5.0.

### Changed

- README rewritten to follow the conventional VS Code Marketplace structure used by mature extensions (Microsoft Python, GitLens, ESLint): Features, Quick start, Requirements, Useful commands, Extension settings, Example flow, Known issues, Release notes, Questions and contributions, Build from source, License.
- Hero icon now references the absolute `https://raw.githubusercontent.com/.../vscode-extension/icon.png` URL. The previous relative `<img src="icon.png">` rendered as a broken-image placeholder on the Marketplace listing because the rendering context does not resolve relative paths.
- VS Marketplace version and install badges replaced with the working `vsmarketplacebadges.dev` endpoints; the previous shields.io endpoints are retired and were rendering as the literal text "VS Marketplace retired badge".
- Four scattered "What's new in vX.Y.Z" sections collapsed into a single Release notes section that defers to the project CHANGELOG for the full feature list.
- Duplicate "Build from source" block removed; em dashes, first-person plural in prose, and AI-tell phrasing stripped throughout.

## [0.5.0] — 2026-05-01

The "active interceptor" release. The extension goes from a
Command-Palette-only tool to an active gate that wires into the AI
tools running alongside it.

### Added

- **Auto-detect on first activation.** On startup the extension shells
  out to `guard mcp scan --json`, summarises what's unwrapped (Claude
  Code PreToolUse hook missing + per-host MCP server count), and shows
  a non-modal toast: **[Wire All] [Pick…] [Not Now]**. "Pick…" opens a
  multi-select QuickPick. Dismissals are remembered per-fingerprint
  via globalState — adding a new MCP server to your config re-arms the
  prompt.
- **Localhost approval server.** `~/.ai-firewall/extension.port`
  publishes a token-authenticated 127.0.0.1 endpoint. The Python
  Claude Code hook (and the MCP transparent proxy) POST the Decision
  there when REQUIRE_APPROVAL fires; the existing approval webview
  pops up; the user's click flows back as the hook's exit code. AI
  paused for ≤30s waiting for you. Falls back to safe-default BLOCK
  when no extension is reachable.
- **AI Firewall: Show Status** — markdown preview combining the wired
  hosts, the approval-server port + token path, and the last 20 audit
  records as a table. One place to glance at "what's protected and
  what just happened?"
- **AI Firewall: Detect & Wire AI Tools** / **AI Firewall: Unwire All
  AI Tools** — re-run the consent flow on demand or reverse every
  install (modal confirmation; safe to re-run; non-destructive aside
  from the config edits).
- **Decision toasts** — every Approve/Reject from the loopback flow
  drops a 6-second status-bar message so the firewall's actions never
  feel invisible.

### Changed

- Bumped to v0.5.0 to track the Python package. Minimum CLI version is
  now 0.5.0 — the extension shells out to `guard mcp scan --json`,
  `guard mcp install-hook`, and `guard audit show --json`, all of
  which only exist in 0.5.0+. Older CLI = friendlier error in the
  output channel, no crash.

## [0.4.1] — 2026-05-01

### Changed

- Bumped to v0.4.1 to track the Python package. The extension itself
  is unchanged; the underlying `guard scan` CLI now reads from stdin
  when called with `-` or no positional argument, which makes the
  **Scan Text…** input box flow more reliable for very long pastes
  on Windows (no more shell quoting edge cases when guard is invoked).

## [0.4.0] — 2026-05-01

### Added

- **AI Firewall: Scan Text for Secrets and PII…** — input box version of
  `guard scan`. Paste any text (chat message, prompt, error log) and the
  extension surfaces severity + per-finding lines in a preview document.
  Useful as a paste-time check: "did I just put a real key into a chat?"
- **AI Firewall: Scan Selection for Secrets and PII** — same but operates
  on the active editor's current selection. Ideal for checking a chunk
  of code before pasting into an external tool.
- **AI Firewall: Show Governance Status** — opens a preview document
  with current rate-limit counters per intent, loop-detection settings,
  and 24h API byte spend.
- **AI Firewall: Show Behavior Status** — shows configured anomaly
  thresholds (rate burst per intent, spike multiplier, quiet-hour
  guards) alongside the current per-intent burst counts.

### Changed

- Bumped to v0.4.0 to align with the Python package.
- Extension now expects ai-execution-firewall ≥ 0.4.0 (the four new
  commands shell out to `guard scan` / `guard governance status` /
  `guard behavior status` which only exist in 0.4.0+).

## [0.3.0] — 2026-05-01

### Added

- **Secret-DB watcher** — passive detection of writes to your editor's
  `state.vscdb` (Code / Cursor on Windows / macOS / Linux). Surfaces a
  one-shot info notification when an extension modifies the secret store,
  plus a new command **AI Firewall: Show Recent Secret-DB Activity** that
  opens a webview log of timestamped events. Detection-only — the firewall
  doesn't patch fs.readFile or interfere with other extensions.
- **Smart-flow status bar toasts** — when the firewall auto-approves an
  action via *memory* (you've approved this kind of thing before in this
  project) or *inheritance* (you just typed an equivalent command in your
  own terminal), a quiet 4-second status-bar message surfaces what
  happened. Replaces the webview prompt for routine work — fewer
  interruptions.

### Changed

- Bumped to v0.3.0 to align with the Python package.
- Extension now expects ai-execution-firewall ≥ 0.3.0 (smart-flow features
  rely on the new `Decision.reason` strings: "memory match" / "inheritance").

## [0.2.1] — 2026-04-30

### Changed
- Refreshed README to lead with Marketplace install (rather than build-from-source), add badges, and document all six commands and the full demo flow (shell + SQL + HTTP). The 0.2.0 listing shipped with the older "build from source" README; this version updates the public Marketplace page.

## [0.2.0] — 2026-04-30

### Added
- Icon (`icon.png`) and Marketplace gallery metadata (`galleryBanner`, `keywords`, additional `categories`).
- Better `description` mentioning all four action types (shell / files / SQL / HTTP).
- `homepage`, `bugs`, and `repository` URLs pointing at the GitHub project.

### Changed
- Bumped `version` to **0.2.0** for the first Marketplace-targeted release.
- Publisher set to `sk-dev-ai`.

## [0.1.0] — 2026-04-30

### Added
- Six commands surfaced under `AI Firewall` in the Command Palette:
  - `Run Shell Command…` / `Evaluate Selected Text as Shell Command`
  - `Evaluate SQL Query…` / `Evaluate Selected Text as SQL`
  - `Evaluate HTTP Request…`
  - `Show Effective Policy`
- Themed approval webview rendering risk badge, intent/decision pills, findings, git context, and unified diff. Approve / Reject buttons.
- Status bar item (`🛡️ Firewall`) and dedicated "AI Firewall" output channel that streams CLI evaluation + execution traces.
- Three settings: `aiFirewall.guardPath`, `aiFirewall.rulesPath`, `aiFirewall.auditPath`.
- Fixed doubled `AI Firewall: AI Firewall:` prefix in command titles (now single-prefixed via the `category` field).

### Notes
- The extension is a thin wrapper around the [`ai-execution-firewall`](https://pypi.org/project/ai-execution-firewall/) Python CLI (`guard`). Install separately: `pip install ai-execution-firewall`.
