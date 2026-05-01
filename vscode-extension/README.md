<p align="center">
  <img src="https://raw.githubusercontent.com/Shahriyar-Khan27/ai_firewall/main/vscode-extension/icon.png" alt="AI Execution Firewall" width="128" height="128" />
</p>

<h1 align="center">AI Execution Firewall</h1>

<p align="center"><strong>The in-editor approval surface for the AI Execution Firewall.</strong></p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall"><img src="https://vsmarketplacebadges.dev/version-short/sk-dev-ai.ai-execution-firewall.png?label=VS%20Marketplace" alt="VS Marketplace"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall"><img src="https://vsmarketplacebadges.dev/installs-short/sk-dev-ai.ai-execution-firewall.png" alt="Installs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
  <a href="https://github.com/Shahriyar-Khan27/ai_firewall"><img src="https://img.shields.io/github/stars/Shahriyar-Khan27/ai_firewall?style=social" alt="GitHub stars"></a>
</p>

---

This extension is the in-editor approval surface for the [AI Execution Firewall](https://github.com/Shahriyar-Khan27/ai_firewall): a deterministic policy gate that sits between AI coding agents (Claude Code, Cursor, Copilot, Continue, Cline, Zed) and the host system. It does not re-implement policy logic. It shells out to the `guard` Python CLI and renders the resulting Decision in a themed approval webview with the risk badge, findings, git context, and a syntax-coloured unified diff.

## Features

**Approval webview**

Risky actions raised by AI agents (or by the operator running `guard run`) open a themed webview containing the risk badge, intent and decision pills, the findings list, git context (uncommitted, untracked, gitignored markers), and a syntax-coloured unified diff. The operator selects Approve or Reject; the response is recorded in the audit log and, on Approve, in pattern memory so future identical actions auto-approve.

**Auto-detect and one-notification setup**

On first activation, the extension shells out to `guard mcp scan --json` and reads `~/.claude/settings.json` to enumerate every AI tool already configured on the host. A single non-modal notification offers Wire All, Pick, or Not Now. Wiring installs the Claude Code PreToolUse hook and runs `guard mcp install` for each detected MCP server. From that point, any agent action that hits REQUIRE_APPROVAL opens the approval webview automatically; no manual command invocation is required.

**Active interception via a localhost handshake**

The extension binds a token-authenticated HTTP endpoint on `127.0.0.1` and publishes the port at `~/.ai-firewall/extension.port`. The Claude Code PreToolUse hook and the MCP transparent proxy POST REQUIRE_APPROVAL decisions to that endpoint and block for up to thirty seconds for the operator's response. On timeout, the call falls back to a safe-default BLOCK. The endpoint is closed and the port file removed when the extension deactivates.

**Smart-flow auto-approvals**

Routine work passes silently. When the firewall auto-approves an action via memory (a previously-approved equivalent in the same project) or inheritance (the operator just ran the same command in the host shell), a status-bar message confirms the auto-approval without opening the webview.

**Paste-time DLP and SBOM checks**

The Command Palette exposes paste-time scanners. **Scan Text for Secrets and PII** and **Scan Selection for Secrets and PII** run text through the firewall's combined secret and PII scanner before the operator pastes it into a chat, log, or ticket. AI-SBOM validation against PyPI, npm, crates.io, and RubyGems is enforced automatically when the AI issues an install command via Run Shell Command.

**Status surfaces**

**Show Status**, **Show Governance Status**, and **Show Behavior Status** render markdown previews of the wired hosts, the approval-server port, the last twenty audit decisions, the current rate-limit counters, the 24-hour API byte spend, and the configured anomaly thresholds.

**Passive secret-DB watcher**

A `FileSystemWatcher` on the editor's `state.vscdb` detects writes to the editor's secret store. Detection-only; the extension does not patch `fs.readFile` or interfere with other extensions. **Show Recent Secret-DB Activity** opens a read-only webview listing recent writes.

## Quick start

1. Install the extension from the Marketplace (or `code --install-extension sk-dev-ai.ai-execution-firewall`).
2. Install the `guard` Python CLI (see [Requirements](#requirements)).
3. Reload VS Code. The extension detects configured AI tools and offers a single notification to wire firewall protection. Click **Wire All**.

From this point, AI tool actions that the firewall flags as REQUIRE_APPROVAL open the approval webview automatically. Run `guard run "<command>"` from the integrated terminal to evaluate ad-hoc commands through the same policy pipeline.

## Requirements

The extension requires the `guard` Python CLI on PATH:

```bash
pip install ai-execution-firewall    # version 0.5.0 or later
guard --help                          # confirm the CLI resolves
```

A standalone PyInstaller binary is published with each GitHub release for environments without Python. Download `guard-{linux,macos,macos-arm64,windows}` from the [latest release](https://github.com/Shahriyar-Khan27/ai_firewall/releases/latest) and place it on PATH.

If the `guard` executable is not on PATH (for example, installed inside a virtualenv), set the absolute path in **Settings → AI Firewall: Guard Path**, e.g. `C:/Users/you/.venv/Scripts/guard.exe`.

## Useful commands

All commands are registered under the `AI Firewall:` prefix in the Command Palette (Ctrl+Shift+P).

| Command | Description |
|---|---|
| Run Shell Command | Prompt for a shell command, evaluate it, open the approval webview if needed, then execute via `guard run --auto-approve` on accept. |
| Evaluate Selected Text as Shell Command | The same flow, using the editor's current selection as the command. |
| Evaluate SQL Query | Prompt for SQL and evaluate via `sqlglot`. Risky queries (DELETE without WHERE, DROP DATABASE, and similar) trigger the approval webview. Analyze-only; never opens a database connection. |
| Evaluate Selected Text as SQL | The same SQL flow on the editor's selection. |
| Evaluate HTTP Request | Pick an HTTP method, enter a URL. Detects SSRF, cloud-metadata endpoints, URL credentials, and leaked secrets in body or Authorization headers. Analyze-only; never issues the request. |
| Show Effective Policy | Open the merged YAML rules in a preview tab. |
| Show Recent Secret-DB Activity | Open a read-only webview listing recent writes to the editor's `state.vscdb`. |
| Scan Text for Secrets and PII | Paste any text into an input box. The combined secret and PII scanner returns a severity ladder plus per-finding lines. |
| Scan Selection for Secrets and PII | The same scan applied to the editor's current selection. |
| Show Governance Status | Preview document with current rate-limit counters per intent, loop-detection settings, and the 24-hour API byte spend. |
| Show Behavior Status | Configured anomaly thresholds and current per-intent burst counts. |
| Detect & Wire AI Tools | Re-arm and re-run the auto-detect flow, including any AI tools configured since the last scan. |
| Unwire All AI Tools | Reverse the auto-wire integration. Modal confirmation; removes the Claude Code PreToolUse hook and unwraps every wrapped MCP server. |
| Show Status | Markdown summary of currently wired hosts, the approval-server port, and the last twenty audit decisions. |

A status-bar item (`🛡️ Firewall`, bottom-left) is a one-click shortcut to **Run Shell Command**.

## Extension settings

| Setting | Default | Purpose |
|---|---|---|
| `aiFirewall.guardPath` | `guard` | Absolute path to the `guard` CLI. Set when the executable is not on PATH (for example, inside a virtualenv). |
| `aiFirewall.rulesPath` | (empty) | Path to a custom rules YAML file. Empty falls back to the shipped defaults. |
| `aiFirewall.auditPath` | (empty) | Path to the audit JSONL log. Empty falls back to `./logs/audit.jsonl`. |

## Example flow

| Action type | Input | Outcome |
|---|---|---|
| Shell | `echo hello` | ALLOW. Output streams to the AI Firewall output channel. |
| Shell | `rm -rf /` | BLOCK. Surfaced as a red error notification; no execution. |
| Shell | `rm ./tmp.txt` (file exists) | REQUIRE_APPROVAL. Webview opens with the risk badge, file count, and Approve / Reject controls. |
| Shell | Obfuscated `echo "cm0gLXJmIC8=" \| base64 -d \| sh` | BLOCK. Decoded as `rm -rf /` by the bashlex AST and obfuscation decoders. |
| Shell | Repeat of a previously-approved `npm run build` | ALLOW silently. Status-bar message confirms the auto-approval came from memory. |
| SQL | `DELETE FROM users` | REQUIRE_APPROVAL. CRITICAL (no WHERE clause). Finding shown in the webview. |
| SQL | `DROP DATABASE prod` | BLOCK. Never reaches an adapter. |
| HTTP | `GET http://169.254.169.254/` | REQUIRE_APPROVAL. CRITICAL (cloud metadata endpoint, SSRF vector). |
| Scan | `my SSN is 123-45-6789` | Severity CRITICAL. Finding "PII: US SSN". |
| Scan | `pip install requets` (via Run Shell Command) | BLOCK. Possible typosquat of `requests`. |

## Known issues

- The Marketplace listing's contributor sidebar may show a stale entry after a recent history rewrite. GitHub's contributor-graph cache typically refreshes within a few weeks; the extension itself is unaffected.
- The current detection of MCP host configurations covers Claude Code, Cursor, Continue, and any workspace `.mcp.json`. Aider, Cline, and Zed have evolving config layouts and are best supported by community pull requests against `ai_firewall/discovery/mcp_detector.py`.

## Release notes

For the full release-by-release feature list, see the project [CHANGELOG](https://github.com/Shahriyar-Khan27/ai_firewall/blob/main/CHANGELOG.md). Recent highlights:

**0.5.0** Active interceptor. Auto-detect of AI tools on first activation; one-notification wire-up of the Claude Code PreToolUse hook and every detected MCP server. Localhost approval server replaces the previous silent auto-deny on REQUIRE_APPROVAL with the existing webview prompt. New commands: Detect & Wire AI Tools, Unwire All AI Tools, Show Status.

**0.4.0** Extension surfaces the firewall's enterprise-round capabilities. New commands: Scan Text for Secrets and PII, Scan Selection for Secrets and PII, Show Governance Status, Show Behavior Status. Underlying CLI gains AI-SBOM validation, network egress control, fine-grained RBAC, and SIEM-ready audit sinks.

**0.3.0** Smart-flow status-bar messages replace approval prompts for routine work. New command: Show Recent Secret-DB Activity. The underlying CLI moves to a real bashlex AST so obfuscated commands are decoded before policy evaluation.

## Questions, issues, and contributions

The extension is open source under the MIT license alongside the Python firewall it gates. The full project lives at <https://github.com/Shahriyar-Khan27/ai_firewall>.

- **Bug reports and feature requests**: <https://github.com/Shahriyar-Khan27/ai_firewall/issues>
- **Security findings**: please use [GitHub Security advisories](https://github.com/Shahriyar-Khan27/ai_firewall/security/advisories/new) rather than the public issues tracker.
- **Source for build, debug, and packaging instructions**: see [vscode-extension/](https://github.com/Shahriyar-Khan27/ai_firewall/tree/main/vscode-extension) and the project README's Release flow section.

Areas where contributions are most welcome: new host detectors (Aider, Cline, Zed), approval webview polish (diff rendering, accessibility, keyboard shortcuts), and translations of webview copy. Build, debug, and packaging steps are documented in the project's [CONTRIBUTING.md](https://github.com/Shahriyar-Khan27/ai_firewall/blob/main/CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE). Free for commercial and personal use.
