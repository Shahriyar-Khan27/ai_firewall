<div align="center">

<img src="icon.png" alt="AI Execution Firewall" width="128" height="128" />

# AI Execution Firewall — VS Code Extension

[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/sk-dev-ai.ai-execution-firewall.svg?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/sk-dev-ai.ai-execution-firewall.svg)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Shahriyar-Khan27/ai_firewall?style=social)](https://github.com/Shahriyar-Khan27/ai_firewall)

**Open source (MIT) — built in the open. Issues, PRs, and ideas all welcome on [GitHub](https://github.com/Shahriyar-Khan27/ai_firewall).**

</div>

In-editor approval UI for the [AI Execution Firewall](https://github.com/Shahriyar-Khan27/ai_firewall). Gate AI-generated **shell commands, file edits, SQL queries, and HTTP requests** before they execute — see the risk, findings, git context, and unified diff in a webview, then click Approve or Reject. Smart-flow auto-approves routine work silently.

```
VS Code command  →  guard eval  →  Decision  →  webview prompt  →  guard run --auto-approve
```

The extension never re-implements policy logic — it surfaces what the Python `guard` CLI returns.

## What's new in v0.5.0

The "active interceptor" release. The extension stops being a passive
Command-Palette tool and becomes the gate for the AI tools running
alongside it.

- **Auto-detect on first activation.** On startup we shell out to
  `guard mcp scan --json`, summarise what's unwrapped (Claude Code
  PreToolUse hook missing + per-host MCP server count), and show a
  non-modal toast: **[Wire All] [Pick…] [Not Now]**. The "Pick…"
  fallback opens a multi-select QuickPick. Dismissals are remembered
  per-fingerprint via globalState — adding a new MCP server re-arms
  the prompt automatically.
- **Localhost approval server.** When an AI tool tries something
  REQUIRE_APPROVAL hits, the firewall's hook routes the Decision to a
  127.0.0.1 endpoint the extension binds (token-authenticated via
  `~/.ai-firewall/extension.port`). The existing webview pops up; the
  user clicks Approve / Reject. AI is paused ≤30s waiting; on timeout
  the hook falls back to safe-default BLOCK. No more silent auto-deny
  on REQUIRE_APPROVAL.
- **Show Status** — markdown preview combining the wired hosts, the
  approval-server port, and the last 20 audit records.
- **Detect & Wire AI Tools** / **Unwire All AI Tools** — re-arm or
  reverse the auto-wire flow on demand.
- **Decision toasts** — every Approve/Reject from the loopback flow
  drops a 6-second status-bar message so the firewall's actions never
  feel invisible.

## What's new in v0.4.1

Patch release tracking the Python CLI. The extension itself is unchanged, but the underlying `guard scan` now reads from stdin when called with `-` or no positional argument — which makes the **Scan Text for Secrets and PII…** input-box flow more robust for very long pastes on Windows (no more PowerShell quoting edge cases on multi-line content).

## What's new in v0.4.0

The "enterprise round" of the underlying firewall — seven additions that move it from "useful CLI" to "deployable in a regulated org" — surface in the extension as four new Command Palette entries:

- **Scan Text for Secrets and PII…** / **Scan Selection for Secrets and PII** — paste-time DLP. Run any text through the firewall's combined secret + PII scanner (emails, US SSN, Luhn-validated credit cards, E.164 / US phone, IBAN, AWS / GitHub / Slack / Stripe / Anthropic / OpenAI tokens, PEM keys, JWTs, high-entropy fallbacks). Clean text gets a quiet info toast; major / critical findings open a preview document with severity + per-finding lines.
- **Show Governance Status** — opens a preview document with current rate-limit counters per intent, loop-detection settings, and 24h API byte spend (mirrors `guard governance status`).
- **Show Behavior Status** — current per-intent burst counts plus configured anomaly thresholds (rate burst, last-hour spike vs 24h median, quiet-hour outlier guards). Mirrors `guard behavior status`.

Under the hood, the underlying CLI now also enforces **AI-SBOM** validation on `pip install` / `npm install` / `cargo install` / `gem install` (catches typosquats and hallucinated package names), **network egress control** (`curl` / `wget` / `nc` / `socat` route through the same gate as `guard api`), and **fine-grained RBAC** (per-role intent / file-glob / MCP-tool deny lists from `~/.ai-firewall/guard.toml`). Audit records can also broadcast to **SIEM sinks** (syslog / Splunk HEC / generic HTTPS webhook / stdout).

## What's new in v0.3.0

- **Smart-flow status-bar toasts** — when the firewall auto-approves an action via *memory* (you've approved this kind of thing before in this project) or *inheritance* (you just typed an equivalent command in your own terminal), a quiet 4-second status-bar message surfaces what happened. No webview, no friction. Approval fatigue solved.
- **Show Recent Secret-DB Activity** — a new command that opens a webview log of writes to your editor's `state.vscdb` (Code / Cursor). Detection-only — the firewall doesn't patch fs.readFile or interfere with other extensions, but you finally have a forensic trail if something siphons API keys.
- **Tighter pipeline** — the underlying `guard` CLI now uses a real bashlex AST. Obfuscated commands like `echo "<base64>" | base64 -d | sh` are decoded and the inner `rm -rf /` is what gets policy-checked.

See the project [CHANGELOG](https://github.com/Shahriyar-Khan27/ai_firewall/blob/main/CHANGELOG.md) for the full list.

## Install

> **VS Code → Extensions panel → search "AI Execution Firewall" → Install**

Or from the command line:

```bash
code --install-extension sk-dev-ai.ai-execution-firewall
```

## Prerequisites

The extension requires the [`guard` Python CLI](https://pypi.org/project/ai-execution-firewall/) on PATH:

```bash
pip install ai-execution-firewall    # 0.4.0+ required for scan / governance / behavior commands
guard --help                          # confirm it's available
```

Or grab a [standalone binary](https://github.com/Shahriyar-Khan27/ai_firewall/releases/latest) (no Python required) and put it on your PATH.

If `guard` isn't on PATH (e.g. installed inside a virtualenv), set the absolute path in **Settings → AI Firewall: Guard Path**, e.g. `C:/Users/you/.venv/Scripts/guard.exe`.

## Commands

All under the `AI Firewall:` prefix in the Command Palette (Ctrl+Shift+P):

| Command | What it does |
|---|---|
| **Run Shell Command…** | Prompt for a shell command, evaluate, open approval webview if needed, execute via `guard run --auto-approve` on accept. |
| **Evaluate Selected Text as Shell Command** | Same flow, using the editor's current selection as the command. |
| **Evaluate SQL Query…** | Prompt for SQL, evaluate with `sqlglot`. Risky queries (DELETE without WHERE, DROP DATABASE, …) trigger the approval webview. Analyze-only — never touches a real DB. |
| **Evaluate Selected Text as SQL** | Same SQL flow, using the editor's selection. |
| **Evaluate HTTP Request…** | Pick HTTP method (GET / POST / PUT / PATCH / DELETE / …), enter URL. Detects SSRF, cloud-metadata endpoints, URL credentials, leaked secrets in body / Authorization headers. Analyze-only — never makes the request. |
| **Show Effective Policy** | Open the merged YAML rules in a preview tab. |
| **Show Recent Secret-DB Activity** *(0.3.0)* | Open a read-only webview listing recent writes to your editor's `state.vscdb` so you can spot extensions that read your secrets. |
| **Scan Text for Secrets and PII…** *(new in 0.4.0)* | Paste any text into an input box; the firewall's combined secret + PII scanner returns a severity ladder + per-finding list. Useful as a paste-time check before pasting code or logs into an external tool. |
| **Scan Selection for Secrets and PII** *(new in 0.4.0)* | Same scan, run against the active editor's current selection. |
| **Show Governance Status** *(new in 0.4.0)* | Preview document with current rate-limit counters per intent, loop-detection settings, and 24h API byte spend. |
| **Show Behavior Status** *(new in 0.4.0)* | Configured anomaly thresholds (rate burst, last-hour spike vs 24h median, quiet-hour guards) alongside current per-intent burst counts. |

A status bar item (`🛡️ Firewall`, bottom-left) is a one-click shortcut to **Run Shell Command…**.

## Demo flow

After install + `pip install ai-execution-firewall`, try these in the Command Palette:

| Action type | Input | Expected outcome |
|---|---|---|
| Shell | `echo hello` | ALLOW — runs immediately, output streams to the **AI Firewall** output channel |
| Shell | `rm -rf /` | BLOCK — red error toast, no execution |
| Shell | `rm ./tmp.txt` (file exists) | REQUIRE_APPROVAL — webview opens with risk badge, file count, Approve / Reject |
| Shell | obfuscated `echo "cm0gLXJmIC8=" \| base64 -d \| sh` | BLOCK — decoded as `rm -rf /` (semantic parser caught it) |
| Shell | repeat of an earlier-approved `npm run build` | ALLOW silently — *"auto-approved (learned from you)"* status-bar toast |
| SQL | `DELETE FROM users` | REQUIRE_APPROVAL — CRITICAL (no WHERE), shown in webview with the finding |
| SQL | `DROP DATABASE prod` | BLOCK — red toast, never reaches an adapter |
| HTTP | `GET http://169.254.169.254/` | REQUIRE_APPROVAL — CRITICAL (cloud metadata SSRF) |
| Scan | `my SSN is 123-45-6789` | severity CRITICAL — finding "PII: US SSN" *(0.4.0)* |
| Scan | `pip install requets` *(via Run Shell)* | BLOCK — possible typosquat of `requests` *(0.4.0 SBOM)* |

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `aiFirewall.guardPath` | `guard` | Absolute path to the `guard` CLI. Set this if it's not on PATH. |
| `aiFirewall.rulesPath` | _(empty)_ | Custom rules YAML; empty = shipped defaults. |
| `aiFirewall.auditPath` | _(empty)_ | Audit log JSONL location; empty = `./logs/audit.jsonl`. |

## Architecture

- **`src/firewall.ts`** — spawns the `guard` CLI as a subprocess (`guard eval`, `guard run`, `guard sql`, `guard api`), parses the Decision JSON.
- **`src/webview.ts`** — renders the approval UI: risk badge, intent / decision pills, findings list, git context, unified diff with syntax colours.
- **`src/secret_watcher.ts`** *(new in 0.3.0)* — passive `FileSystemWatcher` on the editor's secret-store DB. Detection-only.
- **`src/extension.ts`** — registers commands around an `ActionRunner` interface so shell / SQL / HTTP share one `evaluate → approve → run` pipeline. Streams output to the **AI Firewall** output channel and toasts smart-flow auto-approvals to the status bar.

The extension surfaces whatever `code_findings` the Python pipeline emits, so SQL warnings, AST findings, git context, URL / secret findings all render through the same webview without per-type UI code.

## For contributors — build from source

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall/vscode-extension
npm install
npm run compile
```

Open the `vscode-extension/` folder in VS Code and press **F5** to launch an Extension Development Host with the local build loaded.

To produce an installable `.vsix` (e.g. for sideloading or Marketplace re-publish):

```bash
npx vsce package --no-yarn
```

## Contributing

<img src="icon.png" alt="" width="64" height="64" align="left" hspace="12" />

This extension is fully open source under the MIT license alongside the Python firewall it gates. The whole project lives at <https://github.com/Shahriyar-Khan27/ai_firewall>.

**Where help is most useful:**
- **New host detectors** — Aider / Cline / Zed / future AI-IDE configs evolve faster than any one maintainer can track. PRs adding detectors to [`ai_firewall/discovery/mcp_detector.py`](https://github.com/Shahriyar-Khan27/ai_firewall/blob/main/ai_firewall/discovery/mcp_detector.py) keep the extension's auto-wire flow useful for everyone.
- **Approval webview polish** — better diff rendering, dark-theme tweaks, accessibility, keyboard shortcuts — `vscode-extension/src/webview.ts` welcomes contributions.
- **Translations of webview copy** — currently English-only.
- **Bug reports + feature requests** — file at <https://github.com/Shahriyar-Khan27/ai_firewall/issues>. Real-world AI-tool screenshots ("here's what Cursor / Continue / Cline did, and how the firewall handled it") are especially valued.

**To build from source:**

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall/vscode-extension
npm install
npm run compile
```

Open `vscode-extension/` in VS Code and press **F5** to launch an Extension Development Host with the local build.

**Star the repo if you find it useful** — it's the simplest way to signal this kind of safety tooling is worth investing in.

## Links

- **Source**: https://github.com/Shahriyar-Khan27/ai_firewall
- **Issues**: https://github.com/Shahriyar-Khan27/ai_firewall/issues
- **Python package on PyPI**: https://pypi.org/project/ai-execution-firewall/
- **CHANGELOG**: [CHANGELOG.md](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE). Free for commercial and personal use.
