# AI Execution Firewall — VS Code Extension

[![VS Marketplace](https://img.shields.io/visual-studio-marketplace/v/sk-dev-ai.ai-execution-firewall.svg?label=VS%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/sk-dev-ai.ai-execution-firewall.svg)](https://marketplace.visualstudio.com/items?itemName=sk-dev-ai.ai-execution-firewall)

In-editor approval UI for the [AI Execution Firewall](https://github.com/Shahriyar-Khan27/ai_firewall). Gate AI-generated **shell commands, file edits, SQL queries, and HTTP requests** before they execute — see the risk, findings, git context, and unified diff in a webview, then click Approve or Reject.

```
VS Code command  →  guard eval  →  Decision  →  webview prompt  →  guard run --auto-approve
```

The extension never re-implements policy logic — it surfaces what the Python `guard` CLI returns.

## Install

> **VS Code → Extensions panel → search "AI Execution Firewall" → Install**

Or from the command line:

```bash
code --install-extension sk-dev-ai.ai-execution-firewall
```

## Prerequisites

The extension requires the [`guard` Python CLI](https://pypi.org/project/ai-execution-firewall/) on PATH:

```bash
pip install ai-execution-firewall
guard --help    # confirm it's available
```

If `guard` isn't on PATH (e.g. installed inside a virtualenv), set the absolute path in **Settings → AI Firewall: Guard Path**, e.g. `C:/Users/you/.venv/Scripts/guard.exe`.

## Commands

Six commands, all under the `AI Firewall:` prefix in the Command Palette (Ctrl+Shift+P):

| Command | What it does |
|---|---|
| **Run Shell Command…** | Prompts for a shell command, evaluates, opens approval webview if needed, executes via `guard run --auto-approve` on accept. |
| **Evaluate Selected Text as Shell Command** | Same flow, using the editor's current selection as the command. |
| **Evaluate SQL Query…** | Prompts for SQL, evaluates with `sqlglot`. Risky queries (DELETE without WHERE, DROP DATABASE, …) trigger the approval webview. Analyze-only — never touches a real DB. |
| **Evaluate Selected Text as SQL** | Same SQL flow, using the editor's selection. |
| **Evaluate HTTP Request…** | Pick HTTP method (GET / POST / PUT / PATCH / DELETE / …), enter URL. Detects SSRF, cloud-metadata endpoints, URL credentials, leaked secrets in body / Authorization headers. Analyze-only — never makes the request. |
| **Show Effective Policy** | Opens the merged YAML rules in a preview tab. |

A status bar item (`🛡️ Firewall`, bottom-left) is a one-click shortcut to **Run Shell Command…**.

## Demo flow

After install + `pip install ai-execution-firewall`, try these in the Command Palette:

| Action type | Input | Expected outcome |
|---|---|---|
| Shell | `echo hello` | ALLOW — runs immediately, output streams to the **AI Firewall** output channel |
| Shell | `rm -rf /` | BLOCK — red error toast, no execution |
| Shell | `rm ./tmp.txt` (where the file exists) | REQUIRE_APPROVAL — webview opens with risk badge, file count, Approve / Reject buttons |
| SQL | `DELETE FROM users` | REQUIRE_APPROVAL — CRITICAL (no WHERE), shown in webview with the finding |
| SQL | `DROP DATABASE prod` | BLOCK — red toast, never reaches an adapter |
| HTTP | `GET http://169.254.169.254/` | REQUIRE_APPROVAL — CRITICAL (cloud metadata SSRF) |

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `aiFirewall.guardPath` | `guard` | Absolute path to the `guard` CLI. Set this if it's not on PATH. |
| `aiFirewall.rulesPath` | _(empty)_ | Custom rules YAML; empty = shipped defaults. |
| `aiFirewall.auditPath` | _(empty)_ | Audit log JSONL location; empty = `./logs/audit.jsonl`. |

## Architecture

- **`src/firewall.ts`** — spawns the `guard` CLI as a subprocess (`guard eval`, `guard run`, `guard sql`, `guard api`), parses the Decision JSON.
- **`src/webview.ts`** — renders the approval UI: risk badge, intent / decision pills, findings list, git context, unified diff with syntax colours.
- **`src/extension.ts`** — registers commands around an `ActionRunner` interface so shell / SQL / HTTP share one `evaluate → approve → run` pipeline. Streams output to the **AI Firewall** output channel.

The extension surfaces whatever `code_findings` the Python pipeline emits, so SQL warnings, AST findings, git context, and URL / secret findings all render through the same webview without per-type UI code.

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

## Links

- **Source**: https://github.com/Shahriyar-Khan27/ai_firewall
- **Issues**: https://github.com/Shahriyar-Khan27/ai_firewall/issues
- **Python package on PyPI**: https://pypi.org/project/ai-execution-firewall/
- **CHANGELOG**: [CHANGELOG.md](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE).
