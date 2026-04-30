# AI Execution Firewall — VS Code Extension

In-editor approval UI for the [AI Execution Firewall](../README.md).
Wraps the `guard` CLI; every action gets evaluated by the same Python pipeline.

```
VS Code command  →  guard eval  →  Decision  →  webview prompt  →  guard run --auto-approve
```

## Prerequisites

1. **Node.js 18+** and **npm** (for compiling the extension).
2. **The `guard` CLI** on PATH, or a configured absolute path.
   From the project root:
   ```bash
   pip install -e .
   guard --help    # confirm it's on PATH
   ```

## Build

```bash
cd vscode-extension
npm install
npm run compile
```

This emits `out/extension.js`. To live-rebuild while editing: `npm run watch`.

## Run / debug

1. Open `vscode-extension/` in VS Code.
2. Press **F5** — this launches an Extension Development Host with the extension loaded.
3. In the host window, open the Command Palette (Ctrl+Shift+P) and run:
   - **AI Firewall: Run Shell Command…** — type a command, see the decision/approval flow
   - **AI Firewall: Evaluate Selected Text** — same flow with the editor selection
   - **AI Firewall: Show Effective Policy** — opens the merged YAML in a preview tab

## Demo flow

| Command typed | Expected UI |
|---|---|
| `echo hello` | ALLOW — runs immediately, output in "AI Firewall" channel |
| `rm -rf /` | BLOCK — error toast with reason, no execution |
| `rm ./tmp.txt` (file exists) | webview with risk=MEDIUM, impact summary, Approve/Reject buttons |

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `aiFirewall.guardPath` | `guard` | Path to the `guard` CLI |
| `aiFirewall.rulesPath` | _(empty)_ | Custom rules YAML; empty = shipped defaults |
| `aiFirewall.auditPath` | _(empty)_ | Audit log JSONL location |

If `guard` isn't on PATH, set `aiFirewall.guardPath` to the absolute path, e.g.
`C:/Users/you/myproject/.venv-firewall/Scripts/guard.exe`.

## Architecture

- **`src/firewall.ts`** — spawns the `guard` CLI as a subprocess, parses Decision JSON.
- **`src/webview.ts`** — renders the approval UI (risk badge, findings, syntax-coloured diff).
- **`src/extension.ts`** — registers commands, drives the eval → approve → run flow, streams output to the "AI Firewall" output channel.

The extension never re-implements policy logic — it only surfaces what the Python firewall returns.
