/**
 * Passive Cursor / VS Code secret-DB watcher.
 *
 * VS Code (and forks like Cursor) store secrets — API keys, OAuth tokens,
 * remote credentials — in a SQLite-backed `state.vscdb` file inside the
 * user's `globalStorage`. Any installed extension can read that file at
 * runtime, including malicious ones.
 *
 * The firewall can't *prevent* those reads (extensions live in the same
 * Node process as us), but we *can* notice when the file is modified and
 * surface that to the user. This is detection-only by design — we never
 * patch fs at runtime, never lie to other extensions, never pretend keys
 * don't exist.
 *
 * What we do:
 *   1. Locate the active host's secret-storage path.
 *   2. Watch it with a FileSystemWatcher.
 *   3. Each time it's written, log a timestamped record + show a low-noise
 *      info notification once per session.
 *   4. Expose a command "AI Firewall: Show Recent Secret-DB Activity" that
 *      lists the recorded events.
 */
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

interface SecretEvent {
  ts: number;
  path: string;
  size: number;
  kind: "modified" | "created";
}

const RECENT_LIMIT = 50;

export class SecretWatcher implements vscode.Disposable {
  private events: SecretEvent[] = [];
  private watchers: vscode.FileSystemWatcher[] = [];
  private outputChannel: vscode.OutputChannel;
  private warned = false;

  constructor(private context: vscode.ExtensionContext, outputChannel: vscode.OutputChannel) {
    this.outputChannel = outputChannel;
  }

  start(): void {
    const targets = candidateSecretPaths(this.context);
    for (const target of targets) {
      try {
        const dir = path.dirname(target);
        const base = path.basename(target);
        const watcher = vscode.workspace.createFileSystemWatcher(
          new vscode.RelativePattern(vscode.Uri.file(dir), base),
          /* ignoreCreateEvents */ false,
          /* ignoreChangeEvents */ false,
          /* ignoreDeleteEvents */ true,
        );
        watcher.onDidChange(() => this.record(target, "modified"));
        watcher.onDidCreate(() => this.record(target, "created"));
        this.watchers.push(watcher);
        this.context.subscriptions.push(watcher);
        this.outputChannel.appendLine(`[secret-watch] watching ${target}`);
      } catch (e) {
        this.outputChannel.appendLine(`[secret-watch] could not watch ${target}: ${(e as Error).message}`);
      }
    }
  }

  recentEvents(): readonly SecretEvent[] {
    return [...this.events].reverse();
  }

  private record(p: string, kind: "modified" | "created"): void {
    let size = 0;
    try {
      size = fs.statSync(p).size;
    } catch {
      // not fatal — record without size
    }
    const evt: SecretEvent = { ts: Date.now(), path: p, kind, size };
    this.events.push(evt);
    if (this.events.length > RECENT_LIMIT) this.events.shift();

    this.outputChannel.appendLine(
      `[secret-watch] ${new Date(evt.ts).toISOString()}  ${kind}  ${p}  (${size} B)`,
    );

    if (!this.warned) {
      this.warned = true;
      void vscode.window.showInformationMessage(
        "🛡️ AI Firewall: your editor's secret store changed. " +
          "Run 'AI Firewall: Show Recent Secret-DB Activity' to inspect.",
        "Show",
      ).then((choice) => {
        if (choice === "Show") {
          void vscode.commands.executeCommand("aiFirewall.showSecretActivity");
        }
      });
    }
  }

  dispose(): void {
    for (const w of this.watchers) {
      try {
        w.dispose();
      } catch {
        /* ignore */
      }
    }
    this.watchers = [];
  }
}

/**
 * Open a webview listing recent secret-DB events. Read-only, no execution.
 */
export function showSecretActivityWebview(
  context: vscode.ExtensionContext,
  watcher: SecretWatcher,
): void {
  const panel = vscode.window.createWebviewPanel(
    "aiFirewallSecretActivity",
    "Firewall: Secret-DB Activity",
    vscode.ViewColumn.Active,
    { enableScripts: false, retainContextWhenHidden: false },
  );
  const events = watcher.recentEvents();
  panel.webview.html = renderHtml(events);
}

// ---------------------------------------------------------------------------
// Path discovery
// ---------------------------------------------------------------------------

/**
 * Best-effort list of secret-DB paths for the host editor we're running in.
 *
 * VS Code:  $APPDATA/Code/User/globalStorage/state.vscdb           (Windows)
 *           ~/Library/Application Support/Code/User/globalStorage/state.vscdb
 *           ~/.config/Code/User/globalStorage/state.vscdb           (Linux)
 *
 * Cursor:   same layout but `Cursor` instead of `Code`.
 */
function candidateSecretPaths(context: vscode.ExtensionContext): string[] {
  const out = new Set<string>();
  // The official, host-agnostic way: derive the storage root from this extension's globalStoragePath.
  // It's something like .../<host>/User/globalStorage/<publisher.extensionId>/.
  // The actual state.vscdb is two levels up, in `globalStorage/`.
  try {
    const ourGlobal = context.globalStorageUri.fsPath;
    const globalStorageRoot = path.resolve(ourGlobal, "..");
    out.add(path.join(globalStorageRoot, "state.vscdb"));
  } catch {
    // ignore
  }

  // Belt-and-braces: known-static paths for the common hosts.
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const appdata = process.env.APPDATA || "";

  const candidates: string[] = [];
  if (process.platform === "win32") {
    if (appdata) {
      candidates.push(path.join(appdata, "Code", "User", "globalStorage", "state.vscdb"));
      candidates.push(path.join(appdata, "Cursor", "User", "globalStorage", "state.vscdb"));
    }
  } else if (process.platform === "darwin") {
    if (home) {
      candidates.push(path.join(home, "Library", "Application Support", "Code", "User", "globalStorage", "state.vscdb"));
      candidates.push(path.join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "state.vscdb"));
    }
  } else {
    if (home) {
      candidates.push(path.join(home, ".config", "Code", "User", "globalStorage", "state.vscdb"));
      candidates.push(path.join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"));
    }
  }

  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) {
        out.add(c);
      }
    } catch {
      /* ignore */
    }
  }

  return [...out];
}

// ---------------------------------------------------------------------------
// HTML renderer
// ---------------------------------------------------------------------------

function renderHtml(events: readonly SecretEvent[]): string {
  const rows = events
    .map(
      (e) =>
        `<tr><td>${esc(new Date(e.ts).toLocaleString())}</td>` +
        `<td>${esc(e.kind)}</td>` +
        `<td>${esc(String(e.size))}</td>` +
        `<td>${esc(e.path)}</td></tr>`,
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Secret-DB Activity</title>
<style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 18px; }
  h1 { font-size: 1.05rem; margin: 0 0 6px 0; }
  .muted { opacity: 0.7; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-family: var(--vscode-editor-font-family); font-size: 0.9rem; }
  th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--vscode-textBlockQuote-background); }
  th { opacity: 0.85; }
  tr:hover td { background: var(--vscode-textBlockQuote-background); }
</style>
</head>
<body>
  <h1>🛡️ AI Firewall — Secret-DB Activity</h1>
  <p class="muted">
    Detection-only. The firewall doesn't prevent reads — it just records when
    your editor's secret store changes, so you have a forensic trail if a
    malicious extension siphons API keys.
  </p>
  ${
    events.length === 0
      ? `<p class="muted"><em>No activity recorded this session.</em></p>`
      : `<table>
          <thead><tr><th>When</th><th>Kind</th><th>Size</th><th>Path</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`
  }
</body>
</html>`;
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
