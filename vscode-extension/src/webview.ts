import * as vscode from "vscode";
import { Decision } from "./firewall";

export type ApprovalChoice = "approve" | "reject";

/**
 * Show the approval webview and resolve with the user's choice.
 *
 * The panel renders the firewall's risk badge, intent, reason, impact summary,
 * findings, and unified diff, then waits for the user to click Approve or Reject.
 * Disposal of the panel without a click resolves to "reject" (safe default).
 */
export function showApprovalPanel(
  context: vscode.ExtensionContext,
  command: string,
  decision: Decision
): Promise<ApprovalChoice> {
  const panel = vscode.window.createWebviewPanel(
    "aiFirewallApproval",
    `Firewall: ${truncate(command, 40)}`,
    vscode.ViewColumn.Active,
    { enableScripts: true, retainContextWhenHidden: false }
  );

  panel.webview.html = renderHtml(command, decision, panel.webview, context.extensionUri);

  return new Promise<ApprovalChoice>((resolve) => {
    let settled = false;
    const settle = (choice: ApprovalChoice) => {
      if (settled) return;
      settled = true;
      resolve(choice);
      panel.dispose();
    };
    panel.webview.onDidReceiveMessage((msg: { type: string }) => {
      if (msg.type === "approve") settle("approve");
      else if (msg.type === "reject") settle("reject");
    });
    panel.onDidDispose(() => settle("reject"));
  });
}

function renderHtml(
  command: string,
  decision: Decision,
  webview: vscode.Webview,
  _extensionUri: vscode.Uri
): string {
  const nonce = newNonce();
  const csp = `default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';`;
  const riskClass = `risk-${decision.risk.toLowerCase()}`;
  const findingsHtml = decision.impact.code_findings.length
    ? `<ul class="findings">${decision.impact.code_findings.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>`
    : `<p class="muted">none</p>`;

  const gitHtml = renderGit(decision.impact.git);
  const diffHtml = decision.impact.diff
    ? `<pre class="diff">${renderDiff(decision.impact.diff)}</pre>`
    : `<p class="muted">no diff (not a write)</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <title>Firewall Approval</title>
  <style>
    body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 18px; line-height: 1.45; }
    h1 { font-size: 1.05rem; margin: 0 0 6px 0; }
    h2 { font-size: 0.9rem; margin: 18px 0 6px 0; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.75; }
    .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
    .badge { padding: 2px 10px; border-radius: 10px; font-size: 0.78rem; font-weight: 600; letter-spacing: 0.04em; }
    .risk-low { background: #2b7a2b; color: white; }
    .risk-medium { background: #b07c1e; color: white; }
    .risk-high { background: #c0392b; color: white; }
    .risk-critical { background: #6e0e0e; color: white; }
    .pill { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); padding: 2px 8px; border-radius: 8px; font-size: 0.78rem; }
    .cmd { background: var(--vscode-textBlockQuote-background); padding: 8px 10px; border-radius: 4px; font-family: var(--vscode-editor-font-family); white-space: pre-wrap; word-break: break-all; }
    .reason { opacity: 0.85; margin: 4px 0 12px 0; }
    .findings li { margin: 2px 0; }
    .muted { opacity: 0.6; font-style: italic; margin: 4px 0; }
    .diff { background: var(--vscode-textBlockQuote-background); padding: 10px; border-radius: 4px; font-family: var(--vscode-editor-font-family); font-size: 0.88rem; max-height: 360px; overflow: auto; white-space: pre; }
    .diff .add { color: #2b9b3a; }
    .diff .rem { color: #d04545; }
    .diff .hunk { color: #6f8aff; }
    .actions { display: flex; gap: 10px; margin-top: 24px; position: sticky; bottom: 0; padding-top: 12px; background: var(--vscode-editor-background); }
    button { padding: 8px 18px; border: none; border-radius: 4px; font-size: 0.92rem; cursor: pointer; }
    button.approve { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
    button.approve:hover { background: var(--vscode-button-hoverBackground); }
    button.reject { background: var(--vscode-errorForeground); color: white; }
    button.reject:hover { opacity: 0.9; }
    .stats { font-variant-numeric: tabular-nums; }
  </style>
</head>
<body>
  <h1>🛡️ AI Firewall — Approval Required</h1>
  <div class="row">
    <span class="badge ${riskClass}">${esc(decision.risk)}</span>
    <span class="pill">${esc(decision.intent)}</span>
    <span class="pill">${esc(decision.decision)}</span>
    <span class="stats">+${decision.impact.lines_added}/-${decision.impact.lines_removed} lines · ${decision.impact.files_affected} file(s)</span>
  </div>
  <p class="reason">${esc(decision.reason)}</p>

  <h2>Command</h2>
  <div class="cmd">${esc(command)}</div>

  <h2>Findings</h2>
  ${findingsHtml}

  <h2>Git</h2>
  ${gitHtml}

  <h2>Diff</h2>
  ${diffHtml}

  <div class="actions">
    <button class="approve" id="approve">Approve & run</button>
    <button class="reject" id="reject">Reject</button>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.getElementById('approve').addEventListener('click', () => vscode.postMessage({ type: 'approve' }));
    document.getElementById('reject').addEventListener('click', () => vscode.postMessage({ type: 'reject' }));
  </script>
</body>
</html>`;
}

function renderGit(git: Record<string, unknown>): string {
  if (!git || Object.keys(git).length === 0) {
    return `<p class="muted">no git context</p>`;
  }
  const rows: string[] = [];
  for (const [k, v] of Object.entries(git)) {
    if (k === "in_repo" || k === "repo_root") continue;
    if (Array.isArray(v) && v.length) {
      rows.push(`<li><strong>${esc(k)}</strong>: ${v.map((x) => esc(String(x))).join(", ")}</li>`);
    }
  }
  if (!rows.length) {
    return `<p class="muted">inside repo, no warnings</p>`;
  }
  return `<ul class="findings">${rows.join("")}</ul>`;
}

function renderDiff(raw: string): string {
  const lines = raw.split("\n");
  return lines
    .map((ln) => {
      const safe = esc(ln);
      if (ln.startsWith("+++") || ln.startsWith("---")) return `<span class="hunk">${safe}</span>`;
      if (ln.startsWith("@@")) return `<span class="hunk">${safe}</span>`;
      if (ln.startsWith("+")) return `<span class="add">${safe}</span>`;
      if (ln.startsWith("-")) return `<span class="rem">${safe}</span>`;
      return safe;
    })
    .join("\n");
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

function newNonce(): string {
  let nonce = "";
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) nonce += chars.charAt(Math.floor(Math.random() * chars.length));
  return nonce;
}
