import * as vscode from "vscode";
import { ApprovalServerHandle, startApprovalServer } from "./approval_server";
import { resetAutoWireDismissal, runAutoWire, unwireAll } from "./auto_wire";
import { Decision, ExecResult, FirewallClient } from "./firewall";
import { SecretWatcher, showSecretActivityWebview } from "./secret_watcher";
import { showApprovalPanel } from "./webview";

let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let firewall: FirewallClient;
let secretWatcher: SecretWatcher | undefined;
let approvalServer: ApprovalServerHandle | undefined;

interface ActionRunner {
  /** Human-readable label shown in prompts and audit lines. */
  display: string;
  /** Calls `guard … --evaluate-only` and returns the Decision JSON. */
  evaluate(): Promise<Decision>;
  /** Calls `guard … --auto-approve` or `--auto-deny`. */
  run(mode: "auto-approve" | "auto-deny"): Promise<ExecResult>;
}

export function activate(context: vscode.ExtensionContext): void {
  outputChannel = vscode.window.createOutputChannel("AI Firewall");
  context.subscriptions.push(outputChannel);

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = "$(shield) Firewall";
  statusBarItem.tooltip = "AI Execution Firewall — click to run a shell command";
  statusBarItem.command = "aiFirewall.runCommand";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  firewall = new FirewallClient();

  // Passive secret-DB watcher (Feature H). Detection-only, never patches fs.
  secretWatcher = new SecretWatcher(context, outputChannel);
  secretWatcher.start();
  context.subscriptions.push(secretWatcher);

  // v0.5.0: localhost approval server. Lets the Claude Code PreToolUse
  // hook (and the MCP proxy) ask the user via our webview when an action
  // hits REQUIRE_APPROVAL. Bound to 127.0.0.1 with a token in
  // ~/.ai-firewall/extension.port. Disposed via context.subscriptions.
  void startApprovalServer(context, outputChannel)
    .then((handle) => {
      approvalServer = handle;
    })
    .catch((err) => {
      outputChannel.appendLine(`[firewall] approval server failed to start: ${err}`);
    });

  context.subscriptions.push(
    vscode.commands.registerCommand("aiFirewall.runCommand", () => runShellCommand(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSelection", () => evaluateSelectionAsShell(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSql", () => runSqlQuery(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSqlSelection", () => evaluateSelectionAsSql(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateApi", () => runApiRequest(context)),
    vscode.commands.registerCommand("aiFirewall.showPolicy", () => showPolicy()),
    vscode.commands.registerCommand("aiFirewall.showSecretActivity", () => {
      if (secretWatcher) showSecretActivityWebview(context, secretWatcher);
    }),
    vscode.commands.registerCommand("aiFirewall.scanText", () => scanText()),
    vscode.commands.registerCommand("aiFirewall.scanSelection", () => scanSelection()),
    vscode.commands.registerCommand("aiFirewall.showGovernanceStatus", () => showGovernanceStatus()),
    vscode.commands.registerCommand("aiFirewall.showBehaviorStatus", () => showBehaviorStatus()),
    vscode.commands.registerCommand("aiFirewall.detectAndWire", async () => {
      await resetAutoWireDismissal(context);
      await runAutoWire(context, { firewall, output: outputChannel }, true);
    }),
    vscode.commands.registerCommand("aiFirewall.unwireAll", () =>
      unwireAll(context, { firewall, output: outputChannel }),
    ),
    vscode.commands.registerCommand("aiFirewall.showStatus", () => showStatus()),
  );

  // First-activation auto-wire: runs once per "fingerprint" of detected
  // unwrapped targets. Non-blocking — failures are logged, not surfaced.
  void runAutoWire(context, { firewall, output: outputChannel }).catch((err) => {
    outputChannel.appendLine(`[firewall] auto-wire crashed: ${err}`);
  });

  outputChannel.appendLine("[firewall] extension activated");
}

export async function deactivate(): Promise<void> {
  // Disposables registered in context.subscriptions are run by VS Code.
  // We additionally await the approval server's port-file cleanup so
  // the next session never inherits a stale loopback target.
  if (approvalServer) {
    try {
      await approvalServer.dispose();
    } catch {
      // best-effort
    }
    approvalServer = undefined;
  }
}

// --- Command handlers ---

async function runShellCommand(context: vscode.ExtensionContext): Promise<void> {
  const command = await vscode.window.showInputBox({
    prompt: "Shell command to evaluate through the firewall",
    placeHolder: "e.g. rm -rf ./build",
    ignoreFocusOut: true,
  });
  if (!command) return;
  await driveAction(context, shellRunner(command));
}

async function evaluateSelectionAsShell(context: vscode.ExtensionContext): Promise<void> {
  const text = readSelection();
  if (!text) return;
  await driveAction(context, shellRunner(text));
}

async function runSqlQuery(context: vscode.ExtensionContext): Promise<void> {
  const query = await vscode.window.showInputBox({
    prompt: "SQL query to evaluate (analyze-only — never executes)",
    placeHolder: "e.g. DELETE FROM users WHERE id = 1",
    ignoreFocusOut: true,
  });
  if (!query) return;
  await driveAction(context, sqlRunner(query));
}

async function evaluateSelectionAsSql(context: vscode.ExtensionContext): Promise<void> {
  const text = readSelection();
  if (!text) return;
  await driveAction(context, sqlRunner(text));
}

async function runApiRequest(context: vscode.ExtensionContext): Promise<void> {
  const method = await vscode.window.showQuickPick(
    ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    { placeHolder: "HTTP method", ignoreFocusOut: true }
  );
  if (!method) return;
  const url = await vscode.window.showInputBox({
    prompt: `URL for the ${method} request`,
    placeHolder: "e.g. https://api.example.com/users/42",
    ignoreFocusOut: true,
  });
  if (!url) return;
  await driveAction(context, apiRunner(method, url));
}

async function showPolicy(): Promise<void> {
  try {
    const yaml = await firewall.policyShow();
    const doc = await vscode.workspace.openTextDocument({ content: yaml, language: "yaml" });
    await vscode.window.showTextDocument(doc, { preview: true });
  } catch (e) {
    vscode.window.showErrorMessage(`AI Firewall: ${(e as Error).message}`);
  }
}

async function scanText(): Promise<void> {
  const text = await vscode.window.showInputBox({
    prompt: "Text to scan for leaked secrets and PII",
    placeHolder: "paste a chat message, a prompt, an error log…",
    ignoreFocusOut: true,
  });
  if (!text) return;
  await runScan(text);
}

async function scanSelection(): Promise<void> {
  const text = readSelection();
  if (!text) return;
  await runScan(text);
}

async function runScan(text: string): Promise<void> {
  outputChannel.appendLine(`[firewall] scan: ${text.length} chars`);
  try {
    const result = await firewall.scan(text);
    outputChannel.appendLine(`[firewall] scan severity=${result.severity} findings=${result.findings.length}`);
    if (!result.findings.length) {
      vscode.window.showInformationMessage(
        "🛡️ Firewall scan: clean — no secrets or PII detected."
      );
      return;
    }
    const summary =
      `severity: ${result.severity}\n\n` +
      result.findings.map((f) => `  • ${f}`).join("\n");
    const doc = await vscode.workspace.openTextDocument({
      content: summary,
      language: "plaintext",
    });
    await vscode.window.showTextDocument(doc, { preview: true });

    const sev = result.severity.toLowerCase();
    if (sev === "critical" || sev === "major") {
      vscode.window.showWarningMessage(
        `🛡️ Firewall scan: ${result.findings.length} finding(s) — severity ${result.severity}.`
      );
    } else {
      vscode.window.showInformationMessage(
        `🛡️ Firewall scan: ${result.findings.length} finding(s) — severity ${result.severity}.`
      );
    }
  } catch (e) {
    vscode.window.showErrorMessage(`AI Firewall: ${(e as Error).message}`);
  }
}

async function showGovernanceStatus(): Promise<void> {
  try {
    const text = await firewall.governanceStatus();
    const doc = await vscode.workspace.openTextDocument({ content: text, language: "plaintext" });
    await vscode.window.showTextDocument(doc, { preview: true });
  } catch (e) {
    vscode.window.showErrorMessage(`AI Firewall: ${(e as Error).message}`);
  }
}

async function showBehaviorStatus(): Promise<void> {
  try {
    const text = await firewall.behaviorStatus();
    const doc = await vscode.workspace.openTextDocument({ content: text, language: "plaintext" });
    await vscode.window.showTextDocument(doc, { preview: true });
  } catch (e) {
    vscode.window.showErrorMessage(`AI Firewall: ${(e as Error).message}`);
  }
}

async function showStatus(): Promise<void> {
  // Combine: auto-wire status + recent audit records into one markdown doc.
  let scanLines: string[] = ["## Wired hosts", ""];
  try {
    const scan = await firewall.mcpScanJson();
    if (scan.claude_code_hook.installed) {
      scanLines.push(`- ✅ **Claude Code** PreToolUse hook installed (${scan.claude_code_hook.settings_path})`);
    } else {
      scanLines.push("- ⚠️ Claude Code PreToolUse hook **not installed** — run `AI Firewall: Detect & Wire AI Tools`");
    }
    if (scan.mcp_servers.length === 0) {
      scanLines.push("- (no MCP servers detected in known hosts)");
    } else {
      for (const s of scan.mcp_servers) {
        const tag = s.wrapped ? "✅ wrapped" : "⚠️ unwrapped";
        scanLines.push(`- ${tag}: \`${s.host}/${s.name}\` — \`${s.config_path}\``);
      }
    }
  } catch (e) {
    scanLines.push(`(scan failed: ${(e as Error).message})`);
  }

  let auditLines: string[] = ["", "## Recent decisions", ""];
  try {
    const records = await firewall.recentAuditRecords(20);
    if (records.length === 0) {
      auditLines.push("(no audit records yet)");
    } else {
      auditLines.push("| time | type | intent | risk | decision | rendered |");
      auditLines.push("|---|---|---|---|---|---|");
      for (const r of records) {
        const t = new Date((r.ts ?? 0) * 1000).toLocaleString();
        const decision = r.tampered ? `${r.decision} ⚠️ tampered` : (r.decision ?? "?");
        const rendered = (r.rendered ?? "").slice(0, 60).replace(/\|/g, "\\|");
        auditLines.push(`| ${t} | ${r.type ?? "?"} | ${r.intent ?? "?"} | ${r.risk ?? "?"} | ${decision} | \`${rendered}\` |`);
      }
    }
  } catch (e) {
    auditLines.push(`(audit fetch failed: ${(e as Error).message})`);
  }

  const portInfo = approvalServer
    ? `Listening on \`127.0.0.1:${approvalServer.port}\` (token at \`${approvalServer.portFilePath}\`)`
    : "Approval server not running.";

  const md = [
    "# AI Firewall Status",
    "",
    "## Approval bridge",
    "",
    portInfo,
    "",
    ...scanLines,
    ...auditLines,
    "",
    "---",
    "",
    "_Refresh: re-run `AI Firewall: Show Status`._",
  ].join("\n");

  const doc = await vscode.workspace.openTextDocument({ content: md, language: "markdown" });
  await vscode.window.showTextDocument(doc, { preview: true });
}

// --- Generic action driver: same flow for shell / SQL / API ---

async function driveAction(context: vscode.ExtensionContext, runner: ActionRunner): Promise<void> {
  outputChannel.appendLine(`[firewall] evaluate: ${runner.display}`);
  let decision: Decision;
  try {
    decision = await runner.evaluate();
  } catch (e) {
    const msg = (e as Error).message;
    outputChannel.appendLine(`[firewall] eval error: ${msg}`);
    vscode.window.showErrorMessage(`AI Firewall: ${msg}`);
    return;
  }
  outputChannel.appendLine(
    `[firewall] decision=${decision.decision} risk=${decision.risk} intent=${decision.intent}`
  );

  if (decision.decision === "BLOCK") {
    vscode.window.showErrorMessage(`🛡️ Firewall BLOCKED: ${decision.reason}`, { modal: false });
    return;
  }

  if (decision.decision === "ALLOW") {
    // Smart-flow auto-approval (memory match or permission inheritance) — surface
    // a quiet toast so the user knows the firewall did something on their behalf.
    const r = decision.reason || "";
    if (r.startsWith("memory match")) {
      vscode.window.setStatusBarMessage("$(check) Firewall: auto-approved (learned from you)", 4000);
    } else if (r.startsWith("inheritance")) {
      vscode.window.setStatusBarMessage("$(check) Firewall: auto-approved (you just ran an equivalent command)", 4000);
    }
    await execute(runner, "auto-approve");
    return;
  }

  const choice = await showApprovalPanel(context, runner.display, decision);
  outputChannel.appendLine(`[firewall] user choice: ${choice}`);
  if (choice === "approve") {
    await execute(runner, "auto-approve");
  } else {
    await execute(runner, "auto-deny"); // records the rejection in the audit log
    vscode.window.showInformationMessage("🛡️ Firewall: action rejected — not executed.");
  }
}

async function execute(runner: ActionRunner, mode: "auto-approve" | "auto-deny"): Promise<void> {
  outputChannel.show(true);
  outputChannel.appendLine(`[firewall] $ guard ${runner.display} --${mode}`);
  try {
    const result = await runner.run(mode);
    if (result.stdout) outputChannel.append(result.stdout);
    if (result.stderr) outputChannel.append(result.stderr);
    outputChannel.appendLine(`[firewall] exit ${result.exitCode}`);
    if (mode === "auto-approve" && result.exitCode === 0) {
      vscode.window.setStatusBarMessage("$(check) Firewall: action approved", 4000);
    }
  } catch (e) {
    const msg = (e as Error).message;
    outputChannel.appendLine(`[firewall] run error: ${msg}`);
    vscode.window.showErrorMessage(`AI Firewall: ${msg}`);
  }
}

// --- Runner factories per action kind ---

function shellRunner(command: string): ActionRunner {
  return {
    display: `shell: ${command}`,
    evaluate: () => firewall.evaluate(command),
    run: (mode) => firewall.run(command, mode),
  };
}

function sqlRunner(query: string): ActionRunner {
  return {
    display: `sql: ${query}`,
    evaluate: () => firewall.evaluateSql(query),
    run: (mode) => firewall.runSql(query, mode),
  };
}

function apiRunner(method: string, url: string): ActionRunner {
  return {
    display: `api: ${method} ${url}`,
    evaluate: () => firewall.evaluateApi(method, url),
    run: (mode) => firewall.runApi(method, url, mode),
  };
}

// --- Helpers ---

function readSelection(): string | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("No active editor.");
    return undefined;
  }
  const text = editor.document.getText(editor.selection).trim();
  if (!text) {
    vscode.window.showWarningMessage("No text selected.");
    return undefined;
  }
  return text;
}
