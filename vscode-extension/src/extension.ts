import * as vscode from "vscode";
import { Decision, ExecResult, FirewallClient } from "./firewall";
import { showApprovalPanel } from "./webview";

let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let firewall: FirewallClient;

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

  context.subscriptions.push(
    vscode.commands.registerCommand("aiFirewall.runCommand", () => runShellCommand(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSelection", () => evaluateSelectionAsShell(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSql", () => runSqlQuery(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSqlSelection", () => evaluateSelectionAsSql(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateApi", () => runApiRequest(context)),
    vscode.commands.registerCommand("aiFirewall.showPolicy", () => showPolicy())
  );

  outputChannel.appendLine("[firewall] extension activated");
}

export function deactivate(): void {
  // Disposables are cleaned up via context.subscriptions.
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
