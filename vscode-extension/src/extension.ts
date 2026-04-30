import * as vscode from "vscode";
import { Decision, FirewallClient } from "./firewall";
import { showApprovalPanel } from "./webview";

let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;
let firewall: FirewallClient;

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
    vscode.commands.registerCommand("aiFirewall.runCommand", () => runCommand(context)),
    vscode.commands.registerCommand("aiFirewall.evaluateSelection", () => evaluateSelection(context)),
    vscode.commands.registerCommand("aiFirewall.showPolicy", () => showPolicy())
  );

  outputChannel.appendLine("[firewall] extension activated");
}

export function deactivate(): void {
  // Disposables are cleaned up via context.subscriptions.
}

async function runCommand(context: vscode.ExtensionContext): Promise<void> {
  const command = await vscode.window.showInputBox({
    prompt: "Shell command to evaluate through the firewall",
    placeHolder: "e.g. rm -rf ./build",
    ignoreFocusOut: true,
  });
  if (!command) {
    return;
  }
  await evaluateAndAct(context, command);
}

async function evaluateSelection(context: vscode.ExtensionContext): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("No active editor.");
    return;
  }
  const text = editor.document.getText(editor.selection).trim();
  if (!text) {
    vscode.window.showWarningMessage("No text selected.");
    return;
  }
  await evaluateAndAct(context, text);
}

async function evaluateAndAct(context: vscode.ExtensionContext, command: string): Promise<void> {
  outputChannel.appendLine(`[firewall] evaluate: ${command}`);
  let decision: Decision;
  try {
    decision = await firewall.evaluate(command);
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
    vscode.window.showErrorMessage(
      `🛡️ Firewall BLOCKED: ${decision.reason}`,
      { modal: false }
    );
    return;
  }

  if (decision.decision === "ALLOW") {
    await execute(command, "auto-approve");
    return;
  }

  // REQUIRE_APPROVAL — show webview.
  const choice = await showApprovalPanel(context, command, decision);
  outputChannel.appendLine(`[firewall] user choice: ${choice}`);
  if (choice === "approve") {
    await execute(command, "auto-approve");
  } else {
    await execute(command, "auto-deny"); // records the rejection in the audit log
    vscode.window.showInformationMessage("🛡️ Firewall: action rejected — not executed.");
  }
}

async function execute(command: string, mode: "auto-approve" | "auto-deny"): Promise<void> {
  outputChannel.show(true);
  outputChannel.appendLine(`[firewall] $ guard run ${JSON.stringify(command)} --${mode}`);
  try {
    const result = await firewall.run(command, mode);
    if (result.stdout) {
      outputChannel.append(result.stdout);
    }
    if (result.stderr) {
      outputChannel.append(result.stderr);
    }
    outputChannel.appendLine(`[firewall] exit ${result.exitCode}`);
    if (mode === "auto-approve" && result.exitCode === 0) {
      vscode.window.setStatusBarMessage("$(check) Firewall: command executed", 4000);
    }
  } catch (e) {
    const msg = (e as Error).message;
    outputChannel.appendLine(`[firewall] run error: ${msg}`);
    vscode.window.showErrorMessage(`AI Firewall: ${msg}`);
  }
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
