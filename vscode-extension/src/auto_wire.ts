import * as vscode from "vscode";
import { FirewallClient, McpScanResult } from "./firewall";

/**
 * On first activation per workspace (or when the user invokes
 * `AI Firewall: Detect & Wire AI Tools`), shell out to
 * `guard mcp scan --json`, surface a consent toast listing what was
 * found, and on user approval install the Claude Code hook + wrap each
 * unwrapped MCP server. The user can also choose "Pick…" for a
 * per-host picker, or "Not now" to defer.
 *
 * State management:
 *
 *   - `context.globalState.get("aiFirewall.autoWire.dismissed")` — once
 *     the user has either wired or said "not now", we don't pester
 *     them on every activation. Re-arm with a Command Palette command.
 *   - `aiFirewall.autoWire.lastSeen` — fingerprint of the last detection,
 *     so a *new* unwrapped server triggers a fresh prompt even if the
 *     user previously dismissed.
 */

const DISMISSED_KEY = "aiFirewall.autoWire.dismissed";
const FINGERPRINT_KEY = "aiFirewall.autoWire.lastFingerprint";

export interface AutoWireDeps {
  firewall: FirewallClient;
  output: vscode.OutputChannel;
}

/** Run the auto-wire flow. Pass `force=true` to bypass the dismissed flag. */
export async function runAutoWire(
  context: vscode.ExtensionContext,
  deps: AutoWireDeps,
  force = false,
): Promise<void> {
  const { firewall, output } = deps;

  let scan: McpScanResult;
  try {
    scan = await firewall.mcpScanJson();
  } catch (e) {
    output.appendLine(`[auto-wire] scan failed: ${(e as Error).message}`);
    if (force) {
      vscode.window.showErrorMessage(
        `AI Firewall: scan failed — ${(e as Error).message}`,
      );
    }
    return;
  }

  const unwrappedServers = scan.mcp_servers.filter((s) => !s.wrapped);
  const hookMissing = !scan.claude_code_hook.installed;
  const total = unwrappedServers.length + (hookMissing ? 1 : 0);

  if (total === 0) {
    if (force) {
      vscode.window.showInformationMessage(
        "🛡️ AI Firewall: nothing to wire — Claude Code hook is installed and every MCP server is wrapped.",
      );
    } else {
      output.appendLine("[auto-wire] nothing to do (already fully wired)");
    }
    return;
  }

  // Skip the prompt if the user previously dismissed AND nothing new appeared.
  const fingerprint = makeFingerprint(scan);
  const lastSeen = context.globalState.get<string>(FINGERPRINT_KEY);
  const dismissed = context.globalState.get<boolean>(DISMISSED_KEY, false);
  if (!force && dismissed && lastSeen === fingerprint) {
    output.appendLine(`[auto-wire] previously dismissed; ${total} item(s) still unwrapped (re-run via Command Palette)`);
    return;
  }

  const summary = describe(unwrappedServers, hookMissing);
  output.appendLine(`[auto-wire] detected: ${summary}`);

  const choice = await vscode.window.showInformationMessage(
    `🛡️ AI Firewall detected ${summary}. Wire firewall protection?`,
    { modal: false },
    "Wire All",
    "Pick…",
    "Not Now",
  );

  // Remember whatever the user just saw, so we don't re-prompt for the
  // same set after a "Not Now".
  await context.globalState.update(FINGERPRINT_KEY, fingerprint);

  if (!choice || choice === "Not Now") {
    await context.globalState.update(DISMISSED_KEY, true);
    output.appendLine("[auto-wire] user dismissed (not now)");
    return;
  }

  if (choice === "Wire All") {
    await wireAll(firewall, output, unwrappedServers, hookMissing);
    await context.globalState.update(DISMISSED_KEY, true);
    return;
  }

  if (choice === "Pick…") {
    await wirePicker(firewall, output, unwrappedServers, hookMissing);
    await context.globalState.update(DISMISSED_KEY, true);
    return;
  }
}

/** Reset the dismissed-flag so the next activation re-prompts. */
export async function resetAutoWireDismissal(context: vscode.ExtensionContext): Promise<void> {
  await context.globalState.update(DISMISSED_KEY, false);
  await context.globalState.update(FINGERPRINT_KEY, undefined);
}

/** Reverse all wiring this extension previously installed. */
export async function unwireAll(
  context: vscode.ExtensionContext,
  deps: AutoWireDeps,
): Promise<void> {
  const { firewall, output } = deps;

  const confirm = await vscode.window.showWarningMessage(
    "Unwire firewall protection from all detected AI tools? This will remove the Claude Code hook and unwrap every wrapped MCP server. You can re-wire any time.",
    { modal: true },
    "Unwire All",
  );
  if (confirm !== "Unwire All") return;

  let scan: McpScanResult;
  try {
    scan = await firewall.mcpScanJson();
  } catch (e) {
    vscode.window.showErrorMessage(`AI Firewall: scan failed — ${(e as Error).message}`);
    return;
  }

  let problems = 0;
  if (scan.claude_code_hook.installed) {
    try {
      await firewall.mcpUninstallHook();
      output.appendLine("[unwire] removed Claude Code hook");
    } catch (e) {
      problems += 1;
      output.appendLine(`[unwire] hook removal failed: ${(e as Error).message}`);
    }
  }
  for (const s of scan.mcp_servers.filter((x) => x.wrapped)) {
    try {
      await firewall.mcpUninstall(s.name);
      output.appendLine(`[unwire] unwrapped ${s.host}/${s.name}`);
    } catch (e) {
      problems += 1;
      output.appendLine(`[unwire] failed for ${s.host}/${s.name}: ${(e as Error).message}`);
    }
  }
  await resetAutoWireDismissal(context);

  if (problems === 0) {
    vscode.window.showInformationMessage("🛡️ AI Firewall: all hosts unwired.");
  } else {
    vscode.window.showWarningMessage(
      `🛡️ AI Firewall: unwired with ${problems} problem(s). See output for details.`,
    );
  }
}

// --- Helpers ---

function describe(unwrapped: McpScanResult["mcp_servers"], hookMissing: boolean): string {
  const bits: string[] = [];
  if (hookMissing) bits.push("Claude Code");
  const byHost = new Map<string, number>();
  for (const s of unwrapped) byHost.set(s.host, (byHost.get(s.host) ?? 0) + 1);
  for (const [host, n] of byHost) {
    bits.push(`${host} (${n} MCP server${n === 1 ? "" : "s"})`);
  }
  return bits.join(" + ");
}

function makeFingerprint(scan: McpScanResult): string {
  const unwrapped = scan.mcp_servers
    .filter((s) => !s.wrapped)
    .map((s) => `${s.host}:${s.name}`)
    .sort()
    .join(",");
  return `${scan.claude_code_hook.installed ? "h+" : "h-"};${unwrapped}`;
}

async function wireAll(
  firewall: FirewallClient,
  output: vscode.OutputChannel,
  unwrappedServers: McpScanResult["mcp_servers"],
  hookMissing: boolean,
): Promise<void> {
  let installed = 0;
  let problems = 0;
  if (hookMissing) {
    try {
      await firewall.mcpInstallHook("prompt");
      output.appendLine("[wire] installed Claude Code hook (approval=prompt)");
      installed += 1;
    } catch (e) {
      problems += 1;
      output.appendLine(`[wire] hook install failed: ${(e as Error).message}`);
    }
  }
  for (const s of unwrappedServers) {
    try {
      await firewall.mcpInstall(s.name);
      output.appendLine(`[wire] wrapped ${s.host}/${s.name}`);
      installed += 1;
    } catch (e) {
      problems += 1;
      output.appendLine(`[wire] failed for ${s.host}/${s.name}: ${(e as Error).message}`);
    }
  }
  if (problems === 0) {
    vscode.window.showInformationMessage(
      `✓ AI Firewall: protection active for ${installed} target${installed === 1 ? "" : "s"}.`,
    );
  } else {
    vscode.window.showWarningMessage(
      `🛡️ AI Firewall: wired ${installed} with ${problems} problem(s). See output for details.`,
    );
  }
}

// Discriminator can't be `kind` — vscode.QuickPickItem already uses that.
interface WireItem extends vscode.QuickPickItem {
  wireKind: "hook" | "mcp";
  serverName?: string;
}

async function wirePicker(
  firewall: FirewallClient,
  output: vscode.OutputChannel,
  unwrappedServers: McpScanResult["mcp_servers"],
  hookMissing: boolean,
): Promise<void> {
  const items: WireItem[] = [];
  if (hookMissing) {
    items.push({
      label: "Claude Code PreToolUse hook",
      description: "Intercepts every Bash / Write / Edit / MultiEdit tool call",
      wireKind: "hook",
      picked: true,
    });
  }
  for (const s of unwrappedServers) {
    items.push({
      label: `${s.host} / ${s.name}`,
      description: s.config_path,
      wireKind: "mcp",
      serverName: s.name,
      picked: true,
    });
  }
  const chosen = await vscode.window.showQuickPick<WireItem>(items, {
    canPickMany: true,
    title: "Wire firewall protection",
    placeHolder: "Select which targets to wire",
  });
  if (!chosen || chosen.length === 0) return;

  const hookSelected = chosen.some((c) => c.wireKind === "hook");
  const mcpSelected: McpScanResult["mcp_servers"] = chosen
    .filter((c) => c.wireKind === "mcp" && c.serverName)
    .map((c) => unwrappedServers.find((s) => s.name === c.serverName))
    .filter((s): s is McpScanResult["mcp_servers"][number] => Boolean(s));
  await wireAll(firewall, output, mcpSelected, hookSelected);
}
