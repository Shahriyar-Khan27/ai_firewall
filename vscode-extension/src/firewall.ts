import { spawn, SpawnOptionsWithoutStdio } from "child_process";
import * as vscode from "vscode";

export type DecisionKind = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";

export interface Impact {
  files_affected: number;
  bytes_affected: number;
  paths: string[];
  notes: string;
  diff: string;
  lines_added: number;
  lines_removed: number;
  code_findings: string[];
  git: Record<string, unknown>;
}

export interface Decision {
  decision: DecisionKind;
  reason: string;
  intent: string;
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  impact: Impact;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/** Shape returned by `guard mcp scan --json` — matches the Python CLI. */
export interface McpServerEntry {
  host: string;
  name: string;
  config_path: string;
  wrapped: boolean;
  command?: string;
  args?: string[];
  upstream_command?: string | null;
  upstream_args?: string[];
}

export interface McpScanResult {
  mcp_servers: McpServerEntry[];
  claude_code_hook: {
    settings_path: string;
    installed: boolean;
  };
}

interface SpawnResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function parseDecision(stdout: string): Decision {
  try {
    return JSON.parse(stdout) as Decision;
  } catch {
    throw new Error(`guard returned non-JSON output: ${stdout}`);
  }
}

/** Wraps the `guard` CLI as a subprocess. */
export class FirewallClient {
  private get guardPath(): string {
    return vscode.workspace.getConfiguration("aiFirewall").get<string>("guardPath", "guard");
  }

  private get extraArgs(): string[] {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const args: string[] = [];
    const rules = cfg.get<string>("rulesPath", "");
    if (rules) {
      args.push("--rules", rules);
    }
    const audit = cfg.get<string>("auditPath", "");
    if (audit) {
      args.push("--audit", audit);
    }
    return args;
  }

  /**
   * Calls `guard eval <command>` and parses the Decision JSON.
   * Note: `eval` only takes --rules, not --audit (no execution = no audit row).
   */
  async evaluate(command: string): Promise<Decision> {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const rules = cfg.get<string>("rulesPath", "");
    const args = ["eval", command];
    if (rules) {
      args.push("--rules", rules);
    }

    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard eval failed (exit ${result.exitCode}): ${result.stderr || result.stdout}`);
    }
    return parseDecision(result.stdout);
  }

  /** Calls `guard run <command> --auto-approve` (or --auto-deny) and returns stdout/stderr. */
  async run(command: string, mode: "auto-approve" | "auto-deny"): Promise<ExecResult> {
    const args = ["run", command, `--${mode}`, ...this.extraArgs];
    const result = await this.spawn(args);
    return { exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr };
  }

  /** Calls `guard sql <query> --evaluate-only` and parses Decision JSON. */
  async evaluateSql(query: string): Promise<Decision> {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const rules = cfg.get<string>("rulesPath", "");
    const args = ["sql", query, "--evaluate-only"];
    if (rules) args.push("--rules", rules);
    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard sql failed (exit ${result.exitCode}): ${result.stderr || result.stdout}`);
    }
    return parseDecision(result.stdout);
  }

  /** Calls `guard sql <query> --auto-approve|--auto-deny`. Analyze-only, never executes the query. */
  async runSql(query: string, mode: "auto-approve" | "auto-deny"): Promise<ExecResult> {
    const args = ["sql", query, `--${mode}`, ...this.extraArgs];
    const result = await this.spawn(args);
    return { exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr };
  }

  /** Calls `guard api METHOD URL --evaluate-only` and parses Decision JSON. */
  async evaluateApi(method: string, url: string): Promise<Decision> {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const rules = cfg.get<string>("rulesPath", "");
    const args = ["api", method, url, "--evaluate-only"];
    if (rules) args.push("--rules", rules);
    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard api failed (exit ${result.exitCode}): ${result.stderr || result.stdout}`);
    }
    return parseDecision(result.stdout);
  }

  /** Calls `guard api METHOD URL --auto-approve|--auto-deny`. Analyze-only, never makes the request. */
  async runApi(method: string, url: string, mode: "auto-approve" | "auto-deny"): Promise<ExecResult> {
    const args = ["api", method, url, `--${mode}`, ...this.extraArgs];
    const result = await this.spawn(args);
    return { exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr };
  }

  /**
   * Calls `guard scan <text> --json` and parses the result.
   * Returns the severity ladder + per-finding lines so the UI can
   * present them however it likes.
   */
  async scan(text: string): Promise<{ severity: string; findings: string[] }> {
    const args = ["scan", text, "--json"];
    const result = await this.spawn(args);
    // `scan` exits 1 when severity is major/critical — that's not an error.
    try {
      return JSON.parse(result.stdout) as { severity: string; findings: string[] };
    } catch {
      throw new Error(`guard scan returned non-JSON output: ${result.stdout || result.stderr}`);
    }
  }

  /** Calls `guard governance status` and returns the rendered text. */
  async governanceStatus(): Promise<string> {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const args = ["governance", "status"];
    const rules = cfg.get<string>("rulesPath", "");
    const audit = cfg.get<string>("auditPath", "");
    if (rules) args.push("--rules", rules);
    if (audit) args.push("--audit", audit);
    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard governance status failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout;
  }

  /** Calls `guard behavior status` and returns the rendered text. */
  async behaviorStatus(): Promise<string> {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const args = ["behavior", "status"];
    const rules = cfg.get<string>("rulesPath", "");
    const audit = cfg.get<string>("auditPath", "");
    if (rules) args.push("--rules", rules);
    if (audit) args.push("--audit", audit);
    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard behavior status failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout;
  }

  /**
   * Calls `guard mcp scan --json` and returns the parsed payload.
   * Used by the auto-wire toast on first activation.
   */
  async mcpScanJson(): Promise<McpScanResult> {
    const args = ["mcp", "scan", "--json"];
    const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (cwd) args.push("--workspace", cwd);
    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard mcp scan failed: ${result.stderr || result.stdout}`);
    }
    try {
      return JSON.parse(result.stdout) as McpScanResult;
    } catch {
      throw new Error(`guard mcp scan returned non-JSON output: ${result.stdout}`);
    }
  }

  /** `guard mcp install <name>` — wraps an unwrapped MCP server in place. */
  async mcpInstall(name: string): Promise<string> {
    const result = await this.spawn(["mcp", "install", name]);
    if (result.exitCode !== 0) {
      throw new Error(`guard mcp install '${name}' failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  /** `guard mcp uninstall <name>` — restores a previously-wrapped server. */
  async mcpUninstall(name: string): Promise<string> {
    const result = await this.spawn(["mcp", "uninstall", name]);
    if (result.exitCode !== 0) {
      throw new Error(`guard mcp uninstall '${name}' failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  /** `guard mcp install-hook` — adds the Claude Code PreToolUse hook. */
  async mcpInstallHook(approvalMode: "prompt" | "block" | "allow" = "prompt"): Promise<string> {
    const result = await this.spawn(["mcp", "install-hook", "--approval-mode", approvalMode]);
    if (result.exitCode !== 0) {
      throw new Error(`guard mcp install-hook failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  /** `guard mcp uninstall-hook` — reverses install-hook. */
  async mcpUninstallHook(): Promise<string> {
    const result = await this.spawn(["mcp", "uninstall-hook"]);
    if (result.exitCode !== 0) {
      throw new Error(`guard mcp uninstall-hook failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  /** Calls `guard policy show` and returns the YAML text. */
  async policyShow(): Promise<string> {
    const cfg = vscode.workspace.getConfiguration("aiFirewall");
    const rules = cfg.get<string>("rulesPath", "");
    const args = ["policy", "show"];
    if (rules) {
      args.push("--rules", rules);
    }
    const result = await this.spawn(args);
    if (result.exitCode !== 0) {
      throw new Error(`guard policy show failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout;
  }

  private spawn(args: string[]): Promise<SpawnResult> {
    return new Promise((resolve, reject) => {
      const cwd = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      const opts: SpawnOptionsWithoutStdio = { cwd, shell: false };
      let proc;
      try {
        proc = spawn(this.guardPath, args, opts);
      } catch (e) {
        reject(new Error(`failed to spawn ${this.guardPath}: ${(e as Error).message}`));
        return;
      }
      let stdout = "";
      let stderr = "";
      proc.stdout.on("data", (chunk) => (stdout += chunk.toString("utf-8")));
      proc.stderr.on("data", (chunk) => (stderr += chunk.toString("utf-8")));
      proc.on("error", (err) => {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          reject(
            new Error(
              `guard CLI not found at "${this.guardPath}". Install with \`pip install -e .\` from the project root, or set aiFirewall.guardPath in settings.`
            )
          );
        } else {
          reject(err);
        }
      });
      proc.on("close", (code) => {
        resolve({ stdout, stderr, exitCode: code ?? 0 });
      });
    });
  }
}
