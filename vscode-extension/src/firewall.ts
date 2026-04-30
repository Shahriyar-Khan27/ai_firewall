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
