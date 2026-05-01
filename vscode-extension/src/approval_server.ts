import * as crypto from "crypto";
import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { Decision } from "./firewall";
import { showApprovalPanel } from "./webview";

/**
 * Localhost HTTP server the Python side uses to ask the user for an
 * approval decision via our existing webview.
 *
 * Contract (matches `ai_firewall/approval/extension_bridge.py`):
 *
 *   - We bind 127.0.0.1 with an OS-assigned port.
 *   - We write a `~/.ai-firewall/extension.port` file containing JSON
 *     `{host, port, token, pid}`. The file is the discovery mechanism
 *     for the Python bridge — no other channel.
 *   - Each POST `/approve` request must carry `X-Firewall-Token: <token>`
 *     matching the value we wrote. Token mismatch → 401, no webview.
 *   - The body is `{action_id, action: {type, payload, context}, decision}`
 *     where `decision` is the Python `Decision.to_dict()` shape.
 *   - We open `showApprovalPanel`, await the user's click, respond with
 *     `{decision: "approve"|"reject"}`.
 *   - Disposal removes the port file. `deactivate()` should call dispose.
 */

export interface ApprovalServerHandle {
  /** Port the server is listening on, for diagnostics / status sidebar. */
  readonly port: number;
  /** Path to the port file we wrote. */
  readonly portFilePath: string;
  /** Stop the server, delete the port file. Idempotent. */
  dispose(): Promise<void>;
}

interface RequestBody {
  action_id?: string;
  action?: {
    type?: string;
    payload?: Record<string, unknown>;
    context?: Record<string, unknown>;
  };
  decision?: Decision;
}

export async function startApprovalServer(
  context: vscode.ExtensionContext,
  output: vscode.OutputChannel,
): Promise<ApprovalServerHandle> {
  const token = crypto.randomBytes(16).toString("hex");
  const portFilePath = portFile();

  const server = http.createServer((req, res) => {
    handleRequest(context, output, token, req, res).catch((err) => {
      output.appendLine(`[approval-server] handler error: ${err}`);
      try {
        res.statusCode = 500;
        res.end(JSON.stringify({ error: String(err) }));
      } catch {
        // socket already closed; nothing to do
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    // Bind 127.0.0.1 explicitly — never expose this on a non-loopback.
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("approval server failed to bind a port");
  }
  const port = address.port;
  await writePortFile(portFilePath, { host: "127.0.0.1", port, token, pid: process.pid });

  output.appendLine(`[approval-server] listening on 127.0.0.1:${port} (token written to ${portFilePath})`);

  let disposed = false;
  const handle: ApprovalServerHandle = {
    port,
    portFilePath,
    async dispose(): Promise<void> {
      if (disposed) return;
      disposed = true;
      await new Promise<void>((resolve) => server.close(() => resolve()));
      try {
        await fs.promises.unlink(portFilePath);
      } catch {
        // already gone — fine
      }
      output.appendLine("[approval-server] stopped");
    },
  };

  // Tie lifetime to extension deactivation as a backstop.
  context.subscriptions.push({ dispose: () => void handle.dispose() });
  return handle;
}

async function handleRequest(
  context: vscode.ExtensionContext,
  output: vscode.OutputChannel,
  expectedToken: string,
  req: http.IncomingMessage,
  res: http.ServerResponse,
): Promise<void> {
  if (req.method === "GET" && req.url === "/health") {
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (req.method !== "POST" || req.url !== "/approve") {
    res.statusCode = 404;
    res.end();
    return;
  }

  const token = (req.headers["x-firewall-token"] as string | undefined) || "";
  if (token !== expectedToken) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: "token mismatch" }));
    return;
  }

  let raw = "";
  req.setEncoding("utf-8");
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 1_000_000) {
      // 1 MB cap — Decision payloads are tiny; anything bigger is suspect
      res.statusCode = 413;
      res.end();
      return;
    }
  }

  let body: RequestBody;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    res.statusCode = 400;
    res.end(JSON.stringify({ error: "invalid JSON body" }));
    return;
  }

  if (!body.decision) {
    res.statusCode = 400;
    res.end(JSON.stringify({ error: "missing decision" }));
    return;
  }

  const command = renderActionDescription(body);
  output.appendLine(`[approval-server] popup: ${body.decision.intent} ${command}`);

  // Bring the editor window forward so the user actually sees the popup.
  // (No-op when the window is already focused.)
  try {
    vscode.commands.executeCommand("workbench.action.focusActiveEditorGroup");
  } catch {
    // best-effort
  }

  const choice = await showApprovalPanel(context, command, body.decision);
  output.appendLine(`[approval-server] user choice: ${choice}`);

  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ decision: choice }));
}

function renderActionDescription(body: RequestBody): string {
  const action = body.action;
  if (!action) return body.action_id || "(unknown action)";
  const p = (action.payload || {}) as Record<string, unknown>;
  switch (action.type) {
    case "shell":
      return `shell: ${String(p.cmd || "")}`;
    case "file":
      return `file: ${String(p.op || "")} ${String(p.path || "")}`.trim();
    case "db":
      return `sql: ${String(p.sql || "")}`;
    case "api":
      return `api: ${String(p.method || "GET")} ${String(p.url || "")}`.trim();
    default:
      return `${action.type ?? "unknown"}: ${JSON.stringify(p)}`;
  }
}

function portFile(): string {
  return path.join(os.homedir(), ".ai-firewall", "extension.port");
}

async function writePortFile(
  portFilePath: string,
  payload: { host: string; port: number; token: string; pid: number },
): Promise<void> {
  await fs.promises.mkdir(path.dirname(portFilePath), { recursive: true });
  // Best-effort 0600 perms on POSIX; chmod is a no-op on Windows.
  const tmp = portFilePath + ".tmp";
  await fs.promises.writeFile(tmp, JSON.stringify(payload), { mode: 0o600 });
  try {
    await fs.promises.chmod(tmp, 0o600);
  } catch {
    // Windows: ignore
  }
  await fs.promises.rename(tmp, portFilePath);
}
