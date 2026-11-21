/**
 * Human approval queue.
 *
 * The gateway writes a pending request file into <stateDir>/approvals/ and
 * polls it. A human (or, in the demo, a scripted step) resolves it with the
 * CLI: `agentgate approve <id>` / `agentgate deny <id>`. No decision before
 * the timeout means DENY — approvals fail closed.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface ApprovalRequest {
  id: string;
  traceId: string;
  agent: string;
  tool: string;
  args: Record<string, unknown>;
  reason: string;
  requestedAt: string;
  expiresAt: string;
  status: "pending" | "approved" | "denied";
  decidedAt?: string;
  decidedBy?: string;
}

export function approvalsDir(stateDir: string): string {
  const dir = join(stateDir, "approvals");
  mkdirSync(dir, { recursive: true });
  return dir;
}

function fileFor(stateDir: string, id: string): string {
  return join(approvalsDir(stateDir), `${id}.json`);
}

export function createApproval(stateDir: string, req: Omit<ApprovalRequest, "status">): ApprovalRequest {
  const full: ApprovalRequest = { ...req, status: "pending" };
  writeFileSync(fileFor(stateDir, req.id), JSON.stringify(full, null, 2) + "\n");
  return full;
}

export function readApproval(stateDir: string, id: string): ApprovalRequest | null {
  const path = fileFor(stateDir, id);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as ApprovalRequest;
}

export function listApprovals(stateDir: string): ApprovalRequest[] {
  return readdirSync(approvalsDir(stateDir))
    .filter((f) => f.endsWith(".json"))
    .map((f) => JSON.parse(readFileSync(join(approvalsDir(stateDir), f), "utf8")) as ApprovalRequest)
    .sort((a, b) => a.requestedAt.localeCompare(b.requestedAt));
}

export function decideApproval(
  stateDir: string,
  id: string,
  decision: "approved" | "denied",
  decidedBy = "cli",
): ApprovalRequest {
  const req = readApproval(stateDir, id);
  if (!req) throw new Error(`No approval request with id '${id}'`);
  if (req.status !== "pending") throw new Error(`Request '${id}' is already ${req.status}`);
  req.status = decision;
  req.decidedAt = new Date().toISOString();
  req.decidedBy = decidedBy;
  writeFileSync(fileFor(stateDir, id), JSON.stringify(req, null, 2) + "\n");
  return req;
}

/** Poll until the request is decided or the timeout passes. Timeout resolves to null (deny). */
export async function waitForDecision(
  stateDir: string,
  id: string,
  timeoutMs: number,
  pollMs = 200,
): Promise<ApprovalRequest | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const req = readApproval(stateDir, id);
    if (req && req.status !== "pending") return req;
    await new Promise((r) => setTimeout(r, pollMs));
  }
  return null;
}
