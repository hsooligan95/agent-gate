#!/usr/bin/env node
/**
 * AgentGate operator CLI.
 *
 *   agentgate approvals [--state-dir <dir>]            list approval requests
 *   agentgate approve <id> [--state-dir <dir>]         approve a pending call
 *   agentgate deny <id> [--state-dir <dir>]             deny a pending call
 *   agentgate audit verify [--state-dir <dir>]         verify the audit hash chain
 *   agentgate evidence --trace <id> [--out <file>]     export an evidence pack
 *
 * State dir resolution: --state-dir flag > AGENTGATE_STATE_DIR env > ./.agentgate
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { decideApproval, listApprovals } from "./approvals.js";
import { readEntries, verifyChain } from "./audit.js";

const argv = process.argv.slice(2);
const cmd = argv[0];

function opt(name: string): string | undefined {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
}
const stateDir = opt("--state-dir") ?? process.env.AGENTGATE_STATE_DIR ?? ".agentgate";
const auditPath = join(stateDir, "audit.jsonl");

try {
  if (cmd === "approvals") {
    const all = listApprovals(stateDir);
    if (all.length === 0) console.log("No approval requests.");
    for (const r of all) {
      console.log(
        `${r.id}  [${r.status}]  ${r.agent} -> ${r.tool} ${JSON.stringify(r.args)}  (requested ${r.requestedAt}, expires ${r.expiresAt})`,
      );
    }
  } else if (cmd === "approve" || cmd === "deny") {
    const id = argv[1];
    if (!id) throw new Error(`Usage: agentgate ${cmd} <approval-id>`);
    const decided = decideApproval(stateDir, id, cmd === "approve" ? "approved" : "denied");
    console.log(`${decided.id}: ${decided.status} (tool ${decided.tool})`);
  } else if (cmd === "audit" && argv[1] === "verify") {
    const result = verifyChain(auditPath);
    if (result.ok) {
      console.log(`Audit chain OK — ${result.entries} entries, every hash verified.`);
    } else {
      console.log(`Audit chain BROKEN at seq ${result.brokenAtSeq}: ${result.reason} (${result.entries} entries read)`);
      process.exit(1);
    }
  } else if (cmd === "evidence") {
    const traceId = opt("--trace");
    if (!traceId) throw new Error("Usage: agentgate evidence --trace <trace-id> [--out <file>]");
    const entries = readEntries(auditPath).filter((e) => e.traceId === traceId);
    if (entries.length === 0) throw new Error(`No audit entries for trace ${traceId}`);
    const chain = verifyChain(auditPath);
    const pack = {
      product: "AgentGate evidence pack",
      traceId,
      exportedAt: new Date().toISOString(),
      chainValid: chain.ok,
      summary: {
        entries: entries.length,
        policyDecisions: entries.filter((e) => e.type === "policy_decision").length,
        approvalsRequested: entries.filter((e) => e.type === "approval_requested").length,
        toolsExecuted: entries.filter((e) => e.type === "tool_executed").length,
        screeningFindings: entries.filter((e) => e.type === "screening_findings").length,
      },
      entries,
    };
    const out = opt("--out");
    if (out) {
      writeFileSync(out, JSON.stringify(pack, null, 2) + "\n");
      console.log(`Evidence pack for trace ${traceId} written to ${out} (${entries.length} entries, chain valid: ${chain.ok})`);
    } else {
      console.log(JSON.stringify(pack, null, 2));
    }
  } else {
    console.log("Usage: agentgate <approvals|approve|deny|audit verify|evidence> [options]");
    process.exit(cmd ? 1 : 0);
  }
} catch (err) {
  console.error(`agentgate: ${String(err instanceof Error ? err.message : err)}`);
  process.exit(1);
}
