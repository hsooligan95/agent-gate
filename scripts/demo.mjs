#!/usr/bin/env node
/**
 * AgentGate demo — runs the whole story with no API keys and no network:
 *
 *   1. an agent connects through AgentGate and lists tools
 *   2. read-only calls pass straight through
 *   3. a poisoned tool result is flagged and its PII redacted
 *   4. a destructive call pauses for approval; the CLI approves it
 *   5. a read-only agent is denied the same destructive call outright
 *   6. the audit log is printed and its hash chain verified
 *   7. an evidence pack is exported for the demo session
 *
 * Run `npm run build` first (npm run demo does it for you).
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const stateDir = mkdtempSync(join(tmpdir(), "agentgate-demo-"));
const failures = [];
const check = (cond, label) => {
  console.log(`  ${cond ? "✓" : "✗ FAILED:"} ${label}`);
  if (!cond) failures.push(label);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const resultText = (res) => res.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");

async function connectAgent(token) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      join(root, "dist/src/index.js"),
      "--upstream",
      process.execPath,
      join(root, "demo-upstream/server.mjs"),
    ],
    env: {
      ...process.env,
      AGENTGATE_TOKEN: token,
      AGENTGATE_POLICY: join(root, "policy.json"),
      AGENTGATE_STATE_DIR: stateDir,
    },
    stderr: "inherit",
  });
  const client = new Client({ name: "demo-client", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return client;
}

console.log("=== AgentGate demo ===");
console.log(`state dir (audit + approvals): ${stateDir}\n`);

console.log("— 1. demo-agent connects through AgentGate; read-only calls —");
const agent = await connectAgent("demo-agent-token");
const { tools } = await agent.listTools();
console.log(`  tools visible through the gateway: ${tools.map((t) => t.name).join(", ")}`);
check(tools.some((t) => t.name === "terminate_instance"), "demo-agent can see terminate_instance (allowlisted)");

const resources = await agent.callTool({ name: "list_resources", arguments: {} });
console.log(`  list_resources -> ${resultText(resources).split("\n")[1]?.trim() ?? "ok"} ...`);
check(!resources.isError, "list_resources allowed and executed");

const costs = await agent.callTool({ name: "get_cost_summary", arguments: {} });
check(resultText(costs).includes("463.07"), "get_cost_summary returned the mock total ($463.07)");

console.log("\n— 2. poisoned tool result: screening —");
const notes = await agent.callTool({ name: "get_incident_notes", arguments: {} });
const notesText = resultText(notes);
console.log(notesText.split("\n").map((l) => `  | ${l}`).join("\n"));
check(notesText.includes("AGENTGATE SCREENING WARNING"), "injection flagged with a warning banner");
check(!notesText.includes("123-45-6789"), "SSN redacted before reaching the agent");
check(!notesText.includes("jane.ops@example.com"), "email redacted before reaching the agent");

console.log("\n— 3. destructive call: approval flow —");
const terminatePromise = agent.callTool({
  name: "terminate_instance",
  arguments: { instanceId: "i-demo-batch-02" },
});
let pendingId;
for (let i = 0; i < 50 && !pendingId; i++) {
  const dir = join(stateDir, "approvals");
  if (existsSync(dir)) {
    const pending = readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")))
      .find((r) => r.status === "pending");
    if (pending) pendingId = pending.id;
  }
  if (!pendingId) await sleep(200);
}
check(Boolean(pendingId), `terminate_instance paused; approval request written (${pendingId})`);
console.log(`  a human approves it out-of-band:  node dist/src/cli.js approve ${pendingId}`);
const approveRun = spawnSync(process.execPath, [join(root, "dist/src/cli.js"), "approve", pendingId], {
  env: { ...process.env, AGENTGATE_STATE_DIR: stateDir },
  encoding: "utf8",
});
console.log(`  CLI: ${approveRun.stdout.trim()}`);
const terminated = await terminatePromise;
check(!terminated.isError && resultText(terminated).includes("terminated"), "approved call executed upstream");

console.log("\n— 4. readonly-agent: same call, denied outright —");
const reader = await connectAgent("readonly-agent-token");
const readerTools = await reader.listTools();
check(
  !readerTools.tools.some((t) => t.name === "terminate_instance"),
  "terminate_instance is hidden from readonly-agent's tool list",
);
const denied = await reader.callTool({
  name: "terminate_instance",
  arguments: { instanceId: "i-demo-batch-02" },
});
console.log(`  -> ${resultText(denied)}`);
check(Boolean(denied.isError) && resultText(denied).includes("DENIED"), "readonly-agent denied by allowlist");
await reader.close();
await agent.close();

console.log("\n— 5. audit log + hash-chain verification —");
const entries = readFileSync(join(stateDir, "audit.jsonl"), "utf8")
  .split("\n")
  .filter(Boolean)
  .map((l) => JSON.parse(l));
for (const e of entries) {
  const detail =
    e.type === "policy_decision" ? `${e.tool} -> ${e.effect}` : e.type === "screening_findings" ? e.findings.map((f) => f.pattern).join(", ") : "";
  console.log(`  #${e.seq} ${e.type}${detail ? ` (${detail})` : ""}`);
}
const verify = spawnSync(process.execPath, [join(root, "dist/src/cli.js"), "audit", "verify"], {
  env: { ...process.env, AGENTGATE_STATE_DIR: stateDir },
  encoding: "utf8",
});
console.log(`  ${verify.stdout.trim()}`);
check(verify.status === 0, "audit hash chain verifies");

console.log("\n— 6. evidence pack export —");
const demoTrace = entries.find((e) => e.type === "session_start" && e.agent === "demo-agent").traceId;
const evidencePath = join(stateDir, "evidence.json");
const ev = spawnSync(
  process.execPath,
  [join(root, "dist/src/cli.js"), "evidence", "--trace", demoTrace, "--out", evidencePath],
  { env: { ...process.env, AGENTGATE_STATE_DIR: stateDir }, encoding: "utf8" },
);
console.log(`  ${ev.stdout.trim()}`);
check(ev.status === 0 && existsSync(evidencePath), "evidence pack exported");

console.log(failures.length === 0 ? "\n=== DEMO OK — every step passed ===" : `\n=== DEMO FAILED: ${failures.length} step(s) ===`);
process.exit(failures.length === 0 ? 0 : 1);
