#!/usr/bin/env node
/**
 * AgentGate × CredBroker demo — the interlock, end to end.
 *
 * Broker mode makes the gateway require a CredBroker token (from the
 * sibling cred-broker repo) before any tool call executes. All tokens
 * below are minted by the REAL Python broker — policy, scope-down and
 * signing included — via `credbroker.mint_cli`; this gateway verifies
 * them locally in TypeScript against the documented token format.
 *
 *   1. no token presented        -> gateway refuses to start (fail closed)
 *   2. valid token, scope tool/* -> read calls execute
 *   3. valid token, scope tool/get_cost_summary only
 *                                -> that call executes; list_resources
 *                                   is DENIED on broker scope
 *   4. expired token             -> DENIED by the broker check
 *   5. the audit log's decision records carry the broker grant ID (jti)
 *
 * Needs the sibling cred-broker checkout (override with CREDBROKER_HOME)
 * and a built gateway (`npm run demo:broker` builds first).
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const credBrokerHome = process.env.CREDBROKER_HOME ?? join(root, "..", "cred-broker");
const stateDir = mkdtempSync(join(tmpdir(), "agentgate-broker-demo-"));
const KEY = "demo-signing-key-not-a-real-secret"; // cred-broker's synthetic demo key
const TRACE = "trace-gate-broker-demo";
const failures = [];
const check = (cond, label) => {
  console.log(`  ${cond ? "✓" : "✗ FAILED:"} ${label}`);
  if (!cond) failures.push(label);
};
const resultText = (res) => res.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");

if (!existsSync(join(credBrokerHome, "src", "credbroker", "mint_cli.py"))) {
  console.log(`✗ sibling cred-broker checkout not found at ${credBrokerHome} (set CREDBROKER_HOME)`);
  process.exit(1);
}

function mint(label, extraArgs) {
  const out = join(stateDir, `token-${label}.txt`);
  const run = spawnSync(
    "python3",
    ["-m", "credbroker.mint_cli", "--agent", "demo-agent", "--trace-id", TRACE,
     "--out", out, ...extraArgs],
    {
      env: { ...process.env, PYTHONPATH: join(credBrokerHome, "src") },
      encoding: "utf8",
    },
  );
  if (run.status !== 0) {
    console.log(run.stdout ?? "");
    console.log(run.stderr ?? "");
    throw new Error(`mint_cli failed for ${label}`);
  }
  console.log(`  cred-broker: ${run.stdout.trim()}`);
  return out;
}

async function connectBrokerAgent(tokenFile) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      join(root, "dist/src/index.js"),
      "--broker",
      "--trace-id", TRACE,
      "--upstream",
      process.execPath,
      join(root, "demo-upstream/server.mjs"),
    ],
    env: {
      ...process.env,
      AGENTGATE_TOKEN: "demo-agent-token",
      AGENTGATE_POLICY: join(root, "policy.json"),
      AGENTGATE_STATE_DIR: stateDir,
      AGENTGATE_BROKER_KEY: KEY,
      ...(tokenFile ? { AGENTGATE_BROKER_TOKEN_FILE: tokenFile } : {}),
    },
    stderr: "inherit",
  });
  const client = new Client({ name: "demo-broker-client", version: "1.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return client;
}

console.log("=== AgentGate × CredBroker demo (broker mode) ===");
console.log(`state dir (audit + approvals): ${stateDir}`);
console.log(`tokens minted by: ${join(credBrokerHome, "src", "credbroker", "mint_cli.py")}\n`);

console.log("— 1. no CredBroker token presented: the gateway refuses to start —");
const noToken = spawnSync(
  process.execPath,
  [join(root, "dist/src/index.js"), "--broker", "--trace-id", TRACE,
   "--upstream", process.execPath, join(root, "demo-upstream/server.mjs")],
  {
    env: {
      ...process.env,
      AGENTGATE_TOKEN: "demo-agent-token",
      AGENTGATE_POLICY: join(root, "policy.json"),
      AGENTGATE_STATE_DIR: stateDir,
      AGENTGATE_BROKER_KEY: KEY,
    },
    encoding: "utf8",
    timeout: 15000,
  },
);
const refusal = (noToken.stderr ?? "").split("\n").find((l) => l.includes("CredBroker")) ?? "";
console.log(`  gateway: ${refusal.trim()}`);
check(noToken.status === 2 && refusal.includes("Refusing to start"),
  "no token -> gateway exits 2, fail closed, before any upstream connection");

console.log("\n— 2. valid token with covering scope (tool/*): calls execute —");
const fullToken = mint("full", ["--resource", "tool/*"]);
const agent = await connectBrokerAgent(fullToken);
const resources = await agent.callTool({ name: "list_resources", arguments: {} });
check(!resources.isError, "list_resources allowed by policy AND broker, executed");
const costs = await agent.callTool({ name: "get_cost_summary", arguments: {} });
check(resultText(costs).includes("463.07"), "get_cost_summary executed ($463.07)");
await agent.close();

console.log("\n— 3. valid token with narrower scope (tool/get_cost_summary only) —");
const narrowToken = mint("narrow", ["--resource", "tool/get_cost_summary"]);
const narrow = await connectBrokerAgent(narrowToken);
const narrowCosts = await narrow.callTool({ name: "get_cost_summary", arguments: {} });
check(!narrowCosts.isError, "the one covered tool still executes — the token works");
const narrowDenied = await narrow.callTool({ name: "list_resources", arguments: {} });
console.log(`  -> ${resultText(narrowDenied)}`);
check(
  Boolean(narrowDenied.isError) && resultText(narrowDenied).includes("outside the token's scope"),
  "list_resources DENIED on broker scope (policy alone would have allowed it)",
);
await narrow.close();

console.log("\n— 4. expired token: denied by the broker check —");
const expiredToken = mint("expired", ["--resource", "tool/*", "--expired"]);
const stale = await connectBrokerAgent(expiredToken);
const staleDenied = await stale.callTool({ name: "list_resources", arguments: {} });
console.log(`  -> ${resultText(staleDenied)}`);
check(
  Boolean(staleDenied.isError) && resultText(staleDenied).includes("CredBroker: token expired"),
  "expired token DENIED with the broker's reason",
);
await stale.close();

console.log("\n— 5. decision records carry the broker grant ID —");
const entries = readFileSync(join(stateDir, "audit.jsonl"), "utf8")
  .split("\n")
  .filter(Boolean)
  .map((l) => JSON.parse(l));
const allowed = entries.find(
  (e) => e.type === "policy_decision" && e.tool === "list_resources" && e.brokerOk === true,
);
console.log(`  policy_decision for list_resources: brokerOk=${allowed?.brokerOk}, brokerJti=${allowed?.brokerJti}`);
check(allowed?.brokerJti === "cred-0001", "the allowed call's decision record carries grant cred-0001");
const scoped = entries.find(
  (e) => e.type === "policy_decision" && e.tool === "list_resources" && e.brokerOk === false,
);
console.log(`  denied decision: brokerOk=${scoped?.brokerOk}, brokerReason=${scoped?.brokerReason}`);
check(Boolean(scoped?.brokerReason?.includes("outside the token's scope")),
  "the scope denial is on the decision record too");
const verify = spawnSync(process.execPath, [join(root, "dist/src/cli.js"), "audit", "verify"], {
  env: { ...process.env, AGENTGATE_STATE_DIR: stateDir },
  encoding: "utf8",
});
console.log(`  ${verify.stdout.trim()}`);
check(verify.status === 0, "audit hash chain verifies");

console.log(failures.length === 0 ? "\n=== BROKER DEMO OK — every step passed ===" : `\n=== BROKER DEMO FAILED: ${failures.length} step(s) ===`);
process.exit(failures.length === 0 ? 0 : 1);
