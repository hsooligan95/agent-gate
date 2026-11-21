import assert from "node:assert/strict";
import { test } from "node:test";
import { authenticate, evaluate, globMatch, loadPolicy, type Policy } from "../src/policy.js";

const policy = loadPolicy(new URL("../../policy.json", import.meta.url).pathname);
const demo = policy.agents.find((a) => a.name === "demo-agent")!;
const reader = policy.agents.find((a) => a.name === "readonly-agent")!;

test("authenticate resolves known tokens and rejects unknown ones", () => {
  assert.equal(authenticate(policy, "demo-agent-token")?.name, "demo-agent");
  assert.equal(authenticate(policy, "readonly-agent-token")?.name, "readonly-agent");
  assert.equal(authenticate(policy, "wrong-token"), null);
  assert.equal(authenticate(policy, undefined), null);
});

test("globMatch handles prefix and embedded wildcards", () => {
  assert.ok(globMatch("list_*", "list_resources"));
  assert.ok(globMatch("i-prod-*", "i-prod-db-01"));
  assert.ok(!globMatch("list_*", "get_cost_summary"));
  assert.ok(globMatch("terminate_instance", "terminate_instance"));
});

test("read tools are allowed for both agents", () => {
  for (const agent of [demo, reader]) {
    assert.equal(evaluate(policy, agent, "list_resources").effect, "allow");
    assert.equal(evaluate(policy, agent, "get_cost_summary").effect, "allow");
    assert.equal(evaluate(policy, agent, "get_incident_notes").effect, "allow");
  }
});

test("destructive tool requires approval for demo-agent", () => {
  const d = evaluate(policy, demo, "terminate_instance", { instanceId: "i-demo-batch-02" });
  assert.equal(d.effect, "require-approval");
  assert.equal(d.stage, "rule");
});

test("destructive tool is denied for readonly-agent at the allowlist stage", () => {
  const d = evaluate(policy, reader, "terminate_instance", { instanceId: "i-demo-batch-02" });
  assert.equal(d.effect, "deny");
  assert.equal(d.stage, "allowlist");
});

test("unlisted tools are denied even for demo-agent", () => {
  const d = evaluate(policy, demo, "drop_database");
  assert.equal(d.effect, "deny");
  assert.equal(d.stage, "allowlist");
});

test("argument-pattern rules can scope an effect to matching arguments", () => {
  const custom: Policy = {
    version: 1,
    agents: [{ name: "ops", token: "t", allowedTools: ["terminate_instance"] }],
    defaultEffect: "deny",
    approvalTimeoutMs: 1000,
    screening: { enabled: true, pii: "redact", injection: "flag" },
    rules: [
      { tool: "terminate_instance", args: { instanceId: "i-prod-*" }, effect: "require-approval", reason: "prod" },
      { tool: "terminate_instance", effect: "allow", reason: "non-prod" },
    ],
  };
  const ops = custom.agents[0];
  assert.equal(
    evaluate(custom, ops, "terminate_instance", { instanceId: "i-prod-db-01" }).effect,
    "require-approval",
  );
  assert.equal(
    evaluate(custom, ops, "terminate_instance", { instanceId: "i-demo-01" }).effect,
    "allow",
  );
});

test("default effect applies when no rule matches an allowlisted tool", () => {
  const custom: Policy = {
    version: 1,
    agents: [{ name: "a", token: "t", allowedTools: ["*"] }],
    defaultEffect: "deny",
    approvalTimeoutMs: 1000,
    screening: { enabled: false, pii: "off", injection: "off" },
    rules: [],
  };
  const d = evaluate(custom, custom.agents[0], "anything_at_all");
  assert.equal(d.effect, "deny");
  assert.equal(d.stage, "default");
});
