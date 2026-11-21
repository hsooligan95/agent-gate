import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { AuditLog, readEntries, verifyChain } from "../src/audit.js";

function freshLog() {
  const dir = mkdtempSync(join(tmpdir(), "agentgate-audit-test-"));
  return join(dir, "audit.jsonl");
}

test("appends form a verifiable hash chain", () => {
  const path = freshLog();
  const log = new AuditLog(path);
  log.append("session_start", "trace-1", { agent: "demo-agent" });
  log.append("policy_decision", "trace-1", { tool: "list_resources", effect: "allow" });
  log.append("tool_executed", "trace-1", { tool: "list_resources" });
  const result = verifyChain(path);
  assert.ok(result.ok);
  assert.equal(result.entries, 3);
  const entries = readEntries(path);
  assert.deepEqual(entries.map((e) => e.seq), [1, 2, 3]);
  assert.equal(entries[1].prevHash, entries[0].hash);
});

test("a second AuditLog on the same file continues the chain", () => {
  const path = freshLog();
  new AuditLog(path).append("session_start", "trace-1", {});
  const log2 = new AuditLog(path);
  const e = log2.append("session_start", "trace-2", {});
  assert.equal(e.seq, 2);
  assert.ok(verifyChain(path).ok);
});

test("tampering with a historical entry breaks verification", () => {
  const path = freshLog();
  const log = new AuditLog(path);
  log.append("policy_decision", "trace-1", { tool: "terminate_instance", effect: "require-approval" });
  log.append("approval_resolved", "trace-1", { outcome: "denied by approver" });
  log.append("session_end", "trace-1", {});
  // Attacker rewrites history: the denial becomes an approval.
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
  const tampered = JSON.parse(lines[1]);
  tampered.outcome = "approved";
  lines[1] = JSON.stringify(tampered);
  writeFileSync(path, lines.join("\n") + "\n");
  const result = verifyChain(path);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAtSeq, 2);
});

test("deleting an entry breaks verification", () => {
  const path = freshLog();
  const log = new AuditLog(path);
  log.append("a", "t", {});
  log.append("b", "t", {});
  log.append("c", "t", {});
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
  writeFileSync(path, [lines[0], lines[2]].join("\n") + "\n");
  assert.equal(verifyChain(path).ok, false);
});

test("missing log file fails verification cleanly", () => {
  const result = verifyChain(join(tmpdir(), "agentgate-definitely-missing.jsonl"));
  assert.equal(result.ok, false);
  assert.equal(result.entries, 0);
});
