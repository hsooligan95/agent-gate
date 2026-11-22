import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  inScope,
  verifyBrokerToken,
  type BrokerClaims,
  type BrokerConfig,
} from "../src/broker.js";

/**
 * Broker-mode verification tests. Fixture tokens are minted here
 * against cred-broker's documented wire format (base64url canonical
 * JSON + "." + base64url HMAC-SHA256 over the payload segment — see
 * cred-broker/src/credbroker/tokens.py). The end-to-end demo
 * (scripts/demo-broker.mjs) covers the cross-repo direction: tokens
 * minted by the real Python broker, verified by this gateway.
 */
const KEY = "demo-signing-key-not-a-real-secret";
const TRACE = "trace-broker-test";
const NOW = 1_800_000_000; // fixed clock for deterministic expiry checks

/** Python json.dumps(obj, sort_keys=True, separators=(",", ":")) for
 *  the flat claim shapes used here. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

function mint(claims: Partial<BrokerClaims>, key: string = KEY): string {
  const full: BrokerClaims = {
    jti: "cred-0001",
    agent: "demo-agent",
    resource: "tool/*",
    actions: ["call"],
    trace_id: TRACE,
    iat: NOW - 60,
    exp: NOW + 3600,
    ...claims,
  };
  const payload = Buffer.from(canonicalJson(full), "utf8").toString("base64url");
  const sig = createHmac("sha256", key).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function config(token?: string, revokedPath?: string): BrokerConfig {
  return { key: KEY, token, revokedPath };
}

const check = { agent: "demo-agent", traceId: TRACE, tool: "list_resources", nowSeconds: NOW };

test("a covering token verifies and returns its grant ID", () => {
  const v = verifyBrokerToken(config(mint({})), check);
  assert.equal(v.ok, true);
  assert.equal(v.jti, "cred-0001");
});

test("an exact-resource token covers its tool and no other", () => {
  const cfg = config(mint({ resource: "tool/get_cost_summary" }));
  assert.equal(verifyBrokerToken(cfg, { ...check, tool: "get_cost_summary" }).ok, true);
  const v = verifyBrokerToken(cfg, check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /outside the token's scope/);
});

test("a token without the 'call' action is denied on scope", () => {
  const v = verifyBrokerToken(config(mint({ actions: ["read"] })), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /not in the token's actions/);
});

test("an expired token is denied", () => {
  const v = verifyBrokerToken(config(mint({ iat: NOW - 7200, exp: NOW - 1 })), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /expired/);
});

test("expiry is reported before scope (cred-broker's verify order)", () => {
  const v = verifyBrokerToken(
    config(mint({ resource: "tool/get_cost_summary", iat: NOW - 7200, exp: NOW - 1 })),
    check,
  );
  assert.equal(v.ok, false);
  assert.match(v.reason!, /expired/);
});

test("a revoked token is denied", () => {
  const dir = mkdtempSync(join(tmpdir(), "agentgate-broker-test-"));
  const revokedPath = join(dir, "revoked.txt");
  writeFileSync(revokedPath, "cred-9999\ncred-0001\n");
  const v = verifyBrokerToken(config(mint({}), revokedPath), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /revoked/);
});

test("a token bound to another agent is denied", () => {
  const v = verifyBrokerToken(config(mint({ agent: "readonly-agent" })), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /was issued to/);
});

test("a token bound to another trace is denied", () => {
  const v = verifyBrokerToken(config(mint({ trace_id: "trace-someone-else" })), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /bound to trace/);
});

test("a tampered payload fails the signature check", () => {
  const [payload, sig] = mint({}).split(".");
  const flipped = (payload[0] === "A" ? "B" : "A") + payload.slice(1);
  const v = verifyBrokerToken(config(`${flipped}.${sig}`), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /bad signature/);
});

test("a token signed with the wrong key fails the signature check", () => {
  const v = verifyBrokerToken(config(mint({}, "some-other-key")), check);
  assert.equal(v.ok, false);
  assert.match(v.reason!, /bad signature/);
});

test("malformed tokens and missing tokens fail closed", () => {
  assert.equal(verifyBrokerToken(config("not-a-token"), check).ok, false);
  assert.equal(verifyBrokerToken(config(undefined), check).ok, false);
  assert.match(verifyBrokerToken(config(undefined), check).reason!, /no CredBroker token/);
});

test("inScope mirrors cred-broker's prefix rule", () => {
  assert.ok(inScope("tool/*", "tool/list_resources"));
  assert.ok(inScope("tool/*", "tool"));
  assert.ok(!inScope("tool/*", "toolbox/list"));
  assert.ok(inScope("tool/list_resources", "tool/list_resources"));
  assert.ok(!inScope("tool/list_resources", "tool/list_secrets"));
});
