/**
 * CredBroker broker mode — optional, off by default.
 *
 * With broker mode on (flag `--broker` or env `AGENTGATE_BROKER=1`),
 * every tool call that policy would let execute must ALSO present a
 * valid CredBroker token (the sibling cred-broker project). The token
 * is bound to this gateway's agent identity and session trace ID, and
 * its granted scope must cover the call, mapped as:
 *
 *   broker resource  =  "tool/<tool name>"   (e.g. "tool/list_resources")
 *   broker action    =  "call"
 *
 * so a token granted `tool/*` covers every tool, and a token granted
 * `tool/get_cost_summary` covers exactly that one.
 *
 * Verification here re-implements cred-broker's own semantics in
 * TypeScript (see cred-broker/src/credbroker/broker.py `verify_token`
 * and tokens.py). The token format is small and fully specified —
 * base64url(canonical JSON claims) + "." + base64url(HMAC-SHA256 over
 * the payload segment) — so the gateway verifies locally instead of
 * spawning a Python process per call. Checks run in cred-broker's
 * order, failing closed:
 *
 *   signature -> expiry -> revocation -> binding (agent, trace) -> scope
 *
 * Configuration (environment):
 *   AGENTGATE_BROKER_KEY          HMAC signing key (bridge: the shared
 *                                 synthetic demo key; a production
 *                                 design would use asymmetric signing
 *                                 or a broker introspection endpoint,
 *                                 so the verifier never holds minting
 *                                 power — cred-broker's README says so)
 *   AGENTGATE_BROKER_TOKEN        the token string, or:
 *   AGENTGATE_BROKER_TOKEN_FILE   a file containing it (what
 *                                 credbroker.mint_cli writes)
 *   AGENTGATE_BROKER_REVOKED_FILE optional file of revoked jtis, one
 *                                 per line; re-read on every call so a
 *                                 revocation appended mid-session takes
 *                                 effect on the next call
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

export interface BrokerConfig {
  key: string;
  token?: string;
  revokedPath?: string;
}

export interface BrokerClaims {
  jti: string;
  agent: string;
  resource: string;
  actions: string[];
  trace_id: string;
  iat: number;
  exp: number;
}

export interface BrokerVerdict {
  ok: boolean;
  /** The broker grant ID (claims.jti) whenever the token parsed. */
  jti?: string;
  claims?: BrokerClaims;
  /** Why verification failed, in cred-broker's wording. Set iff !ok. */
  reason?: string;
}

/** The broker resource a gate tool call maps to. */
export function brokerResourceFor(tool: string): string {
  return `tool/${tool}`;
}

/** The broker action every gate tool call maps to. */
export const BROKER_ACTION = "call";

/** Load broker configuration from the environment. Returns an error
 *  string instead of a config when broker mode cannot run — the
 *  gateway refuses to start rather than run unbrokered (fail closed). */
export function loadBrokerConfig(): BrokerConfig | { error: string } {
  const key = process.env.AGENTGATE_BROKER_KEY;
  if (!key) {
    return { error: "broker mode is on but AGENTGATE_BROKER_KEY is not set" };
  }
  let token = process.env.AGENTGATE_BROKER_TOKEN || undefined;
  const tokenFile = process.env.AGENTGATE_BROKER_TOKEN_FILE;
  if (!token && tokenFile) {
    if (!existsSync(tokenFile)) {
      return { error: `broker token file not found: ${tokenFile}` };
    }
    token = readFileSync(tokenFile, "utf8").trim() || undefined;
  }
  if (!token) {
    return {
      error:
        "broker mode is on but no CredBroker token was presented " +
        "(set AGENTGATE_BROKER_TOKEN or AGENTGATE_BROKER_TOKEN_FILE)",
    };
  }
  return {
    key,
    token,
    revokedPath: process.env.AGENTGATE_BROKER_REVOKED_FILE || undefined,
  };
}

/** Decode a token's claims WITHOUT verifying — for log lines only. */
export function peekJti(token: string): string | undefined {
  try {
    const claims = JSON.parse(
      Buffer.from(token.split(".")[0], "base64url").toString("utf8"),
    ) as Partial<BrokerClaims>;
    return typeof claims.jti === "string" ? claims.jti : undefined;
  } catch {
    return undefined;
  }
}

function loadRevoked(path: string | undefined): Set<string> {
  if (!path || !existsSync(path)) return new Set();
  return new Set(
    readFileSync(path, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean),
  );
}

/** cred-broker's scope rule (broker.py `_in_scope`): exact match, or a
 *  trailing "/*" covering the prefix itself and everything under it. */
export function inScope(granted: string, resource: string): boolean {
  if (granted.endsWith("/*")) {
    return resource === granted.slice(0, -2) || resource.startsWith(granted.slice(0, -1));
  }
  return resource === granted;
}

export function verifyBrokerToken(
  config: BrokerConfig,
  check: { agent: string; traceId: string; tool: string; nowSeconds?: number },
): BrokerVerdict {
  const token = config.token;
  if (!token) return { ok: false, reason: "no CredBroker token presented" };
  if (token.split(".").length !== 2) {
    return { ok: false, reason: "malformed token: expected '<payload>.<signature>'" };
  }
  const [payloadB64, sigB64] = token.split(".");

  // 1. signature — HMAC-SHA256 over the payload segment, constant-time.
  const expected = createHmac("sha256", config.key).update(payloadB64).digest();
  let given: Buffer;
  try {
    given = Buffer.from(sigB64, "base64url");
  } catch {
    return { ok: false, reason: "malformed token: signature is not base64url" };
  }
  if (given.length !== expected.length || !timingSafeEqual(expected, given)) {
    return { ok: false, reason: "bad signature: token was forged or tampered with" };
  }
  let claims: BrokerClaims;
  try {
    claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as BrokerClaims;
  } catch {
    return { ok: false, reason: "malformed token: payload is not JSON" };
  }
  if (typeof claims !== "object" || claims === null || typeof claims.jti !== "string") {
    return { ok: false, reason: "malformed token: payload is not a claims object" };
  }
  const jti = claims.jti;

  // 2. expiry
  const now = check.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (now >= claims.exp) {
    return { ok: false, jti, claims, reason: `token expired at ${claims.exp} (now ${now})` };
  }
  // 3. revocation
  if (loadRevoked(config.revokedPath).has(jti)) {
    return { ok: false, jti, claims, reason: `token ${jti} has been revoked` };
  }
  // 4. binding — agent identity, then the session trace ID
  if (claims.agent !== check.agent) {
    return {
      ok: false, jti, claims,
      reason: `token was issued to '${claims.agent}', not '${check.agent}'`,
    };
  }
  if (claims.trace_id !== check.traceId) {
    return {
      ok: false, jti, claims,
      reason: `token is bound to trace '${claims.trace_id}', not this session's '${check.traceId}'`,
    };
  }
  // 5. scope — resource coverage, then the granted actions
  const resource = brokerResourceFor(check.tool);
  if (!inScope(claims.resource, resource)) {
    return {
      ok: false, jti, claims,
      reason: `resource '${resource}' is outside the token's scope '${claims.resource}'`,
    };
  }
  if (!claims.actions.includes(BROKER_ACTION)) {
    return {
      ok: false, jti, claims,
      reason: `action '${BROKER_ACTION}' is not in the token's actions ${JSON.stringify(claims.actions)}`,
    };
  }
  return { ok: true, jti, claims };
}
