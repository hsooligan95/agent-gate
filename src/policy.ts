/**
 * Policy loading and evaluation.
 *
 * Decision pipeline for every tools/call:
 *   1. the tool must match the agent's allowedTools globs (else DENY)
 *   2. rules are evaluated in order; first match wins
 *   3. no rule matches -> policy.defaultEffect
 */
import { readFileSync } from "node:fs";

export type Effect = "allow" | "deny" | "require-approval";

export interface AgentIdentity {
  name: string;
  description?: string;
  token?: string;
  tokenEnv?: string;
  allowedTools: string[];
}

export interface PolicyRule {
  tool: string;
  args?: Record<string, string>;
  effect: Effect;
  reason?: string;
}

export interface ScreeningConfig {
  enabled: boolean;
  /** redact = replace PII values in place; off = leave values untouched (findings still audited) */
  pii: "redact" | "off";
  /** flag = deliver with a warning banner; block = withhold the result; off = deliver silently */
  injection: "flag" | "block" | "off";
}

export interface Policy {
  version: number;
  agents: AgentIdentity[];
  rules: PolicyRule[];
  defaultEffect: Effect;
  approvalTimeoutMs: number;
  screening: ScreeningConfig;
}

export function loadPolicy(path: string): Policy {
  const raw = JSON.parse(readFileSync(path, "utf8")) as Policy;
  if (!Array.isArray(raw.agents) || raw.agents.length === 0) {
    throw new Error(`Policy ${path}: at least one agent is required`);
  }
  raw.defaultEffect ??= "deny";
  raw.approvalTimeoutMs ??= 60_000;
  raw.screening ??= { enabled: true, pii: "redact", injection: "flag" };
  return raw;
}

/** Resolve the agent for a presented token. Returns null when nothing matches. */
export function authenticate(policy: Policy, token: string | undefined): AgentIdentity | null {
  if (!token) return null;
  for (const agent of policy.agents) {
    const expected = agent.tokenEnv ? process.env[agent.tokenEnv] : agent.token;
    if (expected && expected === token) return agent;
  }
  return null;
}

/** Glob match supporting a single trailing or embedded `*` wildcard style (e.g. "list_*", "i-prod-*"). */
export function globMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`).test(value);
}

export interface Decision {
  effect: Effect;
  reason: string;
  stage: "allowlist" | "rule" | "default";
  ruleIndex?: number;
}

export function evaluate(
  policy: Policy,
  agent: AgentIdentity,
  tool: string,
  args: Record<string, unknown> = {},
): Decision {
  const allowlisted = agent.allowedTools.some((p) => globMatch(p, tool));
  if (!allowlisted) {
    return {
      effect: "deny",
      stage: "allowlist",
      reason: `Tool '${tool}' is not in agent '${agent.name}'s allowlist (${agent.allowedTools.join(", ")}).`,
    };
  }
  for (let i = 0; i < policy.rules.length; i++) {
    const rule = policy.rules[i];
    if (!globMatch(rule.tool, tool)) continue;
    if (rule.args) {
      const argsOk = Object.entries(rule.args).every(([key, pattern]) => {
        const v = args[key];
        return v !== undefined && globMatch(pattern, String(v));
      });
      if (!argsOk) continue;
    }
    return {
      effect: rule.effect,
      stage: "rule",
      ruleIndex: i,
      reason: rule.reason ?? `Matched rule #${i} for tool '${tool}'.`,
    };
  }
  return {
    effect: policy.defaultEffect,
    stage: "default",
    reason: `No rule matched tool '${tool}'; default effect '${policy.defaultEffect}' applied.`,
  };
}
