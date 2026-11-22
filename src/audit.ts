/**
 * Tamper-evident audit log.
 *
 * Append-only JSONL where every entry carries the SHA-256 hash of the
 * previous entry ("hash chain"). Rewriting or deleting any historical entry
 * breaks every hash after it, so tampering is detectable offline with
 * `agentgate audit verify`.
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditEntry {
  seq: number;
  ts: string;
  traceId: string;
  type: string;
  [key: string]: unknown;
  prevHash: string;
  hash: string;
}

/** Deterministic JSON: object keys sorted recursively. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

export function entryHash(entryWithoutHash: Record<string, unknown>): string {
  return createHash("sha256").update(canonical(entryWithoutHash)).digest("hex");
}

export class AuditLog {
  private seq = 0;
  private lastHash = GENESIS_HASH;
  // Instance identity for fleet rollups (AgentTrace): which process
  // of this gateway wrote the entry. From the shared AGENT_INSTANCE
  // env var; "default" when unset. Resolved once -- one process is
  // one instance for its whole life.
  private readonly instance = process.env.AGENT_INSTANCE || "default";

  constructor(private readonly path: string) {
    if (existsSync(path)) {
      const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.trim());
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]) as AuditEntry;
        this.seq = last.seq;
        this.lastHash = last.hash;
      }
    }
  }

  append(type: string, traceId: string, fields: Record<string, unknown> = {}): AuditEntry {
    const base: Record<string, unknown> = {
      seq: this.seq + 1,
      ts: new Date().toISOString(),
      traceId,
      type,
      instance: this.instance,
      ...fields,
      prevHash: this.lastHash,
    };
    const entry = { ...base, hash: entryHash(base) } as AuditEntry;
    appendFileSync(this.path, JSON.stringify(entry) + "\n");
    this.seq = entry.seq;
    this.lastHash = entry.hash;
    return entry;
  }
}

export interface VerifyResult {
  ok: boolean;
  entries: number;
  brokenAtSeq?: number;
  reason?: string;
}

/** Recompute the whole chain from disk. Any edit, deletion, or reordering fails. */
export function verifyChain(path: string): VerifyResult {
  if (!existsSync(path)) return { ok: false, entries: 0, reason: "log file not found" };
  const lines = readFileSync(path, "utf8").split("\n").filter((l) => l.trim());
  let prevHash = GENESIS_HASH;
  for (let i = 0; i < lines.length; i++) {
    let entry: AuditEntry;
    try {
      entry = JSON.parse(lines[i]) as AuditEntry;
    } catch {
      return { ok: false, entries: lines.length, brokenAtSeq: i + 1, reason: "line is not valid JSON" };
    }
    if (entry.seq !== i + 1) {
      return { ok: false, entries: lines.length, brokenAtSeq: entry.seq, reason: `sequence gap: expected ${i + 1}, found ${entry.seq}` };
    }
    if (entry.prevHash !== prevHash) {
      return { ok: false, entries: lines.length, brokenAtSeq: entry.seq, reason: "prevHash does not match the previous entry's hash" };
    }
    const { hash, ...rest } = entry;
    if (entryHash(rest) !== hash) {
      return { ok: false, entries: lines.length, brokenAtSeq: entry.seq, reason: "entry hash mismatch — content was modified after it was written" };
    }
    prevHash = hash;
  }
  return { ok: true, entries: lines.length };
}

export function readEntries(path: string): AuditEntry[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as AuditEntry);
}
