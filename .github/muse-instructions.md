# Copilot instructions — agent-gate

You are working in **AgentGate**, a security gateway for the Model Context
Protocol: it sits between an AI agent and upstream MCP servers and puts
identity, policy, output screening, and a tamper-evident audit log on every
tool call.

## Stack

- TypeScript (strict) on Node.js, built on the official MCP TypeScript
  SDK on both sides (low-level `Server` downstream, `Client` upstream),
  Zod for schemas.
- `src/index.ts` (gateway server), `src/policy.ts` (policy engine),
  `src/screen.ts` (output screening), `src/audit.ts` (hash-chained audit),
  `src/approvals.ts`, `src/cli.ts`. Policy is data: see `policy.json`.

## Tests

```bash
npm test          # builds, then runs node --test over dist/test/*.test.js
npm run build     # tsc only
```

## Architecture notes

- Fail closed, always: an unknown agent token refuses startup, and no
  policy path defaults to allow.
- Every `tools/call` is evaluated against ordered rules — allow, deny, or
  require-approval — matched on tool name AND argument patterns. Preserve
  first-match ordering semantics; reads pass, destructive tools pause for
  a human approver (out-of-band CLI decision).
- Upstream results are screened before the agent sees them: injection
  patterns are flagged or withheld, PII/secrets redacted in place. New
  screening patterns belong in `src/screen.ts` with tests in
  `test/screen.test.ts`.
- The audit log is hash-chained JSONL: never rewrite or reorder entries.
- Trace IDs: `AGENTGATE_TRACE_ID` env var or `--trace-id` overrides the
  self-minted session ID so a run can join an AgentTrace fleet trace;
  self-minting remains the default when neither is supplied.

## Shared rules

- Use Unix LF line endings in every file; never CRLF.
- Never commit secrets, tokens, or credentials — real or synthetic-looking.
- Tests must pass before you describe a change as complete; run the test
  command above and report honestly if you cannot.
- Prefer the smallest complete implementation: reuse what already exists in
  this repo before adding new code, files, or dependencies.
