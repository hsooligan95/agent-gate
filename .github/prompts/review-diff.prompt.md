---
mode: agent
description: Review the current diff against agent-gate's invariants
---

Review my current diff against this repo's invariants:

- Fail closed, always: an unknown agent token refuses startup, and no policy path defaults to allow.
- Policy rules are first-match ordered, matched on tool name AND argument patterns; preserve that ordering semantics.
- Upstream results are screened before the agent sees them; new screening patterns belong in src/screen.ts with tests.
- The audit log is hash-chained JSONL: never rewrite or reorder entries.

Flag every violation with file and line. Also flag any change that
alters a documented behavior contract (output shapes, exit codes,
event schemas, recorded artifacts) without updating the docs and
tests that describe it. No style nitpicks — correctness and contract
violations only.
