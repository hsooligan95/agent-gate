---
mode: agent
description: Write tests for a named module in agent-gate
---

Write tests for the module I name, following this repo's existing test
style, layout, and fixtures. Cover the behavior the module documents,
including these invariants where they apply:

- Fail closed, always: an unknown agent token refuses startup, and no policy path defaults to allow.
- Policy rules are first-match ordered, matched on tool name AND argument patterns; preserve that ordering semantics.
- Upstream results are screened before the agent sees them; new screening patterns belong in src/screen.ts with tests.

Then run the test suite:

    npm test

Show the result. Do not claim done unless the suite is green; if a
test cannot pass, say why instead of weakening the assertion.
