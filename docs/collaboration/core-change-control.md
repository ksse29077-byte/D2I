# Core Change Control

## Core-Owned Contract

Core ownership covers:

- Cognitive IR v1 public types and schema
- Module Contract public types and Module Manifest v1 schema
- Module SDK public traits and envelopes
- canonical JSON and stable hash rules
- Conformance Suite verdicts, stable errors, and stable exit codes
- CognitiveExecutor execution laws
- ADR 0014 and ADR 0015
- production package and Runtime ABI
- policy, activation, audit, WFP, and Windows adapter boundaries

The machine-readable path list is `.github/core-owned-paths.txt`. CODEOWNERS
and the module PR workflow protect the corresponding repository paths.

## Required RFC Flow

```text
separate Core RFC Issue
-> impact analysis
-> ADR or contract revision proposal
-> Core owner review
-> dedicated Core-only PR
-> new contract version
-> migration and compatibility tests
-> approval and merge
-> module issue/work order refreshed
-> module PR resumes
```

An RFC in `Pending` state grants no permission. The module author must not edit
Core files, weaken tests, copy a Core type locally, or silently introduce a
parallel schema. A Core change and module implementation never share a PR.

New schemas, capability categories, confidence semantics, network or side
effects, model-backed behavior, external dependencies, trust-boundary changes,
production package mapping, and Runtime ABI proposals require Core review even
when the first draft appears module-local.

Contract versions are never overwritten in place. The dedicated Core PR must
state compatibility, migration, affected modules, rollback, security impact,
and the tests that preserve old-version behavior.
