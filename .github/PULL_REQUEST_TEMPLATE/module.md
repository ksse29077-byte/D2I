## Cognitive Module Submission

Linked issue: Closes #

Module ID and version:

Implemented capability ID and version:

Scope:

Out of scope:

Changed files:

## Contract

Cognitive IR input/output types:

Input/output schema IDs, versions, and paths:

Module Manifest path:

Deterministic behavior and replay evidence:

Confidence semantics:

Unsupported-case and fallback policy:

Network and side-effect declaration:

Core contract change: none / approved Core RFC link

## Data, Model, Security, And License

Data/model summary and versions:

License and commercial-use summary:

Threat model:

Untrusted-content and secret handling:

Security negative tests:

## Verification

Unit tests:

Fixture report:

Conformance result and report hash:

Evaluation metrics and acceptance result:

Benchmark and baseline:

Known limitations:

Reviewer focus:

Rollback:

## Author Checklist

- [ ] Changes are limited to exactly one `modules/<module-id>/` directory
- [ ] Root `Cargo.toml` and root `Cargo.lock` are unchanged
- [ ] Core-owned files are unchanged
- [ ] No Core contract or Module SDK public API changed
- [ ] Module Manifest v1 and strict versioned input/output schemas are included
- [ ] Artifact, manifest, and schema hashes validate
- [ ] Normal, error, unsupported, deterministic replay, and security fixtures execute
- [ ] Conformance status is `pass`; `skipped` or `unsupported` is not counted as pass
- [ ] No hidden network access
- [ ] No raw secret input or output
- [ ] Untrusted content is not promoted to instructions, policy, capability, or action
- [ ] No test or acceptance threshold was weakened to obtain a pass
- [ ] No asset with unclear commercial-use rights is included
- [ ] No production loader or Runtime ABI connection is included
- [ ] No actual side effect is included unless separately approved by Core and policy owners
- [ ] Model card, data card, `licenses.json`, and threat model are present
- [ ] Module-local `Cargo.lock` is committed
- [ ] `scripts/modules/check-module.ps1` reports `pass`
- [ ] Module-local fmt, Clippy `-D warnings`, tests, conformance, replay, and release build pass
- [ ] Every review conversation is resolved
- [ ] Automatic merge is disabled
- [ ] The module owner accepts post-merge maintenance responsibility

Module-only PRs do not require a third-party approval after all required checks
pass. The module author may perform the manual squash merge. If this PR changes
any path in `.github/core-owned-paths.txt`, stop the module PR and use the
separate Core RFC and Core-only PR flow; a current-head approval from a
non-author Core CODEOWNER is required.
