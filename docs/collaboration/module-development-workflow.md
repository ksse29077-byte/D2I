# Module Development Workflow

## Baseline

Every parallel module starts from the latest `origin/main` available when its
issue is assigned. Cognitive IR v1, Module
Contract v1, Module Manifest v1, Rust SDK, conformance verdicts, stable error
and exit codes, canonical JSON/hash rules, CognitiveExecutor laws, ADR 0014,
and ADR 0015 are Core-owned.

The repository contains no production module loader. A module returns a
side-effect-free cognitive result through the SDK; it never receives adapter,
policy, activation, audit, filesystem, process, secret, or network authority.

## State Flow

```text
Cognitive Module Issue complete and assigned
-> issue readiness and contract completeness validated
-> employee GPT creates a repository-grounded Codex work order
-> automated and author checks confirm the work order stays in module scope
-> module/<issue-number>-<module-id> branch
-> manifest, schemas, implementation, fixtures, evaluation, and documentation
-> author checks
-> module PR
-> required CI and optional peer review
-> Core review when a trigger applies
-> author or maintainer manual squash merge
-> issue closure
```

No implementation starts when the issue omits a required contract reference,
finite limit, acceptance threshold, security treatment, or license status.
The readiness result is `Issue 보완 필요`.

## Module Work Order

The Codex work order is generated from the ready issue and repository, not
written from memory. It must identify:

1. Issue and assignee.
2. Purpose and bounded scenarios.
3. Existing contract and exact baseline.
4. Allowed paths under one `modules/<module-id>/` directory.
5. Forbidden Core-owned paths.
6. Ordered implementation steps.
7. Normal, error, unsupported, replay, and security fixtures.
8. Conformance and deterministic replay commands.
9. Evaluation metrics, thresholds, and critical errors.
10. Security and untrusted-content handling.
11. Data, model, dependency, and license evidence.
12. Branch, commit, and PR rules.
13. Definition of done and owner review points.

Unverified details remain blockers. The work order may not invent schema IDs,
capability semantics, paths, APIs, limits, or acceptance thresholds.

## Implementation Boundary

Module work changes exactly one `modules/<module-id>/` directory, including
that standalone workspace's `Cargo.toml` and `Cargo.lock`. Root `Cargo.toml`
and root `Cargo.lock` are always Core-owned and never accompany a module-only
PR. Unrelated formatting, generated build output, customer data, credentials,
and production integration are out of scope.

Use `crates/d2i-module-sdk`, `crates/d2i-cognitive-ir` when Cognitive IR types
are needed, and the checked-in schemas. Do not depend on a product, runtime,
CLI, FFI, Windows, UIA, WebDriver, WFP, policy, activation, or audit
implementation. Each module's `tests/conformance.rs` validates its manifest
and runs its registered fixture suite without dynamic loading.

## Required Local Checks

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/<module-id> `
  -OutputPath build/module-checks/<module-id>.json
```

Record failures honestly. `skipped` and `unsupported` are not passes.

## Merge And Completion

Module changes use a PR and required automated checks, but a third-party
approval is not a merge condition. The module author may manually squash-merge
their own PR when all required checks pass on the current head, conversations
are resolved, the PR is ready and conflict-free, and no Core-owned path or
shared contract changed. Peer review remains available but is optional.

Core, contract, security, trust-boundary, shared workflow, ADR, root Cargo, and
shared policy changes require a separate Core PR and a current-head
approval from a non-author Core CODEOWNER. Automatic merge is prohibited. The
PR title becomes the squash commit title. Close the issue only after the
merged commit and reports are linked.
