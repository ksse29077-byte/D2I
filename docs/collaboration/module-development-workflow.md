# Module Development Workflow

## Baseline

Every parallel module starts from commit
`68d5e5f9453b7ea9d58d42f5e1ad3e5184065f2e`. Its Cognitive IR v1, Module
Contract v1, Module Manifest v1, Rust SDK, conformance verdicts, stable error
and exit codes, canonical JSON/hash rules, CognitiveExecutor laws, ADR 0014,
and ADR 0015 are Core-owned.

The repository contains no production module loader. A module returns a
side-effect-free cognitive result through the SDK; it never receives adapter,
policy, activation, audit, filesystem, process, secret, or network authority.

## State Flow

```text
Cognitive Module Issue complete and assigned
-> total owner confirms readiness
-> employee GPT creates a repository-grounded Codex work order
-> total owner approves that work order
-> module/<issue-number>-<module-id> branch
-> manifest, schemas, implementation, fixtures, evaluation, and documentation
-> author checks
-> module PR
-> CI and peer review
-> Core review when a trigger applies
-> manual squash merge
-> issue closure
```

No implementation starts when the issue omits a required contract reference,
finite limit, acceptance threshold, security treatment, or license status.
The readiness result is `Issue 보완 필요`.

## Module Work Order

The approved Codex work order is generated from the issue and repository, not
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

Module work normally changes exactly one `modules/<module-id>/` directory and
the workspace member list only when a new crate must be registered. Changing
the workspace root requires explicit review because it has a repository-wide
effect. Unrelated formatting, generated build output, customer data,
credentials, lockfile churn without a dependency reason, and production
integration are out of scope.

Use `crates/d2i-module-sdk` and the checked-in schemas. `module validate`
checks manifests, schemas, path confinement, hashes, security defaults,
license metadata, and evaluation declarations. Each module's
`tests/conformance.rs` runs its registered fixture suite without dynamic
loading.

## Required Local Checks

```text
cargo run -p d2i-cli -- module validate modules/<module-id> --json
cargo test --manifest-path modules/<module-id>/Cargo.toml --test conformance --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

Record failures honestly. `skipped` and `unsupported` are not passes.

## Merge And Completion

Merge only after required checks pass, review conversations are resolved, and
the required approvals exist. Automatic merge is prohibited. The repository
uses squash merge for team PRs; the PR title becomes the conventional commit.
Close the issue only after the merged commit and reports are linked.
