# D2I Progress Snapshot

Date: 2026-07-28

## Current Completed Scope

- Rust workspace baseline for D2I compiler, runtime, adapter, learning,
  embodied, desktop, and Windows host crates.
- Source-pack validation, typed IR, deterministic package generation, package
  verification, reference runtime, executor selection/evaluation, native ABI,
  controlled learning, embodied contracts, and desktop autonomy foundation.
- Desktop Windows security baseline including signed activation, protected
  audit/activation storage, Windows worker boundaries, and concrete WFP
  loopback browser-egress contracts.
- Cognitive IR v1 and model-free `CognitiveExecutor` baseline.
- Cognitive Module Contract v1, Rust Module SDK, deterministic fixture runner,
  Conformance Suite, starter template, and `RuleBasedWorkReporter`.

## Cognitive Core Status

Implemented in `products/d2i-desktop/src/cognitive.rs`:

- `GoalSpec`
- `ObservationSnapshot`
- `WorldState`
- `PlanGraph`
- `ActionProposal`
- `Postcondition`
- `VerificationResult`
- `RecoveryDecision`
- `WorkReport`
- narrow traits for observation, world reduction, capability lookup, candidate
  generation, policy, activation, action execution, verification, recovery,
  and audit.

The baseline executor is deterministic and model-free. It executes one action
at a time, reobserves after execution, verifies postconditions before
continuing, rejects stale proposals, bounds retries/replans/deadlines, and
fails closed for unsupported or incomplete contracts.

## Documents Added

- `docs/adr/0014-contract-governed-cognitive-task-runtime.md`
- `docs/cognitive-ir-v1.md`
- `schemas/cognitive/cognitive-ir-v1.schema.json`
- `docs/adr/0015-versioned-cognitive-module-contract-and-conformance-platform.md`
- `docs/modules/`
- `schemas/modules/`

## Cognitive Module Platform Status

Implemented in `crates/d2i-module-sdk`:

- versioned module identity, capability, invocation, result, and error contracts
- strict JSON parsing with unknown/duplicate-field and nesting rejection
- canonical JSON and stable SHA-256 hashing
- Module Manifest v1 loading, path containment, schema compilation, and
  artifact/schema hash verification
- deny-by-default network, side-effect, privilege, secret, and retention policy
- typed Rust `Module` SDK with schema conversion, stale lifecycle checks,
  panic boundary, logical timeout, resource limits, result binding, and
  untrusted-content guard
- deterministic fixture runner and stable machine-readable conformance report

Repository Decoupling v1:

- pure Cognitive IR v1 contracts extracted to `crates/d2i-cognitive-ir`
- `d2i-desktop` imports and re-exports the exact Core types
- root Cargo workspace excludes `modules/*`
- every module is a standalone workspace with a local `Cargo.lock`
- Core crates and CLI have no dependency on a module implementation
- dynamic module discovery and module-local locked quality checks
- module-only/Core-only/Core-contract/mixed migration CI classification
- synthetic parallel module merge/rebase and lockfile independence tests

Reference module assets:

- `modules/example-module` copyable starter
- `modules/rule-based-work-reporter` deterministic Cognitive IR to
  `WorkReport` implementation
- valid, invalid, unsupported, untrusted-content, deadline, capability, and
  deterministic replay fixtures
- model/data cards, threat models, license declarations, and PR checklist

Official module check:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/rule-based-work-reporter
```

The Core CLI intentionally returns structured `unsupported` for module
execution because it does not link standalone implementations. The reference manifest hash is
`sha256:d2c404a923beb9327bc2c5a4f7efec4b2a365144e68b41a3e6821158a389dcca`;
the latest conformance report hash is
`sha256:d1d0d4452fa648047caf1489b0bd6934d6cf394abe16be5a603337b9cf5ae366`.

## Test Coverage Added

`products/d2i-desktop/tests/cognitive_runtime.rs` covers:

- Cognitive IR Rust/JSON round trip
- JSON Schema validation
- unknown-field, invalid enum, and invalid version rejection
- stable observation and report hashes
- plan DAG cycle rejection
- unbounded loop rejection
- single-step execute/reobserve/verify ordering
- stale observation and stale plan generation rejection
- policy and activation deny before executor invocation
- postcondition failure without blind remaining-plan execution
- bounded retry success and exhaustion
- reobserve and replan recovery
- unsupported irreversible action rejection
- untrusted observation content not elevated into an action
- deadline and audit fail-closed behavior
- deterministic replay with identical `WorkReport`
- module contract/schema round trips and stable canonical hashes
- duplicate key, invalid version/enum/hash, path traversal, and raw secret
  rejection
- manifest/artifact tamper and stale manifest identity rejection
- deny-by-default manifest values
- typed invocation and result binding
- panic, logical timeout, invalid output, secret leakage, and unsupported input
  fail-closed behavior
- stable conformance report and exit codes
- starter and reference module deterministic replay

## Application Semantics Status

Implemented in `crates/d2i-application-semantics`:

- strict Application Pack v1 Rust and JSON Schema contracts
- immutable pack identity and canonical SHA-256 verification
- exact UIA/Web source and target-binding admission
- bounded semantic targets, aliases, kinds, and term constraints
- deterministic `ObservationFixture` to Cognitive IR v1 snapshot conversion
- Element Grounder v1 module-owned payload bridge without a module dependency
- UIA/Web fixture, schema compatibility, replay, stale, tamper, ambiguity,
  redaction, secret, and untrusted-content tests
- concrete `d2i-desktop` UIA observation-to-payload integration coverage
- bounded, read-only-only WebDriver observation retry for transient Windows
  loopback aborts; mutation requests remain excluded and fail closed

Cognitive IR v1, Module Contract v1, Module SDK, Element Grounder v1, package
data, Runtime ABI, Windows observation schemas, and action execution remain
unchanged.

## Verification

Passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

## Boundaries Preserved

- No natural-language model implementation.
- No GUI implementation.
- No real UIA/Web observation implementation.
- No real WebDriver execution implementation.
- No external network feature.
- No production package format or Runtime ABI change.
- No concrete WFP, Windows adapter, activation ledger, or protected audit
  storage changes in the Cognitive Core work.
- No production module loader, package embedding, native ABI, Mojo loader, or
  CognitiveExecutor production-flow connection.

## Next Task

`Action Candidate Provider v1 계약 검토 및 semantic target →
capability-bound ActionProposal fixture bridge`

Do not start production module loading, action execution, Runtime ABI, or
package embedding as part of Application Semantics v1.
