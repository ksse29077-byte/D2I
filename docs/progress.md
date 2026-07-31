# D2I Progress Snapshot

Date: 2026-07-31

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

## Action Candidate Provider v1 Status

Implemented in `crates/d2i-action-candidates`:

- sealed semantic-target to `CapabilityDescriptor` bindings
- exact UIA/Web source, observed-kind, operation, Registry, and current plan
  node admission
- closed invoke/set-text/toggle/click/type/select inputs with hash-only text
  values
- deterministic fixture bridge to the existing Cognitive IR v1
  `ActionProposal`
- source-observation-sequence validity, safe identifier/hash evidence, and
  canonical binding/proposal/bridge hashes
- Cognitive IR schema drift, deterministic replay, stale, tamper,
  unsupported capability, secret, untrusted-content, and locator-injection
  tests

Cognitive IR v1, `ActionCandidateProvider`, Module Contract v1, Module SDK,
Application Semantics v1, package data, Runtime ABI, policy, activation,
approval, and action execution remain unchanged.

## Cognitive Action Selection Pipeline v1 Status

Implemented in `crates/d2i-action-selection`:

- strict actual Element Grounder v1 result mirror and duplicate-key parser
- unique grounding validation against Application Pack and Observation
- fixture-oracle-independent `GroundedTargetBindingV1`
- additive sealed `ActionSelectionContextV1` for an unbound
  `SelectCapability` node
- sealed Plan Ranker ranking and trusted pre-admission profiles
- deterministic one-to-64 capability-bound proposal generation
- canonical candidate set and structured capability-only exclusions
- exact metadata-only Plan Ranker v1 input payload and proposal index
- complete external Plan Ranker output validation with no omitted candidates
- exact rank-1 proposal rebinding and stale/substitution rejection
- non-authoritative `PolicyReadyActionV1`
- strict Draft 2020-12 schema and canonical lowercase SHA-256 contracts
- actual Element Grounder and Plan Ranker schema/fixture compatibility tests

The pipeline performs no module invocation, module loading, policy evaluation,
confirmation request, activation, desktop mapping, adapter preparation or
commit, UI action, re-observation, verification, recovery, process,
filesystem, or network side effect.

## Cognitive Policy Admission v1 Status

Implemented in `crates/d2i-policy-admission`:

- exact delegated authority and trusted policy evaluation
- closed allow, confirmation, deny, and escalation outcomes
- bounded one-time confirmation challenge and grant contracts
- activation eligibility bound to integration, runtime, ledger, capability,
  and source observation
- non-executable `CognitiveActivationAdmissionV1`

The policy crate has no adapter, filesystem, process, network, UI, or token
authority.

## Trusted Action Execution Binding v1 Status

Implemented in `crates/d2i-trusted-action-execution` and
`products/d2i-desktop/src/trusted_execution.rs`:

- strict Core session, request, target proof, input proof, bound action,
  prepared binding, and terminal receipt contracts
- exact six-operation UIA/WebDriver mapping with no fallback
- complete PolicyReady, Cognitive admission, eligibility, source observation,
  platform activation, ledger, adapter, target, input, and time intersection
- non-cloneable and non-serializable raw target and payload ownership
- fresh read-only target resolution and prepare-time precondition equality
- additive Cognitive permit digest checked by the existing adapter boundary
- one-shot Windows activation consumption and one adapter commit
- protected binding, target, preparation, permit, commit, terminal, cancel,
  and abort audit events
- deterministic projection to existing `BoundActionExecutionV2` without a
  verification verdict
- actual signed Windows UIA SetValue fixture with side-effect-free
  bind/prepare and zero residual owned worker or execution material

Adapter success means only that an action attempt succeeded. KRN-200 performs
no re-observation, postcondition verification, verified closure, recovery, or
production CognitiveExecutor connection.

## Reobserve and Cognitive Verifier v2 Status

Implemented in `products/d2i-desktop/src/cognitive_reobserve_verify.rs`:

- strict Cognitive IR v1 to existing Verification v2 adaptation
- closed element target grammar and sealed expected-value comparison
- receipt-bound re-observation requests and fresh UIA/WebDriver proof
- separately activated read-only observation worker with explicit shutdown
- expected, allowed, protected, unexpected, security, and volatile delta sets
- deterministic five-verdict postcondition verification
- immutable `VerifiedActionResultV1`, protected audit, and receipt replay guard
- actual WinForms SetValue, fresh UIA re-observation, protected-field check,
  unsafe negative snapshot, and zero residual owned workers

Adapter success and state-hash inequality never imply a passed verdict. The
result is not Case closure and carries no retry, replan, or escalation authority.

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
- No KRN-500 complete Goal-to-WorkReport integration.
- No production CognitiveExecutor-to-KRN-200 connection.
- No external network feature.
- No production package format or Runtime ABI change.
- No concrete WFP, Windows adapter, activation ledger, or protected audit
  storage changes in the Cognitive Core work.
- No production module loader, package embedding, native ABI, Mojo loader, or
  CognitiveExecutor production-flow connection.

## Next Task

`D2I-KRN-500 - First Complete Verified Single-Task E2E`

KRN-400 is complete with deterministic failure classification, atomic recovery
budgets, bounded replay-safe history, a fresh-cycle decision matrix, typed
replan/clarification/escalation artifacts, a protected durable Desktop ledger,
restart-safe coordination, and actual failed-first/recovered-second plus
unsafe-to-escalation Windows UIA fixtures.

The opened E2E gate is: a failed or inconclusive action can be safely
re-observed, retried through a wholly fresh trust chain, replanned, clarified,
escalated, or stopped without blind replay.

Do not start production module loading, Runtime ABI changes, package embedding,
an external planner, or escalation-recipient routing as part of KRN-500.
