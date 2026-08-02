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

## First Complete Verified Single-Task E2E Status

Implemented in `products/d2i-desktop/src/cognitive_kernel_task.rs`, the
`d2i-kernel-e2e` runner, and repository-owned Windows fixtures:

- authenticated, TTL-bound task instruction and ordered stage hash chain
- actual out-of-process Goal Compiler, Element Grounder, and Plan Ranker
- immutable Application Pack and two-step validated PlanGraph
- actual UIA SetValue and Invoke through distinct policy/admission/activation
  chains
- independent per-action verification and terminal stability verification
- bounded failed-first recovery, unsafe escalation, and no-mutation
  clarification
- final `GoalProgress::Complete`, `WorkReport`, and immutable task run record
- deterministic normalized replay and zero process/worker/activation/payload
  residuals

The module hosts are test/evaluation transport only. Core links no standalone
module implementation.

## Work Item / Case Contract v1 Status

Implemented in `crates/d2i-work-case` and
`products/d2i-desktop/src/case_instance.rs`:

- strict hash-only `WorkItemSourceEnvelopeV1` and immutable `WorkItemV1`
- deterministic normalization, semantic hashing, deduplication, and conflict
  detection
- Work Item admission against exact Role, delegation, source, policy,
  calendar, pack, integration, capability, risk, and organization scope
- one-Work-Item/one-Case cardinality and generation-1 accountable ownership
- typed success, evidence, SLA, block, Task request, attempt, closure, refusal,
  escalation, and terminal contracts
- closed non-terminal lifecycle and only verified-complete, explicit-refusal,
  or escalated terminal outcomes
- ACL-protected append-only Case ledger, atomic replacement, restart replay,
  corruption detection, and one-time Task/attempt/KRN-run consumption
- full current Role Instance and ledger-head revalidation before Case Task
  admission
- actual role-bound Windows KRN-500 artifact binding and verified Case closure
- strict Draft 2020-12 schemas, deterministic replay report, CLI inspection,
  AI Safety reference Case fixtures, and official WORK-200 runner

Task failure, clarification, blocked state, suspended Role, and WorkReport-only
evidence remain non-terminal. Radar, source connectors, Queue, Scheduler,
lease, reassignment, and ownership transfer remain unimplemented.

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
- No production CognitiveExecutor-to-KRN-200 connection.
- No external network feature.
- No production package format or Runtime ABI change.
- No concrete WFP, Windows adapter, activation ledger, or protected audit
  storage changes in the Cognitive Core work.
- No production module loader, package embedding, native ABI, Mojo loader, or
  CognitiveExecutor production-flow connection.

## Next Task

`D2I-WORK-300 - Work Radar and Work Intake`

KRN-500 is complete with actual module process invocation, two real UIA action
cycles, per-action policy and activation, independent verification, bounded
recovery, unsafe escalation, clarification without mutation, final verified
closure, deterministic normalized replay, and zero residual execution state.

Track K, WORK-100, and WORK-200 are complete. Do not add a KRN-600 task. WORK-100 now
proves deterministic Role compilation, exact signatures, persistent protected
lifecycle, one-time task admission, existing authority/recovery projections,
and the actual role-bound KRN-500 two-action Windows path. WORK-200 now proves
immutable admitted Work Items, persistent accountable Cases, verified attempt
retention, exact evidence evaluation, and fail-closed terminal disposition.
WORK-300 is next; Work Radar, Queue, and Scheduler remain unimplemented.
