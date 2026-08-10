# D2I Progress Snapshot

Date: 2026-08-09

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
  domain-neutral Case fixtures, optional Safety compatibility fixtures, and
  the official WORK-200 runner

At the WORK-200 boundary, task failure, clarification, blocked state,
suspended Role, and WorkReport-only evidence remain non-terminal. That phase
implemented no Radar, source connector, Queue, Scheduler, lease,
reassignment, or ownership transfer.

## Work Radar and Work Intake v1 Status

Implemented in `crates/d2i-work-intake` and
`products/d2i-desktop/src/work_intake.rs`:

- exact Role/delegation/instance-bound Radar source registration
- signed `WorkSourceApprovalV1` binding organization, Role, delegation,
  registration hash, signer, and bounded lifetime before scan
- bounded typed hash-only Work Signals and one-shot fixture source adapter
- exact deterministic Intake mappings with no model or fuzzy matching
- monotonic source sequence/cursor checkpoints and bounded gap policy
- direct reuse of WORK-200 normalization, duplicate classification, admission,
  protected Case ledger, and `WorkCaseCoordinatorV1`
- closed Intake dispositions, hash-only receipts, and cycle reports
- protected single-writer Intake ledger with DACL/hash-chain/strict-JSON
  verification, atomic replace, replay/tamper rejection, and poisoned writes
- receipt-before-checkpoint crash recovery and exactly-one persistent Case
- General Office `office.record.update` source-to-Case product E2E with no API
  or Task
- deterministic Office, HR, IT, Safety, and schedule compatibility fixtures
  using opaque Role-owned IDs
- strict Draft 2020-12 schemas, inspection CLI, fixture feeds, and official
  WORK-300 runner

The source is at least once; Case creation is exactly once through WORK-200
deduplication. At the WORK-300 boundary, production connectors, background
polling, Queue, Scheduler, lease, reassignment, ownership transfer, and Case
Task execution were intentionally absent.

## Work Queue, Scheduler, and Case Ownership v1 Status

Implemented in `crates/d2i-work-queue` and
`products/d2i-desktop/src/work_queue.rs`:

- strict Queue policy and signed exact ownership pool
- immutable origin ownership with an additive current-owner overlay
- deterministic Case-to-Queue projection and one-shot trusted-time Scheduler
- fixed lexicographic deadline, escalation, integer-aging, sequence, and hash
  ordering
- exclusive hash-chained claim leases with bounded renewal and expiry
- audited signed-pool ownership transfer without Case Contract mutation
- non-executable one-time `CaseWorkGrantV1` for the future planner boundary
- current-user DACL-protected single-writer Queue/ownership ledger with strict
  JSON, atomic replacement, tamper detection, restart replay, and receipts
- actual WORK-300 four-Case General Office E2E through enqueue, selection,
  lease recovery, owner suspension, standby reassignment, and grant
- Office, HR, IT, and Safety opaque-ID compatibility with no Core taxonomy
- strict Draft 2020-12 schemas, inspection CLI, crash windows A-E, and 128
  distinct Cases replayed identically 100 times

WORK-400 starts no background service and creates no Goal, Plan, Task, policy
decision, activation, adapter call, credential, process, network request, Case
closure, SLA delivery, or recipient routing.

## Situation Intelligence and Adaptive Planner v1 Status

Implemented in `crates/d2i-situation-model`,
`crates/d2i-intelligence-provider`, `crates/d2i-adaptive-planner`, and
`products/d2i-desktop`:

- bounded approved Case context with exact Case, Role, ownership, lease, Work
  Grant, observation, policy, procedure, trust, redaction, and evidence hashes
- provenance-separated Situation Models with explicit unknowns and conflicts
- model-neutral goal, situation, and next-step provider contracts
- strict duplicate-key/unknown-field rejection and 15 Draft 2020-12 schemas
- trusted GoalSpec conversion only after complete bounded GoalDraft validation
- one-step adaptive plans bound to exact capabilities, semantic targets,
  approved values, preconditions, postconditions, Case, lease, and generation
- protected append-only planner cycle ledger and crash windows A through F
- pinned Qwen3-4B Q4_K_M through pinned llama.cpp in a zero-capability
  AppContainer and bounded Windows Job Object
- one-shot inference, exact artifact/prompt/schema/decoding binding, 45-second
  timeout, zero retries, network denial, and owned process-tree cleanup
- 60-case holdout with 60/60 typed success, all measured quality metrics at
  100%, and all critical safety error counters at zero
- actual General Office Windows KRN paths: SetValue then Save when incorrect,
  and Save without SetValue when already correct
- three actual action cycles, five fresh observations, verified Case closure,
  path divergence, and zero residual process, credential, activation, or
  AppContainer profile state

The accepted evaluation report hash is
`sha256:18d9b2408cecae12b95902c41f43efc1c456819a8283dea898095336f0b2d2e6`.
The accepted model E2E report hash is
`sha256:1797a918581ac8e437f70009455a0290502d05f7f91be536a259e6bfb0b7370d`.
The accepted Completion evidence hash is
`sha256:6a842b90ada7cf9af6ff65d19f5d90d6a57c7ead1ce92c4270f9987c7dd48216`;
all eleven recorded steps exited zero and all terminal residual counters were
zero.
The official Completion runner regenerates these evidence classes and does not
trust these historical values as an execution shortcut.

## Verification

Passed:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

## Boundaries Preserved

- No remote, online-learning, or unrestricted general-purpose model provider.
- No GUI implementation.
- No production CognitiveExecutor-to-KRN-200 connection.
- No external network feature.
- No production package format or Runtime ABI change.
- No WFP policy, activation authority, or production adapter capability
  expansion; the Windows host change is limited to bounded local-model process
  isolation and the KRN test fixture change rejects stray shared-desktop input.
- No production module loader, package embedding, native ABI, Mojo loader, or
  CognitiveExecutor production-flow connection.

## Next Task

`D2I-OFFICE-200 - HWP/HWPX and Word Document Work`

KRN-500 is complete with actual module process invocation, two real UIA action
cycles, per-action policy and activation, independent verification, bounded
recovery, unsafe escalation, clarification without mutation, final verified
closure, deterministic normalized replay, and zero residual execution state.

Track K and WORK-100 through WORK-500 are complete. Do not add a KRN-600 task. WORK-100 now
proves deterministic Role compilation, exact signatures, persistent protected
lifecycle, one-time task admission, existing authority/recovery projections,
and the actual role-bound KRN-500 two-action Windows path. WORK-200 now proves
immutable admitted Work Items, persistent accountable Cases, verified attempt
retention, exact evidence evaluation, and fail-closed terminal disposition.
WORK-300 now proves signed approved-source discovery, exact Intake mapping,
General Office Case creation, cross-domain replay, receipt/checkpoint
durability, 100 identical normalized replays at the 128-event cycle limit,
crash repair, and zero duplicate Cases. WORK-400 now proves protected Queue
reconciliation, deterministic selection, exclusive lease recovery, signed-pool
ownership reassignment, non-executable grants, crash repair, and 128-Case
deterministic replay. WORK-500 now proves actual bounded local-model goal and
situation interpretation, validated one-step adaptive planning, fresh
replanning, existing KRN execution, adaptive path divergence, and verified
closure. WORK-600 now seals terminal Cases exactly once as reference-only
Episodes, enforces Role memory policy, stores them in a protected Desktop
ledger/index, attaches only signed historical summaries, prefers fresh state
in an actual model-backed Path C, and quarantines offline learning candidates
without production mutation. The General Office `1.0.0` and memory-enabled
`1.1.0` Role bundles are independently compiled and verified; `1.1.0` memory
evidence binds its exact contract, signed approval, signed delegation, and
active Role Instance rather than fixture hashes. WORK-700, WORK-800, and
WORK-900 and EDGE-100 are complete. Track W is complete, and EDGE-200 is the
first active task.

WORK-700 now has a platform-neutral Role Operations crate, 30 strict schemas,
General Office 1.2.0 fixture, protected Desktop store, inspection CLI, and an
official runner. Its actual WORK-600-bound five-Case Completion E2E reports
three SLA-compliant and two breached Cases, one approved 100-second pause, one
human handoff, one explicit refusal, four evidence-covered KPI results, four
internal reports/publications/receipts, two exactly-once escalations, and zero
duplicate breaches or escalations. Signed routing-registry approval, exact
internal destination binding, signed publication receipts, and durable inbox
receipt binding were also verified fail-closed. The Completion report hash is
`sha256:1ef005ed42946686f00943e08ec948df0badbd83c1af891ecb0baeb416f25185`;
the snapshot and 128 Case x 100 replay hashes are
`sha256:d30e3c05eac1706c1ed024d7a0cb73c0c9b7efb802eee27075b5d2dd75ad0024`
and
`sha256:1f8add213c3642bb417eb68cd996dd1c7e98a7c5123d1c78cf1a997f0726fd1d`.
Protected store/audit terminal hashes were verified and process, credential,
activation, profile, store, and lock residuals were all zero. The official
All and Completion runners, fmt, Clippy, full workspace tests, and release
build passed.

WORK-800 now provides the platform-neutral Shadow contract, 31 strict schemas,
the General Office Shadow Role 1.3.0, a current-user/SYSTEM protected Desktop
store and audit, commitment-before-reference blinding, independent comparison
and adjudication, WORK-600 quarantine-only divergence ingress, WORK-700
internal-only publication, and deterministic 128 Session x 100 replay. The
actual pinned Qwen3-4B holdout completed 60 Cases and 80 provider invocations
with 30 natural-language paraphrases and no invalid output, execution attempt,
adapter invocation, or network access. Five Windows sessions include one real
interactive reference session; mandatory escalation misses, false completion,
authority expansion, forbidden capabilities, secret leakage, and critical
errors are all zero. Readiness is `eligible_for_work900_design` and grants no
execution authority.

Completion now uses canonical resumable checkpoints. A sealed provider
validity binding keeps the model/runtime/prompt/provider descriptor exact for
the bounded 24-hour holdout window. Case artifacts are written atomically,
cleanup precedes success checkpointing, dependency invalidation is transitive,
and secret-scanned diagnostics survive child cleanup. The final repeated
Completion reused 72 of 72 checkpoints with zero fresh steps, no model or
interactive replay. The run-specific checkpoint-set, source-tree, and
`finished.json` hashes are recorded in the canonical `finished.json`; the
stable holdout report hash is
`sha256:d853918b5d5e9ae15ad1ed9797793192a0a1cdf1ec38d7bb49fd66665917addc`,
Completion report hash
`sha256:7af3939883090cf7b4122c4459d7d6b97d7e92c3ee3af9ccd0d4a0526931e71d`,
and readiness hash
`sha256:a6dfa9bfb8e2f8e160a943a62e99a2e33a032eb966aed733e0814f1e4c022f93`.
The independent 16-step `All` run also completed with zero failures.
Process, credential, activation, profile, protected-store, and lock residuals
are all zero.

WORK-900 now provides the platform-neutral `d2i-limited-autonomy` contracts,
18 strict schemas, General Office Role 1.4.0, signed readiness/deployment and
control chains, deterministic per-Case eligibility/admission, exactly-once
human exception handoff/response, finite health interlocks, crash directives,
and a protected Desktop autonomy store. Readiness and admission are not
execution authority; every side effect still uses current Role, delegation,
ownership, lease, Work Grant, Policy, one-shot activation, KRN, fresh
re-observation, and independent verification.

The actual pinned Qwen3-4B/llama.cpp Completion ran one bounded eight-Case
General Office duty cycle through actual WORK-300 Radar/Intake, WORK-400 Queue,
eight provider invocations, and eight Windows KRN scenarios. Five routine
Cases reached verified closure with zero routine human touches. Three typed
exception Cases produced exactly-once handoffs; clarification consumed one
bounded human fact and resumed from a fresh plan, and terminal escalations did
not continue autonomously. Eleven actual side effects and 27 observations were
verified with one bounded recovery. False completion, wrong target/action,
duplicate claim/action, authority expansion, forbidden capability, escalation
miss, secret leakage, network access, and critical errors were all zero.

The Completion also proves signed pause/resume after SetValue without blind
Save replay, deterministic 128 Case x 100 replay, protected store/audit
verification, strict sensitive-artifact scanning, step-specific safe
checkpoint reuse, per-model-invocation Job Object performance telemetry, and
zero process, profile, activation, credential, store, or lock residuals.
WORK-900 and Track W are complete. Track X started with EDGE-100, which is now
complete.

The final WORK-900 Role, readiness, Profile, deployment, Completion, replay,
certification, performance, and `finished.json` hashes are respectively
`sha256:15adbd0ed07e2a38481f895fafa9736a03b672a6f5d53094dbd59ec5f2e9a078`,
`sha256:e628ed6a8deb509c63feb60a5859baaee1fd9bc7158698bebbc4125c6722204d`,
`sha256:3173abcee938c0e973189af73cdef354f89de6cbe835a623b55a9041df9c4326`,
`sha256:d22114d5d0baa1b1c24d6739e92f0df760c9194584b61d383343b08b402f5fff`,
`sha256:12bf10a8830e820a3c885d78c0f788dc3e903f5eefa5e6faa2df93499818d871`,
`sha256:46d3945fc470b8d30fa3c41ea587f5b6e8aaab1cfac05da245526ca01fd2b03d`,
`sha256:6b94dd94aa59f4b138097388ddc48247b995d9a911cc154336587f8079c05c29`,
`sha256:af3a95f9933651c920d779d05d49d5ddd9cd75b04de7cec46688958e525b9cc2`,
and
`sha256:a8d66d9cb9b8a3723484807c81d8e988e706868499b7d7b197e552258e4e577d`.
Eight actual provider calls took 178,045 ms in aggregate; measured peak model
process/job memory was 2,614,284,288/2,615,558,144 bytes and model input plus
output movement was 25,302 bytes. These are evidence-run measurements, not a
general performance claim.

## EDGE-100 Enterprise API Execution Plane

EDGE-100 adds the platform-neutral `d2i-enterprise-api-plane` crate, 18 strict
Draft 2020-12 schemas, an inspection-only CLI, a signed General Office 1.5.0
Role fixture, a Desktop credential-isolated connector worker, a separate
reference server process, a protected content-addressed connector store, and a
resumable official runner. `AdapterKindV1::EnterpriseApi` is additive to the
existing Policy admission boundary; existing UIA/Web trusted execution rejects
that adapter so authority cannot cross planes accidentally.

The actual eight-Case duty cycle uses sealed WORK-900 evidence, the pinned
Qwen3-4B and llama.cpp hashes, actual IPv4 loopback sockets, seven model
invocations, 13 reads, seven writes, one stale replan, one bounded rate-limit
retry, and one commit-then-drop fresh-state resolution. It produced five
verified closures and three human exceptions. Four writes were independently
verified, including the unknown-outcome resolution. Blind replay, duplicate
server mutation, wrong endpoint/operation/resource, forbidden operation,
credential leakage, proxy use, redirect, external network, false completion,
escalation miss, critical error, and owned residual state were zero.

Signed Work Source approval and exact Intake mapping were separately exercised
for eight observations, eight Work Items, and eight persistent Cases, with the
existing Queue regression retained. Cross-domain deterministic fixtures prove
that general enterprise, ERP, MES, and CMMS metadata does not change Core
behavior. The protected store terminal and completion/certification hashes are
verified by the official runner, including safe checkpoint resume after a
harness-path correction.

The certified implementation is a JSON API v1 reference loopback system, not a
vendor connector or production customer certification. Production non-loopback
deployment still requires an approved vendor/customer Connector Pack,
credential broker integration, production HTTPS transport, and an exact
destination policy bound to the connector worker executable. No direct
database path, external communication, background service, or EDGE-200 sensor
work was added.

## OFFICE-100 General Office Capability and Artifact Workspace

OFFICE-100 starts Track O ahead of the remaining physical execution planes.
The platform-neutral `d2i-office-capability` crate defines strict source,
catalog, capability-candidate, signed workspace, artifact, observation,
operation, provenance, replay, completion, and certification contracts. Fifteen
official/community sources are exact-revision locked: Excel, PowerPoint, and
HWP/HWPX each include an official authority and multiple public MCP design
references. Public MCPs remain reference-only or rejected for runtime; none is
downloaded or executed by production.

The Desktop implementation binds a current-user/SYSTEM hardened local root,
signed profile, exact source hash/generation, Policy admission, one-shot
activation, and a hidden executable-hash-bound file worker. Cognitive
artifacts contain relative tokens and artifact IDs, never raw absolute paths.
The actual synthetic A-J E2E verifies discovery, working copy, Korean rename,
generation 1-to-2 commit, move to output, stale recovery, traversal and
junction rejection, immutable-original denial, Office lock denial, and replay
denial. It also verifies content-addressed protected persistence, crash windows
A-H, 128 scenarios x 100 deterministic replay, fresh post-operation evidence,
signed certification, and zero temporary process/profile/lock/store residue.

OFFICE-100 does not edit HWP, Excel, or PowerPoint content and adds no browser
download, network share, email, messenger, production Python, or public MCP
execution.

## OFFICE-200 HWPX and Word Document Work

OFFICE-200 adds the platform-neutral `d2i-document-capability` crate, 19 strict
Draft 2020-12 schemas, application-neutral semantic operations, signed backend
approval, exact operation binding, semantic receipts/diffs/verifications,
quality and cross-format reports, replay, Completion, certification, and an
inspection-only CLI. Existing Policy admission gains the additive
`OfficeDocument` adapter class; existing UIA/Web execution continues to reject
it so document authority cannot cross planes.

Desktop supplies separate bounded HWPX and DOCX ZIP/XML backends, a strict
one-operation file worker, and a hidden current-user Word COM worker. Package
tests reject traversal, duplicate/shadow entries, decompression excess,
missing parts, malformed XML, XXE/entity declarations, escaping or external
relationships, macros, OLE/ActiveX, and oversized content. Originals remain
immutable; every mutation creates a new generation and is independently
freshly reopened before protected Office registry persistence.

The actual General Office report sequence uses 16 globally unique one-shot
activations: eight HWPX mutations, five DOCX mutations, and three installed
Word COM mutations. It records 32 fresh reopens, exact HWPX/DOCX semantic
equivalence, 128 scenarios x 100 deterministic replay, protected audit, and
signed terminal certification. Twelve actual pinned Qwen3-4B/llama.cpp calls
include ten bounded plans, one goal draft, one clarification, and two replans.
Word is hidden, macro-disabled, exact-binary-bound, and WFP loopback-only; the
temporary WFP objects and verifier AppContainer profile are removed afterward.

Hancom Office installation was inventoried, but no commercial Automation
license evidence exists. HWPX is first-class without Hancom; legacy HWP status
is exactly `requires_licensed_hancom_backend`. OFFICE-200 adds no public MCP,
production Python/Node, browser, email, clipboard, macro, password bypass,
background Office service, Excel, PowerPoint, or full PDF path. OFFICE-200 is
complete. OFFICE-300 follows below and is also complete.

## OFFICE-300 Excel / Spreadsheet Work (Complete)

The implementation now includes the platform-neutral
`d2i-spreadsheet-capability` crate, 15 strict Draft 2020-12 schemas, a private
typed workbook index, closed lookup/filter/aggregate queries, evidence-bound
typed facts, deterministic context slicing, Situation projection, signed
backend approvals, exact operation bindings, receipts/diffs/verifications,
replay, Completion, certification, and an inspection-only CLI.

Desktop adds bounded XLSX ZIP/XML parsing, deterministic file mutation, hidden
hash-pinned workers, a dedicated spreadsheet KRN dispatcher, and a fixed Excel
COM worker. Package admission rejects traversal, duplicate/shadow entries,
ZIP64/encryption/expansion excess, malformed active XML, external links,
connections, query tables, macros, scripts, OLE, ActiveX, and executable
content. Raw formulas and generic COM are absent from the contract.

The large-context test scans 20,000 rows x 8 columns (160,000 cells), emits 128
bounded query facts, and selects only eight facts. An actual pinned Qwen3-4B
call used a 5,455-byte context slice and 7,949-byte Situation request with zero
raw workbook dumps. Installed Excel 16.0.20228.20158 at the pinned executable
hash successfully recalculated and freshly reopened a typed difference
formula. The exact new Excel PID required recorded exact-image termination
after graceful COM Quit and left zero residual Excel processes.

The official non-elevated `All` runner, runner ownership self-test, workspace
fmt, Clippy with warnings denied, full workspace tests, and release workspace
build pass. Elevated product Completion passed with exact temporary WFP
isolation, one XLSX file mutation, one installed Excel COM mutation, three
fresh reopens, ten crash windows, deterministic replay, protected audit,
signed certification, and every safety and residual counter at zero.

The certified run kept the 160,000-cell workbook private and sent eight typed
facts in 5,455 bytes to one pinned Qwen invocation. Exact report,
certification, replay, and audit hashes remain in the sealed Completion
artifacts so the tracked source tree does not self-reference its own evidence.
OFFICE-300 is complete.

## OFFICE-400 PowerPoint Presentation Work (Complete)

The implementation adds the platform-neutral `d2i-presentation-capability`
crate, 27 strict Draft 2020-12 schemas, semantic presentation snapshots,
closed template queries, bounded context slices, OFFICE-300 typed-fact
bindings, briefs, five-slide plans, signed backend approvals, exact operation
bindings, one-shot activation, receipts, semantic diffs, structural
verification, provenance, replay, Completion, certification, and an
inspection-only verifier CLI.

Desktop adds bounded PPTX ZIP/XML inspection and mutation, a dedicated
presentation KRN dispatcher, separate pinned file and PowerPoint workers, and
a private-desktop PowerPoint COM host. The package reader rejects traversal,
duplicate/shadow entries, encryption, ZIP64/expansion excess, DTD/entities,
external relationships, macros, scripts, OLE, ActiveX, and executable content.
It admits only internal `.xlsx` chart data after recursively applying the same
package, relationship, active-content, and resource checks.

The representative General Office E2E scans a 20,000-row by eight-column
synthetic workbook, deterministically derives the authoritative participant
facts 55, 120, and 18, and selects eight semantic slides from a 120-slide
template. Model context remains below 16 KiB and contains neither workbook nor
PPTX material. Four pinned Qwen calls produce semantic intent/plan evidence;
the runtime performs 13 PPTX mutations and four actual PowerPoint COM
mutations, including embedded image, table, and chart creation. The five-slide
result is saved to immutable generations, freshly reopened after every
mutation, and rendered to five 1280x720 PNGs.

PowerPoint runs with its required window on a non-interactive D2I private
Windows desktop, so no foreground window interrupts the user. Installed
PowerPoint 16.0.20228.20158 is exact-hash pinned, macro force-disabled, and
temporarily WFP-isolated together with chart Excel. Office may retain dedicated
`/automation -Embedding` Excel servers after COM Quit; the worker records this
and uses only bounded post-snapshot, exact-image termination. Baseline user
Office processes are never selected by name.

The official runner separates non-elevated deterministic gates from one
elevated Completion. Completion verifies sealed OFFICE-300 lineage, actual
Qwen, exact WFP state before and after live operations, 20 cases (12 routine,
8 exception), crash windows A-L, deterministic 128 x 100 replay, protected
audit, signed certification, structural quality, rendering, and zero residual
PowerPoint, Excel, worker, WFP, profile, lock, temporary package, activation,
or credential state.

OFFICE-400 and OFFICE-450 are complete.

## OFFICE-450 Organizational Design Intelligence (Complete)

The current implementation adds the platform-neutral
`d2i-design-intelligence` crate, 50 generated strict Draft 2020-12 schemas,
organization/artifact-class corpus and feature contracts, deterministic
Gold-weighted family and grammar compilation, content-minimized exemplar
retrieval, signed immutable pack approval, typography/layout solvers, hard and
soft critics, closed five-round refinement, visual-claim integrity, 128 x 100
replay, Completion, certification, and an inspection-only verifier CLI.

Desktop reuses the existing OFFICE-200/400 semantic snapshots to extract
normalized PPTX and HWPX/DOCX design features without raw XML or source prose.
The new official runner separates non-admin `All` from elevated product
`Completion`. `All`, schema drift, Design crate tests, Desktop extraction tests,
and OFFICE-100 through OFFICE-400 regressions pass. One actual pinned
Qwen3-4B/llama.cpp call passes with an 11.029-second measured runtime,
2,615,492,608-byte peak Job memory, and zero raw corpus, XML, coordinate,
color, font, font-size, or layout-execution authority.

The elevated Completion compiles two isolated organizations across 40 PPTX,
10 HWPX, and 10 DOCX artifacts into 480 normalized features, five families,
five rules, and 272 content-minimized exemplars. Its 34 training and 26 holdout
artifacts include 48 held-out PPTX units and 10 held-out HWPX documents. Exact
mapping, family top-1, and layout accuracy are each 1,000,000 ppm. The live
path creates two five-slide PPTX files, renders all ten slides through pinned
private-desktop PowerPoint, mutates and freshly reopens two HWPX documents,
passes cross-organization rejection, crash windows A-L, and 128 x 100 replay,
then removes every owned process, profile, WFP object, package, key, and lock.

The pre-roadmap-transition certification records completion report hash
`sha256:c395fff8932c9339883da49957fcaa1a2ce7f5f89262534f7608653c0afe44f9`,
certification hash
`sha256:79d51c037238a216543b5a2a303f303135d0f36303827fe7cd72cd43829f20e9`,
replay hash
`sha256:f6fe89586f519edfe6fc1dc1a3258d269776d5fde522fbb5e528a900a203ebff`,
and protected-audit terminal hash
`sha256:2c7b2181c52d0f2a553a06bcac08e27c7d8d1d2b3610e95e00638e27749c123c`.
The final post-roadmap source tree is sealed by a separate Completion run;
its terminal hashes are reported with the release commit rather than embedded
back into the hashed source tree.

## OFFICE-500 PDF Finalization and Document Interchange (Complete)

The current implementation adds the platform-neutral `d2i-pdf-interchange`
crate, 25 generated strict Draft 2020-12 schemas, three closed native Office
fixed-format exporters, a zero-capability AppContainer Windows.Data.Pdf
renderer, source/PDF immutable pairs, signed backend approvals, exact one-shot
bindings, finalization seals, interchange/submission manifests, protected
audit, crash windows A-M, and 128 x 100 deterministic replay.

The certified reference flow creates and exports two DOCX, two XLSX, and two
five-slide PPTX sources. Every PDF is freshly loaded and independently rendered
without a default viewer; the combined result exceeds 15 rendered pages and
includes at least five PPT source-to-PDF visual comparisons. Word, Excel, and
PowerPoint run on a private desktop with exact temporary WFP isolation. The
renderer runs under a one-process Job, 768 MiB memory bound, 120-second
deadline, write-confined sandbox, and exact temporary WFP policy. Existing
Office and viewer PID baselines are preserved and all owned process, WFP,
AppContainer, lock, activation, PDF, PNG, and sandbox state is removed.

One actual pinned Qwen3-4B/llama.cpp call is confined to semantic export-profile
selection. Its raw PDF, page image, extracted PDF fact, and execution-authority
counters remain zero. External PDF intake is render-only, PDF/A request and
exporter flag remain distinct from external conformance, and HWPX-to-PDF reports
`requires_licensed_hancom_render_backend`.

OFFICE-100 through OFFICE-500 are complete. `D2I-OFFICE-600 - Browser Research
and Controlled Download` is the first active task and is not implemented by
this change. The final source tree, completion report, replay, certification,
and protected audit hashes are retained in sealed terminal evidence and
reported with the release commit rather than embedded into the hashed tree.
