# D2I Compiler Architecture

## Current Scope

The product enclosing this compiler is an Open Autonomous Digital Workforce OS
for bounded general office and computer work. Domain vocabularies remain in
Domain Packs, Role Packs, examples, and tests; Core architecture uses opaque
versioned identifiers.

The current baseline implements typed IR, the deterministic package boundary, compile-time
executor selection, the Rust reference runtime, an implementation-neutral
existing-runtime adapter, a versioned native executor ABI, and one removable
experimental acceleration boundary. It adds controlled offline experience
compilation, a separate embodied product, and a policy-gated desktop autonomy
product without changing the production runtime.

## Product Boundary

D2IC converts a Domain Source Pack into a deterministic D2I Intelligence
Package. The compiler owns ingestion, validation, typed IR construction,
executor matching, evaluation, lowering, package verification, provenance, and
build reporting.

The reference runtime owns package loading, execution graph scheduling,
executor activation, policy gates, evidence collection, timing, and decision
envelope construction.

An existing proprietary runtime is treated as an external implementation behind
`RuntimeAdapter`. Its actual calls remain unresolved until documentation or
code is supplied; Phase 5 does not infer handles, symbols, or error values.

## Compile-Time Flow

```text
Domain Source Pack
  -> discover and fingerprint
  -> parse and normalize
  -> validate source contracts
  -> build typed Domain/Skill/Execution/Policy/Evaluation IR
  -> match and evaluate executor candidates
  -> lower and optimize execution graph
  -> write deterministic package
  -> verify package
```

Phase 1 implements:

```text
canonical source-pack root
  -> strict domain.yaml contract
  -> bounded deterministic file inventory
  -> SHA-256 file and aggregate fingerprints
  -> Markdown/text/CSV/JSON/JSONL/YAML parsing
  -> schema and cross-file reference validation
  -> aggregated diagnostics
```

`d2i-core` owns this behavior. `d2i-cli` only renders human or JSON output and
maps results to stable process exit codes. `sources.lock` is an explicit CLI
write and is excluded from its own inventory hash.

Phase 2 adds:

```text
validated canonical sources
  -> Domain / Skill / Execution / Policy / Evaluation IR
  -> provenance reference validation
  -> execution DAG and bounded-loop validation
  -> versioned FlatBuffers sections
  -> deterministic staged package
  -> hash and compatibility verification
```

`d2i-core` owns IR contracts and invariants. `d2i-schema` isolates generated
wire bindings. `d2i-compiler` owns lowering and package behavior. `d2i-cli`
does not contain compiler or verifier logic.

Phase 3 adds:

```text
verified package bytes
  -> target, graph, resource, and executor-binding checks
  -> immutable artifact and knowledge indexes
  -> request-schema validation
  -> bounded DAG scheduling
  -> selective offline executor activation
  -> policy gate and human-review fallback
  -> Decision Envelope and deterministic replay comparison
```

`d2i-runtime-api` owns implementation-neutral Rust contracts.
`d2i-runtime-ref` owns the correctness baseline, built-in modules, scheduler,
and runtime CLI. It does not replace the future proprietary high-efficiency
runtime.

Phase 4 adds:

```text
versioned executor descriptors + benchmark profiles
  -> hard capability/schema/ABI/target/resource/security/quality gates
  -> feasible candidate set and Pareto front
  -> target-weighted or explicit safe binding
  -> graph optimization with retained rationale
  -> immutable selection, optimization, and benchmark artifacts
```

`d2i-eval` owns model-independent executor descriptors, selection, optimization,
and runtime benchmark collection. `d2i-compiler` turns a failed quality gate
that leaves no safe executor into a build error. `d2i-runtime-ref` revalidates
descriptor ABI, target, network policy, and selected bindings before startup.

Phase 5 adds:

```text
verified package + declared adapter capabilities
  -> package/ABI/target/executor/resource compatibility report
  -> adapter package load
  -> identical evaluation and error vectors
  -> output-schema, decision, and error-category comparison
  -> automated reference/adapter latency summary
```

`d2i-runtime-adapter` owns the safe Rust `RuntimeAdapter` contract, mock
implementation, nonfunctional proprietary placeholder, compatibility checker,
ABI mapping metadata, and conformance runner. No native ABI or dynamic module
loading is introduced.

`d2i-cognitive-ir` owns only Cognitive IR v1 data types, pure validation,
canonical hashing, and schema compatibility. `d2i-desktop` imports and
re-exports those exact types while retaining executors and platform behavior.
Cognitive modules are independent one-package workspaces under `modules/`,
each with a local lockfile. The root workspace excludes them, and Core has no
dependency on a module implementation or registry.

`d2i-application-semantics` owns additive Application Pack v1 and synthetic
observation-fixture contracts. It binds an immutable application vocabulary to
an existing Cognitive IR v1 observation and emits a schema-pinned,
side-effect-free Element Grounder v1 JSON payload. It does not invoke or link
the standalone module, does not add executable selectors to semantic metadata,
and does not change Cognitive IR, the Module SDK, package data, or Runtime ABI.

`d2i-action-candidates` owns the additive Action Candidate Provider v1 fixture
contract. It binds one validated semantic target and grounding oracle to an
exact Registry capability, goal/world/plan lifecycle, and observation
sequence, then emits an existing Cognitive IR v1 `ActionProposal`. Typed
arguments contain only closed action variants, stable IDs, hashes, and
sequence metadata. The crate does not emit executable locators or
`DesktopOperation`, invoke a module, or cross policy, activation, approval, or
adapter boundaries.

`d2i-action-selection` owns the additive Cognitive Action Selection Pipeline
v1. It validates actual Element Grounder output, binds one uniquely observed
target without a fixture oracle, generates a canonical set of
capability-bound `ActionProposal` records, emits the exact metadata-only Plan
Ranker v1 input, validates externally returned ranking output, reconnects rank
1 to the immutable original proposal, and produces non-authoritative
`PolicyReadyActionV1` data. A sealed additive selection context supports
multiple capabilities at an unbound `SelectCapability` node without changing
Cognitive IR v1. Core does not link either standalone module or cross policy,
activation, approval, adapter, or execution boundaries.

`d2i-policy-admission` evaluates one exact policy-ready action against
delegated authority, a trusted policy snapshot, optional bounded confirmation,
and a read-only activation eligibility projection. Its terminal
`CognitiveActivationAdmissionV1` is data, not an adapter token.

`d2i-trusted-action-execution` owns the side-effect-free KRN-200 hashes,
identities, lifetimes, target/input proofs, bound action, prepared binding, and
terminal receipt. `d2i-desktop` owns the concrete target and payload material,
consumes one actual `WindowsActivationAdmission`, starts the certified UIA or
WebDriver worker, prepares without mutation, and commits exactly once. A
successful receipt proves only adapter success; re-observation and
postcondition verification remain a separate boundary. KRN-300 implements
that boundary in `d2i-desktop`: the mutation worker exits, a separately
activated UIA/WebDriver read-only worker collects a fresh observation, and a
deterministic protected-invariant verifier emits the existing
`VerificationResultV2` plus an additive `VerifiedActionResultV1`. Exact target
identity, expected and protected deltas, zero observation side effects, worker
cleanup, protected audit, and receipt replay consumption are mandatory. The
terminal result is not case closure or recovery authority.

`d2i-cognitive-recovery` owns the additive KRN-400 deterministic recovery
contract. It normalizes lifecycle failures, applies unsafe-first
classification, atomically consumes bounded budgets, records a replay-safe
hash-only history, and selects complete, continue, read-only re-observation,
wholly fresh trusted retry, equivalent alternate capability, bounded full
graph replan, typed clarification, hash-only escalation, or stop. It does not
change Cognitive IR v1 or own platform side effects. `d2i-desktop` owns the
current-user protected recovery ledger and fail-before-mutation coordinator.
Every mutating retry must create new proposal, policy, admission, activation,
execution, re-observation, and verification evidence; unsafe outcomes can only
escalate or stop.

KRN-500 closes the first complete single-task product path in `d2i-desktop`.
`CognitiveKernelTaskRuntimeV1` chains an authenticated instruction, actual
standalone Goal Compiler/Element Grounder/Plan Ranker process invocations,
actual UIA observation and one-shot actions, per-action policy and activation,
independent verification, bounded recovery, final stability verification,
`WorkReport`, and `KernelTaskRunRecordV1`. Module implementations remain
outside the root dependency graph and communicate through one bounded Module
Contract v1 JSON exchange using test/evaluation-only hosts. Task completion is
permitted only after final criteria and protected invariants pass. This closes
Track K but does not itself implement Role or Case autonomy.

WORK-100 adds the first Workforce boundary above KRN-500:

```text
strict Role source -> immutable RoleContractV1 -> signed approval
-> signed subset delegation -> persistent protected RoleInstanceV1
-> one-time RoleTaskAdmissionV1 -> existing authority/recovery projections
-> RoleBoundKernelTaskContextV1 -> KRN-500
```

`d2i-role-contract` remains platform-neutral. `d2i-desktop` owns protected Role
state, audit, restart recovery, and the role-bound Kernel gate. Role prose,
KPI/SLA declarations, reporting duties, and memory boundaries are not
authority. WORK-100 creates no Work Item, Case, Radar, Queue, Scheduler, Case
ownership, KPI result, SLA claim, or report delivery.

WORK-200 adds the durable work boundary above Role admission:

```text
strict hash-only source envelope -> immutable normalized WorkItemV1
-> deterministic deduplication -> Work Item admission
-> immutable CaseContractV1 + generation-1 accountable Role ownership
-> protected persistent CaseInstanceV1
-> zero or more exact role-bound KRN-500 Task attempts
-> typed evidence and requirement evaluation
-> verified complete, explicit refusal, or escalated terminal record
```

`d2i-work-case` owns platform-neutral normalization, admission, ownership,
requirements, evidence, lifecycle, closure, terminal, strict JSON, and
canonical hash contracts. `d2i-desktop` owns the protected Case ledger and
coordinator. A task failure, timeout, clarification, block, or `WorkReport`
alone never closes a Case. Work Item and Case artifacts grant no execution
authority; every mutation still crosses Role, policy, activation, adapter,
re-observation, and verification boundaries. WORK-200 implements no Radar,
connector, Queue, Scheduler, lease, reassignment, or ownership transfer.

WORK-300 adds authority-free work discovery above the existing admission
boundary:

```text
exact Role source registration -> signed WorkSourceApprovalV1 verification
-> bounded one-shot typed Work Signal
-> freshness and checkpoint verification -> exactly one deterministic mapping
-> existing source envelope / normalization / duplicate / admission
-> existing persistent Case creation -> protected Intake receipt -> checkpoint
```

`d2i-work-intake` owns platform-neutral registrations, source approvals,
signals, mappings, checkpoints, receipts, cycle reports, and the narrow
one-shot source trait. Source approval binds the exact organization, Role
Contract, Role Instance, delegation, registration hash, signer, and lifetime
before scanning. `d2i-desktop` owns the protected approval-bound single-writer
Intake ledger and restart recovery. Signals contain only immutable hashes and opaque references; they
cannot confer command, credential, policy, activation, adapter, filesystem, or
network authority. At-least-once source delivery relies on WORK-200
deduplication for exactly-one Case creation. WORK-300 implements no production
connector, background service, Queue, Scheduler, lease, claim, reassignment,
ownership transfer, or Case Task execution.

The canonical WORK-300 product E2E uses the General Office Operations Employee
and `office.record.update`. HR, IT, and Safety examples prove cross-domain
compatibility without adding those work classes to Core.

WORK-400 adds a platform-neutral coordination layer after persistent Case
creation:

```text
verified non-terminal Case ledger state -> deterministic Queue projection
-> trusted caller one-shot Scheduler tick -> exclusive hash-chained lease
-> non-executable CaseWorkGrantV1
-> release/expiry or signed-pool ownership reassignment
```

The Case ledger remains authoritative. `CaseOwnershipBindingV1` remains the
immutable generation-1 origin record; `CurrentCaseOwnershipStateV1` is an
additive protected overlay. The Desktop Queue ledger owns DACL-protected
single-writer persistence and replay. Scheduler code reads no clock, random
source, environment, process, or network, and no WORK-400 artifact can invoke
Goal, policy, activation, KRN, or an adapter.

Phase 6 adds:

```text
canonical native library path + expected SHA-256
  -> root, symlink, size, and hash verification
  -> fixed d2i_module_v1 symbol lookup
  -> ABI version, table size, identity, and function validation
  -> host-owned input/output buffer views
  -> init / run / reset / destroy lifecycle
  -> ABI copy and allocation metrics
```

`d2i-ffi` is the only handwritten crate allowed to use `unsafe`. It owns the
C-compatible layout, dynamic loader, opaque handle lifetime, and published
header. Rust owns all call buffers and destroys each initialized handle once.
Optional Arrow C Data and DLPack adapters expose borrowed opaque views only;
they do not transfer ownership.

Phase 7 adds:

```text
case-retriever match predicates
  -> three-bit match-mask batch
  -> Rust integer score kernel
  -> optional d2i_score_match_masks_v1 candidate
  -> exact output comparison
  -> same-host latency and copy report
  -> adopt only after reproducible >= 1.20x p50 gain
```

`d2i-kernel` owns the safe Rust baseline and benchmark. `d2i-ffi` owns the
optional C ABI import. `backends/mojo` is never part of a default Cargo build.
The active reference runtime remains Rust because the Phase 7 host has no Mojo
toolchain and therefore provides no candidate performance evidence.

Phase 8 adds:

```text
reviewed Decision Envelope outcomes
  -> strict learning episodes
  -> access-controlled append-only hash chain
  -> deterministic split, duplicate removal, quarantine, and shift checks
  -> separate candidate bundle with non-executable adaptation proposals
  -> existing gold-set baseline and candidate-overlay evaluation
  -> hard regression and critical-error gate
  -> human-approved, Ed25519-signed promotion ledger
```

`d2i-learning` owns this flow. A promotion has state
`approved_for_next_build`; it is not a deployment and never mutates a
production package. Candidate and production identities remain physically and
cryptographically separate.

External training/evaluation corpora first pass a separate offline dataset
registry. License scope, source provenance, review evidence, immutable
revisions, attribution/share-alike plans, local paths, sizes, and hashes must
be complete before artifact admission. Dataset admission performs no download,
normalization, training, candidate build, or production mutation.
Desktop-agent candidates additionally declare third-party, executable, and
credential/session risks. Their GUI, DOM, function, shell, and code actions
remain inert until a future deterministic transition normalizer is implemented
and reviewed.

Phase 9 adds:

```text
ROS 2 byte transport
  -> typed sensor event
  -> D2I cognition / high-level planning / episodic memory
  -> action intent
  -> external fail-closed safety-controller boundary
  -> permit-bound external hardware boundary
```

`products/d2i-embodied` owns these contracts, deterministic simulation replay,
robot-specific append-only memory, and signed staged fleet-promotion metadata.
It is a separate product and dependency leaf. The compiler, package format,
reference runtime, safety loop, and motor controller do not depend on it.

An integration becomes activatable only after two offline gates:

```text
reviewed IntegrationManifest
  -> readiness validation
  -> signed RuntimeBindingEvidence from a reviewed probe
  -> exact identity / type-hash / QoS / safety / hardware comparison
  -> opaque CertifiedIntegration
  -> append-only activation ledger replay/rollback admission
  -> one-shot ActivatedIntegration
  -> certified ROS topic map bound to a transport
```

The evidence signing key is pinned in the manifest, observations and activation
proofs expire within 15 minutes, and failed certification cannot mint the
activation proof. The ledger is pinned to the manifest hash and consumes unique
binding/evidence identities in strictly increasing observation order before
adapter construction. The repository supplies a bounded offline conformance
transport, not a concrete ROS 2 client or hardware implementation.

The post-Phase 9 desktop-autonomy foundation adds:

```text
successful DecisionEnvelope
  -> typed desktop action and trusted risk classification
  -> deny-by-default capability policy
  -> side-effect-free adapter preparation
  -> signed human approval for high-risk work
  -> short-lived execution permit
  -> durable pre-commit audit
  -> adapter commit with precondition recheck
  -> payload-free outcome audit
```

`products/d2i-desktop` is a separate dependency leaf. It supplies a
deterministic virtual conformance adapter, a concrete canonical-root read-only
local filesystem adapter, and four independently certified Windows workers for
UI Automation, loopback W3C WebDriver, file write, and managed processes. A
Windows adapter exists only after exact host/configuration/worker evidence is
signed by the deployment attestor, independently certified, and consumed once
by a manifest-pinned activation ledger. Process children run under a pinned
zero-capability AppContainer SID; WebDriver additionally requires independently
signed egress-policy evidence. The concrete Windows provider pins the browser
image and revalidates persistent WFP loopback-permit/non-loopback-block filters
before every action. Deployment admission can additionally launch the pinned
Edge/EdgeDriver pair against a local dual-address probe, requiring observable
loopback delivery and no observable non-loopback delivery before the protected
provider key signs fresh evidence. Local signing keys use purpose-bound
current-user DPAPI envelopes, and Windows audit/activation storage pins
protected DACL descriptors. It does not depend on learning or embodied
products. Clipboard and credential adapters remain unavailable.

## Runtime Flow

```text
D2I Intelligence Package
  -> verify before load
  -> initialize runtime context
  -> receive request or event
  -> activate only required expert modules
  -> execute graph with timeout and policy gates
  -> return Decision Envelope
```

Every decision envelope includes build ID, package hash, activated module IDs,
evidence, confidence, policy result, per-node timings, warnings, and a replay
key.

## Architecture Invariants

- Compile-time complexity, runtime simplicity.
- Offline-first and network-denied by default.
- Model-agnostic package and compiler contracts.
- Smallest adequate executor after hard quality and safety gates.
- Deterministic package content for identical inputs and settings.
- Explicit provenance for source-derived facts and decisions.
- Immutable production packages.
- Controlled learning through candidate packages and offline promotion only.

## Non-Goals for Phase 9

- No generated-model inference or external API.
- No package signature or encryption.
- No accepted Mojo production backend, MLIR dialect, GPU transfer, or device
  allocator.
- No in-place production mutation, live weight update, or automatic rollout.
- No execution of generated rules or arbitrary online code.
- No automatic deletion of safety or policy records.
- No invented proprietary runtime calls or handles.
- No process sandbox for untrusted native code.
- No package-embedded native executable or automatic dependency discovery.
- No performance superiority claim.
- No concrete ROS 2 client, DDS vendor, QoS default, or message package.
- No real-time safety-loop or emergency-controller implementation.
- No motor/actuator API, physical dispatch, fleet deployment, or automatic
  rollback execution.

## Situation Intelligence And Adaptive Planning

WORK-500 consumes the WORK-400 non-executable grant through a bounded approved
context bundle. Core Situation contracts preserve observed, trusted-system,
approved-policy, approved-procedure, authenticated-assertion, model-inference,
unknown, conflict, and untrusted-content classes separately. Provider output
cannot create authority or rewrite these classes.

The model-neutral provider boundary returns only typed goal interpretation,
situation interpretation, or semantic next-step candidates. The Desktop local
provider verifies exact llama.cpp and GGUF identities, launches one invocation
inside a zero-capability AppContainer already assigned to a bounded Job Object,
and admits only strict schema output. It has no direct adapter, credential,
filesystem mutation, arbitrary process, or network surface.

The Adaptive Planner intersects each candidate with exact Case, lease,
ownership, generation, capability, semantic target, value, precondition,
postcondition, risk, and evidence bounds. One admitted step then enters the
existing Action Selection, Policy, Activation, Trusted Execution,
re-observation, and Verification chain. Remaining plan text is never executed
after a state change. Fresh Situation Model generation drives replan,
clarification, escalation, or verified Case closure.

## Reference-Only Episodic Memory And Case Learning

WORK-600 consumes only verified terminal Case state. Role, Intake, Case,
Queue/Ownership, Planner, protected audit, Evidence Index, and terminal Case
ledgers remain authoritative. `d2i-episodic-memory` seals a bounded projection
of their exact IDs, sequence/head references, and hashes; it never copies raw
source payloads or grants execution, reopening, completion, or mutation
authority.

Role and signed namespace policy choose `forbidden`, `hash_reference_only`, or
`approved_summary_only` reuse. Exact typed filters produce deterministic
terminal-time/ID/hash ordering. Historical context is always
`historical_non_authoritative`; current observation, policy, authority, Case,
and evidence take precedence. `d2i-case-learning` emits only quarantined
offline candidates and cannot alter a model, prompt, Role, Policy, Application
Pack, routing decision, or production package.

`d2i-desktop` owns the current-user DACL-protected content-addressed store,
append-only hash chain, atomic deterministic index, one-writer coordination,
retention/tombstone persistence, rollback/tamper detection, and reference-only
crash repair. Recovery never replays a provider, action, activation, KRN run,
or adapter operation.

## Evidence-Grounded Role Operations

WORK-700 adds the platform-neutral `d2i-role-operations` projection above
authoritative Role, Case, Queue/Ownership, Planner/KRN, Episode, and protected
audit state. A signed Operations Profile may only narrow the immutable Role
Contract. Core consumes trusted caller time, preserves the absolute
`CaseSlaBindingV1` baseline, and derives pause-aware effective deadlines with
checked integer arithmetic.

Milestone events exact-bind received, acknowledged, begun, resolved, and
escalated states to their authoritative ledger classes. Pause intervals bind
approved event, block or clarification classes and finite evidence-backed
bounds. KPI IDs remain Role-owned while formulas are closed, generic,
integer-only operations. Missing or conflicting coverage suppresses values.

Role snapshots and reports contain hashes, typed IDs, counts, and coverage;
they are not execution or completion authority. Separately signed routing
registries map opaque Role routing classes only to protected internal inbox
IDs. Publication receipts do not claim external delivery. Operational
attention and mandatory human handoff remain distinct, and signed
acknowledgement/resolution records cannot approve execution or reopen a Case.

Desktop persists these artifacts in a current-user/SYSTEM DACL-protected,
content-addressed object store with an append-only hash chain, atomic derived
index, one writer, rollback/tamper rejection, and index-only crash repair.
WORK-700 is one-shot: no daemon, timer service, external connector, or Shadow
Mode comparison is introduced.

## Blinded Open Digital Employee Shadow Mode

WORK-800 adds the platform-neutral `d2i-shadow-mode` evaluation layer without
joining the execution path. Signed profile, readiness policy, cohort,
participation, assignment, enrollment, and read-only grant artifacts exact-bind
an approved Role, Case, provider/model/runtime/prompts, Application Pack,
observation scope, and finite resource limits. They cannot claim or mutate a
Case, issue execution authority, invoke KRN, or call a mutation adapter.

Each AI proposal and pure counterfactual policy assessment bind a shared fresh
pre-action observation and are committed to protected storage before the
reference action begins. The operator cannot see the proposal. Reveal requires
a durable signed semantic reference step and fresh post-action observation.
Comparison uses exact Case/cycle/policy/pre-state binding; independent
adjudication uses current policy, success criteria, observation, and verifier
evidence, treating neither lane as automatic ground truth.

Desktop supplies only exact-process, exact-session, allowlisted UIA reads and a
fixture-owned semantic event channel. Values are hashed immediately. Global
input hooks, screenshots/video, clipboard capture, raw UI payloads, locators,
credentials, and personal recipient data are outside the plane. Instrumented
fixtures are hidden and non-activating; Completion separately requires one
explicit interactive reference session.

The Shadow store is DACL protected, content addressed, append-only, and
rollback pinned. Its index is derived and recoverable without replaying model
or human activity. A sealed 60-Case Qwen3-4B holdout, five Windows sessions,
integer metrics, deterministic replay, and a signed readiness policy produce a
readiness assessment. `eligible_for_work900_design` is evidence only and is not
accepted as an activation, confirmation, policy, or execution token. Learning
divergence goes only to WORK-600 quarantine and reports only to the existing
WORK-700 protected internal route.

Completion is a dependency graph of atomic safe checkpoints, not a single
long-lived process. Checkpoints bind source provenance, step-specific
executable inputs, runner and normalized argument hashes, pinned artifacts,
produced evidence, logs, cleanup, and residual state. The holdout additionally
seals a 24-hour provider descriptor validity binding and each accepted Case.
Only terminal Shadow sessions are reusable; an ambiguous action window resumes
from fresh observation and never from the failed command. Final certification
revalidates the entire checkpoint set and semantic product gates.

## Evidence-Gated Limited Autonomy

WORK-900 adds the platform-neutral `d2i-limited-autonomy` governance layer and
a Desktop-owned protected coordinator. Shadow readiness is bound to a finite
Profile and separately signed deployment approval, but remains evidence rather
than execution authority. The live General Office Role is a new immutable
1.4.0 contract; the non-executing Shadow Role 1.3.0 is not promoted or reused.

Every Case receives deterministic eligibility, a non-executable autonomy
admission, and an exact Case Task binding. The coordinator revalidates Role,
delegation, Case, ownership, lease, Work Grant, readiness, deployment, health,
capability, semantic target, risk, policy, and observation freshness before
each side effect. Actual execution remains Policy -> one-shot activation ->
KRN -> fresh observation -> independent verification. Only one action is
issued before re-observation and replanning.

Signed monotonic control commands implement enable, pause, resume, drain,
disable, and revoke. Critical health evidence synchronously trips the
fail-closed interlock. Resume is human-signed, revalidates all current gates,
and always starts from fresh observation and planning. The runtime cannot
self-resume or clear a critical incident.

Typed human-exception handoffs are durable and exactly once. Bounded signed
responses are data rather than commands. Clarification and confirmation force
fresh planning; terminal escalation cannot reopen a Case. Follow-up work is a
new Work Item.

The Desktop autonomy store is DACL protected, content addressed, append-only,
rollback pinned, single-writer, and crash repairable. Common Workforce
checkpoints bind step-specific executable source sets, exact dependencies,
produced artifacts, cleanup, and residual state. Unknown in-flight side
effects are reobserved and verified, never blindly replayed.

The v1 duty cycle is one-shot, maximum eight Cases, and maximum concurrency
one. It is not a Windows service or external connector. Model process
telemetry is measured from the Windows Job Object; runner stage timing is
reported separately and does not masquerade aggregate KRN time as fabricated
per-component latency.

## Enterprise API Execution Plane

EDGE-100 extends the existing execution-plane boundary with a closed
`enterprise-api` adapter class. A signed `EnterpriseConnectorPackV1` maps
opaque operation IDs to exact capabilities, semantic resources, request and
response schemas, fixed HTTP methods and paths, concurrency, idempotency,
verification, network, and finite resource rules. ERP, MES, CMMS, and internal
API names remain fixture or pack metadata and never select Core behavior.

The plane retains the authority sequence `Policy -> one-shot activation -> KRN
-> trusted worker`. Connector Pack approval, endpoint binding, credential
reference, operation intent, and operation binding are evidence and narrowing
inputs, not execution permits. The model cannot call the worker or materialize
HTTP. The worker is executable-hash bound and receives a runtime secret only
through bounded stdin after trusted admission.

Read-only API observations normalize schema-approved fields before they enter
Situation or model context. Mutation receipts do not close a Case. Every
successful or unknown-outcome mutation is followed by a separate fresh read
and exact postcondition verification. Unknown outcomes never trigger blind
replay. Protected storage is content addressed, append-only, hash chained,
single-writer, bounded, and current-user hardened.

The reference network profile is exact IPv4 loopback with one ephemeral port,
deny redirects, deny ambient proxy, and no external connection. Production
contracts require HTTPS and a separately deployed exact-destination policy for
the connector executable. See ADR 0037 and
`docs/execution-planes/enterprise-api-v1.md`.

## General Office Capability and Artifact Workspace

Track O starts with a quarantine boundary between public capability knowledge
and execution. `CapabilitySourceRecordV1` pins source, revision, content hash,
license, dependencies, exposure, advisories, and assessment. MCP catalogs are
hash-only snapshots; `OfficeCapabilityCandidateV1` is always reference-only.
No source status grants runtime approval, and no model can call an MCP server.
Official application API/SDK documentation has higher authority than community
tools.

The workspace authority path is `semantic intent -> Policy -> one-shot
activation -> KRN dispatcher -> executable-hash-bound file worker -> fresh
filesystem verification`. The Cognitive plane sees artifact, workspace, and
folder IDs plus bounded filenames. Only the trusted runtime resolves a signed
local root binding. Network shares, removable media, symlinks, junctions,
reparse points, traversal, device paths, ADS, and raw command/script arguments
are rejected.

Originals are immutable by default. Editing begins from a working copy;
versions bind parent hash, source generation, receipt, Case, Role, and fresh
verification. File writes use a durable temporary sibling and atomic move.
External modification or lock-state change stops the operation and forces a
fresh observation. The protected registry is content addressed, hash chained,
single-writer, index-repairable, and rejects rollback or object mutation.

Future HWP, Excel, and PowerPoint packs own application-specific planning and
backend selection behind typed semantic operations. A worker is bound to one
application, approved document, bounded Case, exact process/file identity, and
exact semantic operation. Core contains no application-family branching. See
ADR 0038 and `docs/office/general-office-capability-workspace-v1.md`.

## Semantic Document Work

OFFICE-200 adds an application-neutral document plane without changing the
Safe Execution Kernel sequence. `DocumentSemanticSnapshotV1` lowers HWPX and
DOCX package structure into bounded stable nodes. A capability pack, backend
descriptor, signed backend approval, operation intent, and exact binding
narrow one Policy admission and one activation to one mutation. Neither a
backend approval nor a document observation is execution authority.

HWPX and DOCX remain separate bounded ZIP/XML adapters. They reject traversal,
decompression excess, malformed or active XML, external relationships, macros,
OLE/ActiveX, and remote content before semantic observation. Each mutation
creates a new generation. The child and parent independently reopen the saved
package before a verified receipt and protected Office registry version exist.

Live Word is a hidden current-user COM child with a fixed CLSID and closed
operation lowering. It is exact-binary/session bound, macro-disabled, and WFP
loopback-only during Completion. It is not available from a service or through
a generic COM API. Legacy HWP requires separate Hancom Automation license
evidence and approval; absent that evidence it remains a typed human exception.
See ADR 0039 and `docs/office/document-work-v1.md`.

## Spreadsheet Query and Work

OFFICE-300 keeps workbook values in a private typed semantic index. A closed
`Lookup | Filter | Aggregate` query algebra produces evidence-bound typed
facts, and a deterministic context slicer enforces fact, canonical-byte, and
estimated-token limits before projecting `VerifiedObservation` Situation
facts. XLSX bytes, worksheet XML, whole cell ranges, raw formulas, and COM
state never enter model context.

Mutation retains the Kernel sequence: semantic intent, `OfficeSpreadsheet`
Policy admission, exact Role/Case/lease/Work Grant/workspace/backend binding,
one-shot activation, pinned worker, new generation, independent fresh reopen,
semantic diff, verification, and protected audit. The Rust XLSX worker handles
bounded value and row changes. Typed formulas are lowered only inside a hidden
interactive Excel COM worker whose binary is hash-pinned, macro-disabled, and
WFP loopback-only during Completion. See ADR 0040 and
`docs/office/spreadsheet-work-v1.md`.

The OFFICE-300 Completion gate is certified: actual pinned Qwen receives only
the deterministic typed-fact slice, installed Excel performs typed formula
calculation under exact temporary WFP isolation, and independent fresh reopen,
protected audit, replay, signed certification, and zero-residual cleanup pass.

## Presentation Context and Work

OFFICE-400 compiles a large presentation into a bounded semantic context
rather than sending PPTX/XML to a model. A closed template query scans the
semantic snapshot, selects at most eight slides, and joins at most sixteen
OFFICE-300 typed facts. The model returns only a brief and five-slide semantic
plan. Summary, table, and chart all retain the same fact IDs and workbook query
lineage.

The `pptx_file` worker owns bounded package mutation. The `powerpoint_com`
worker owns fixed live text, embedded image, table, chart, save-copy, and PNG
rendering. PowerPoint runs with its required window on a private Windows
desktop, never the interactive input desktop. Macro security is force-disabled
before open; PowerPoint and chart Excel are exact-image/WFP bound; only
post-snapshot owned PIDs may be cleaned up. Embedded chart `.xlsx` content is
recursively admitted and external links, macros, OLE, ActiveX, connections,
scripts, and executable content remain forbidden. See ADR 0041 and
`docs/office/presentation-work-v1.md`.

The OFFICE-400 Completion gate uses a 120-slide template, a 160,000-cell
OFFICE-300-compatible query, four actual Qwen calls, 13 PPTX mutations, four
PowerPoint COM mutations including an actual chart, five rendered slides,
fresh reopen after every operation, protected audit, replay, signed
certification, and zero residual PowerPoint, Excel, WFP, and profile state.
