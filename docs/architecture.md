# D2I Compiler Architecture

## Current Scope

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
