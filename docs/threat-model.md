# Threat Model

## Assets

- Domain Source Pack contents.
- Typed IR and compiled package metadata.
- Package signatures and hashes.
- Runtime decision envelopes.
- Evaluation data and benchmark artifacts.
- Future experience and learning data.

## Attack Surfaces

- Malicious domain files.
- Path traversal and symlink escape.
- Oversized source records.
- Malicious or recursive rules.
- Poisoned examples and evaluation data.
- Tampered packages.
- Plugin or executor module replacement.
- External network calls.
- Logs containing sensitive data.
- Future feedback poisoning.

## Phase 1 Controls

- Source-pack roots and every manifest reference are canonicalized.
- Absolute paths and `..` traversal are rejected.
- Symbolic links are rejected; links that escape the root receive a specific
  diagnostic.
- Files are read through a 16 MiB bound both while hashing and parsing.
- CSV and JSONL parsing is capped at 100,000 records per file.
- Only Markdown, text, CSV, JSON, JSONL, YAML, and JSON file extensions are
  accepted.
- JSON Schema uses draft 2020-12 with external and root-absolute `$ref`
  rejected. Bundled relative schema references are registered in memory.
- The schema validator's HTTP/file resolver features are disabled.
- Inventory ordering and fingerprints use normalized paths, byte sizes, and
  content hashes. Timestamps are not fingerprint inputs.
- Source text is parsed as untrusted data and is never executed.
- No package reader, executor loader, FFI, or runtime exists yet.
- No production package mutation path exists.

## Phase 2 Controls

- Every IR element carries a provenance ID validated against the package
  provenance table.
- Execution graphs reject duplicate/missing nodes and cycles. Repetition is a
  bounded-loop node capped at 10,000 iterations rather than a graph back edge.
- High-criticality skills receive a policy gate and human-review failure path.
- Package output is rejected inside the source root and written through a
  verified sibling staging directory.
- Package paths reject absolute paths, traversal, backslashes, and symlinks.
- Package files are bounded to 64 MiB while verifying.
- All artifacts are allowlisted by `hashes.sha256`; missing and unexpected
  files fail verification.
- FlatBuffers identifiers, required fields, schema versions, separated package
  and runtime versions, file sizes, payload hash, and content hashes are
  verified before section metadata is returned.
- No package code performs network access or executes source/package content.

## Phase 3 Controls

- Runtime loading begins with full Phase 2 verification and retains the
  verified bytes instead of reopening package artifacts.
- Target OS/architecture compatibility and deny-network policy are checked
  before indexes or executors are constructed.
- Graphs are revalidated at trust entry with bounds for nodes, edges, retries,
  timeouts, loops, references, cycles, and side effects.
- Every executor binding must be both policy-allowed and present in the local
  registry. Dynamic libraries and package-provided code are not loaded.
- Request JSON is limited to 1 MiB and validated against its verified bundled
  schema before any executor activation.
- Executor calls have deadlines and retries are capped at 16. A timed-out
  cooperative-free executor thread may finish in the background, so Phase 3
  executors are side-effect-free and bounded by construction.
- Policy failure routes high-criticality decisions to a human-review marker;
  the reference runtime never performs the external approval action.
- Replay records are bound to build ID and package content hash.

## Phase 4 Controls

- Descriptor, benchmark, and selection YAML are untrusted typed inputs with
  unknown-field rejection and bounded source-file handling.
- Candidate selection rejects incompatible capability, schema, ABI, target,
  memory, network, side-effect, license, artifact hash, and quality profiles
  before considering cost.
- Forced bindings cannot bypass hard gates. A quality regression that removes
  the final safe binding fails compilation.
- The runtime decodes descriptors only from verified package bytes and checks
  ABI, host target, deny-network policy, duplicate IDs, policy allowlisting,
  local implementation presence, and graph binding presence before execution.
- Optimizations operate on typed DAGs. Duplicate preprocessing and lookup nodes
  are merged only when their executor, schemas, and incoming edges match.
- Benchmark execution is local, bounded by case count, iteration limit, and
  runtime deadlines. It does not fetch models or evaluation data.

## Phase 5 Controls

- Adapter capabilities are explicit data and are checked after full package
  verification, before adapter load.
- Selected executor kinds, estimated resident memory, ABI, target, and network
  policy must fit the declared adapter contract.
- The mock adapter loads only through the verified reference runtime.
- The proprietary placeholder cannot execute and returns a structured
  `AdapterUnavailable` error, preventing accidental use of invented APIs.
- Adapter results are validated against the package output schema and compared
  using timing-independent decision hashes.
- Error conformance compares stable categories rather than untrusted external
  message text.
- Conformance iterations are bounded to 1,000 and each call receives a positive
  deadline.

## Phase 6 Controls

- Native module paths are canonicalized under an explicit root. Symlinks,
  escapes, non-files, and oversized libraries are rejected before loading.
- The complete library file is streamed through SHA-256 and must match an
  explicit allowlist value before platform loader execution.
- Only the fixed `d2i_module_v1` symbol is accepted. ABI version, minimum table
  size, bounded UTF-8 identity, and every required function are validated.
- Rust owns input and output allocations. Pointer, capacity, alignment, and
  memory-kind metadata are checked before and after each call.
- Output length is validated before slicing. Buffer-too-small responses expose
  only the required size and never foreign memory.
- The initialized opaque handle is stored in an `Option` and taken before
  destruction, preventing host-side double free through repeated shutdown or
  `Drop`. Calls after shutdown are rejected; mutable host access serializes
  calls for one handle.
- FFI metadata has a deterministic 10,000-case malformed-input corpus test.
  Rust and C fixtures verify the published 64-bit layout and cross execution.
- Native calls are byte-view based and perform no JSON serialization at the
  boundary. Copy and allocation counters make boundary copies visible.

Trusted in-process native code can still write outside a valid view, retain a
pointer, block forever, or load malicious transitive dependencies. Hash
allowlisting authenticates only the primary file. Process isolation, OS-level
resource enforcement, and signed dependency manifests remain required before
untrusted native modules are supported.

## Phase 7 Controls

- The score candidate receives only bounded match-mask and score arrays, not
  requests, package contents, credentials, or JSON.
- Unknown match bits, output length mismatch, root escape, oversized library,
  hash mismatch, and missing symbol are rejected before or at the call boundary.
- Candidate output must exactly equal the Rust integer baseline before timing
  can influence adoption.
- Cargo never executes the Mojo compiler or backend source. A candidate library
  is an explicit, separately built, hash-allowlisted input.
- The default runtime executes Rust only. Enabling the loader feature does not
  select or activate a native candidate.

## Phase 8 Controls

- Episode JSON is bounded, rejects unknown fields, carries build/package
  identity, route, outcome, correction, policy, provenance, and trust.
- Role allowlists control append, export, and candidate build. Store age and
  entry count are bounded.
- Every store append verifies the complete SHA-256 chain. There is no update or
  delete API.
- Candidate output must be outside the base package, is written via a sibling
  staging directory, and has a fixed path allowlist plus artifact hashes.
- Base-mismatched, untrusted, and unknown-outcome episodes are quarantined.
  Situation-group splitting prevents train/evaluation leakage; distribution
  shift and unresolved poisoning block promotion.
- Adaptation proposals are metadata only. They cannot execute instructions,
  alter policy, train a model, or rewrite a package.
- Evaluation requires the existing bundled gold bytes to match their compiled
  provenance hash. Critical-error increase and quality regression are hard
  failures.
- Promotion requires a human approval, shadow/canary plan, exact rollback
  target, complete evaluation hash, and Ed25519 signature. Ledger records form
  an append-only hash chain.
- Production `.d2ip` files have no Phase 8 write path.
- External datasets remain non-admissible until legal/provenance and applicable
  privacy/security/generation-terms reviews are approved against immutable
  evidence.
- Component-derived datasets require a hashed component-license inventory;
  repository-level licensing is not assumed to cover imported instances or API
  documentation.
- Local dataset artifacts are path-normalized, root-confined, non-symlink,
  size-bounded, and streaming-hash verified. No registry command downloads or
  executes dataset content.
- Third-party content requires component-specific license accounting.
  Executable-looking records require security review; credential or session
  material requires both security and personal-data review.
- GUI coordinates, DOM snapshots, HTML, scripts, function arguments, shell
  commands, and source code remain inert records. Admission never renders,
  compiles, loads, or dispatches them.
- Benchmark test splits marked evaluation-only cannot enter training,
  retrieval, or adaptation inputs.

## Phase 9 Controls

- Sensor payloads and action parameters are bounded strict JSON with explicit
  robot, sequence, time, build, package, evidence, and payload hashes.
- D2I action intents cannot use the 20 ms `safety_loop` class and are never
  represented as raw motor commands.
- Safety permits hash-bind the exact intent, expire no later than the intent,
  and are required before any hardware port dispatch.
- Default ROS 2, safety, and hardware integrations cannot actuate.
- ROS topic syntax and message sizes are bounded; topic/sensor-kind mismatches
  fail before planning.
- Simulation replay is package/world-bound, ordered, deterministic, and has no
  hardware or wall-clock side effects.
- Robot memory is role/robot allowlisted, bounded, append-only, and hash-chained.
- Fleet promotion requires a verified rollout package, distinct verified
  rollback package, external package-signature attestation, zero-critical
  simulation qualification, hardware profile hashes, staged cohorts, approval,
  and Ed25519 signature.
- Fleet promotion creates metadata only and never discovers or contacts robots.
- Integration readiness rejects implicit/system-default QoS, incompatible peer
  reliability/durability/deadline, unowned callback groups, blocking
  deadline-sensitive callbacks, safety-loop routing into D2I, and incomplete
  safety/hardware lifecycle guarantees.
- Runtime binding evidence is bounded, expires within 15 minutes, and is signed
  by an Ed25519 probe key pinned in the reviewed manifest.
- Certification compares exact ROS identity, endpoint set, message type hashes,
  QoS, callbacks, safety latency/protections, and hardware profile/capabilities.
  Any drift prevents creation of the opaque activation proof.
- A manifest-pinned append-only activation ledger rejects evidence replay,
  binding reuse, observation-time rollback, unauthorized activator IDs,
  expired proofs, chain tampering, and entry-limit exhaustion.
- Ledger admission persists and syncs the consumption record before returning a
  one-shot activation object. Adapter binding consumes that object and checks
  expiry again.
- The offline conformance transport has topic and queue bounds and is explicitly
  not a production ROS transport.

## Desktop Autonomy Controls

- Actions are a closed Rust enum; shell text, scripts, arbitrary code, and
  model-declared risk labels are not executable inputs.
- External dataset actions cannot directly construct or authorize a desktop
  action. A future typed transition normalizer and the ordinary decision,
  policy, preparation, approval, permit, and audit path remain mandatory.
- Every action exactly binds a successful runtime decision, build, package,
  request, and evidence set.
- Policy pins actor roles, capabilities, roots, executable identities, origins,
  adapter descriptors, approver keys, lifetimes, and session budgets.
- External communication, credentials, destructive work, and privileged work
  cannot be configured to bypass human approval.
- Approval signatures bind the action, policy decision, preparation snapshot,
  expiry, approver, and nonce.
- Session sequence, action ID, and approval ID replay are rejected.
- Adapter commit rechecks the preparation snapshot and permit binding.
- The concrete local read adapter canonicalizes roots and targets, rejects
  symlinks, and bounds reads and listings.
- Windows side-effect adapters require an exact host/configuration/worker
  manifest, fresh attestor-signed probe evidence, an independent certifier
  signature, and one-time append-only activation before construction.
- Windows workers use bounded framed IPC and immutable configuration inside
  kill-on-close Job Objects with active-process and per-process-memory limits.
  Protocol errors and timeouts terminate the worker tree.
- File writes reject reparse roots and components, recheck content
  preconditions in the worker, atomically move a same-directory temporary file,
  and verify the final content hash.
- Process launch uses exact executable path/hash, policy argument prefix, direct
  argv, and canonical working directory. Each child is created with the
  manifest-pinned zero-capability AppContainer SID, and only managed children
  can be terminated. Network-requesting process intents are denied.
- UI Automation binds PID, executable hash, title hash, unique AutomationId,
  enabled state, runtime ID, and supported control pattern before commit.
- WebDriver resolves only a configured loopback endpoint, pins session and
  origin, accepts CSS selectors only, and does not execute JavaScript. A fresh
  independently signed egress-policy observation is mandatory. The concrete
  Windows mode pins the browser image and exactly revalidates persistent
  application-scoped WFP IPv4/IPv6 loopback permits and catch-all blocks before
  probe, bind, prepare, and commit. Its production attestation path also runs a
  bounded local control/loopback/non-loopback Edge test, rechecks WFP objects,
  and opens the protected signing key only after the negative observation
  passes.
- Windows signing keys are current-user DPAPI protected and role-bound.
  Activation and audit DACL fingerprints are verified before read or append.
- Audit intent is synced before commit. Outcome bytes and direct credentials
  are excluded from audit records.
- The offline conformance adapter never represents a production host
  integration.

## Future Required Controls

- Package signature verification.
- Process isolation and hard memory/time enforcement for untrusted native
  executors.
- Signed native dependency manifests or an equivalent closure-verification
  mechanism.
- Secret redaction in diagnostics and logs.
- External human approval workflow for high-criticality side effects.
- Organization key custody and approver identity binding.
- Hard retention deletion with legal-hold semantics.
- Dataset consent/PII remediation workflows, harmful-content operator controls,
  license-revocation monitoring, and reproducible normalization pipelines.
- Authentication of safety permits and concrete ROS 2/DDS security profiles.
- Attested concrete runtime probe implementation and organization probe-key
  custody, rotation, revocation, and anti-rollback policy.
- OS-authenticated activator identity, external chain-head anchoring, backup,
  and crash-recovery operations.
- Fleet health telemetry, deployment isolation, and rollback execution.
- OS-authenticated desktop actor, activator, and approver identities;
  organization attestor/certifier custody; external chain-head anchoring; and
  crash reconciliation.
- An enforcing proxy or WFP callout for authenticated non-loopback hostname or
  HTTP-origin allowlists, plus browser download/upload governance. The concrete
  WFP provider intentionally supports loopback-only deployments.
- Secure-desktop behavior, credential-provider integration, and clipboard
  policy where those capabilities are later required.
## Trusted Action Execution Binding v1

The KRN-200 boundary treats Cognitive actions, policy records, source
observations, UI/Web content, target hints, and payload sources as untrusted
until their exact hashes and authority intersections are validated.

Mitigations include one-shot Windows activation consumption, a closed
six-operation mapping, exact process/session/origin/image binding, read-only
fresh target snapshots, prepare/commit precondition equality, bounded
non-secret payloads with drop-time clearing, a separate Cognitive permit
digest, protected hash-only audit, and terminal worker cleanup.

An adapter-success receipt must not be treated as verified closure.

## Re-observation and Verification v2

KRN-300 addresses substitution, stale evidence, worker-authority reuse,
collateral UI changes, false completion, and verification replay. It requires
a separately activated read-only worker, a newer observation ID and sequence,
the same logical process/session/window or browser-session/origin, zero
observation side effects, clean worker exit, exact element-ID joins, a
non-empty disjoint guard profile, protected security invariants, canonical
value hashes, protected hash-only audit, and one receipt consumption.

Unexpected or identity-relevant changes are unsafe even if execution failed.
Adapter success and state-hash inequality do not imply a passed verdict. The
terminal artifact has no adapter, filesystem, process, network, retry, replan,
or case-closure authority.

## Bounded Cognitive Recovery Control v1

KRN-400 addresses blind replay, stale trust-chain reuse, retry storms,
authority widening, arbitrary ambiguity resolution, unsafe automatic
compensation, ledger rollback, and restart budget reset. Recovery is decided
by a closed deterministic matrix with unsafe/security priority. Total cycles,
fresh retries, read-only re-observations, replans, clarification requests, and
deadline are independently bounded and consumed atomically.

Proposal, admission, activation, and execution-receipt identities are one-use.
A mutating retry requires a wholly fresh KRN-100 through KRN-300 trust chain.
Replans must remain within the original goal, authority, policy, and bounded
acyclic graph. Clarification is typed and one-shot; escalation is hash-only.
Raw secrets, untrusted instructions, locators, payloads, and absolute paths are
rejected from recovery artifacts and protected audit.

The Desktop coordinator writes its protected hash-chained recovery ledger and
audit intent before invoking a mutation closure. ACL, parse, chain, replay,
budget, truncation, or audit failure stops before mutation. Remaining risks
include external audit-chain anchoring, production escalation-recipient
routing, and user-facing clarification transport; those do not grant fallback
execution authority.

## First Complete Single-Task Kernel E2E

KRN-500 addresses cross-boundary substitution, fake module output, stage
skipping, false task completion, transport nondeterminism, and residual
authority across the complete task. Module identities, manifests, schemas,
host binaries, resource bounds, and invocation IDs are pinned. Core invokes
the actual standalone implementations only through bounded one-shot Module
Contract v1 processes and never links them.

Every action has a new policy admission and Windows activation. Verification
uses a separate read-only activation after the mutation worker exits. Final
completion additionally requires a newer stability observation, all goal
criteria and protected invariants passed, complete goal progress, and an exact
WorkReport hash. Unsafe outcomes cannot retry; clarification cannot activate
or mutate. Core artifacts reject raw locators, payloads, credentials, and
absolute paths. Terminal cleanup requires zero module host, worker, app,
activation, payload, and temporary-state residuals.

Remaining risk is intentionally outside Track K: KRN-500 is one fixed local
fixture task and does not establish persistent Role/Case ownership, general
module loading, arbitrary application control, or production model planning.

## Role Contract and Persistent Role Instance

WORK-100 addresses prose-derived authority, unsigned activation, approval and
delegation substitution, delegated scope expansion, stale or replayed Role
task admission, contract in-place mutation, suspended/revoked reactivation,
ledger rollback, and false KPI/SLA/Case claims. Contracts and signed grants use
exact canonical hashes and bounded explicit sets. The Desktop ledger verifies
protected DACL fingerprints, an atomic append-only hash chain, legal lifecycle
transitions, contract ID/version collisions, consumed request/admission hashes,
and protected audit cross-references before returning current state.

The KRN root is created only after exact Role context, active instance,
instruction, GoalSpec, pack, integration, capabilities, authority projection,
recovery projection, and consumed task-start evidence agree. Role artifacts
exclude raw locators, payloads, credentials, private keys, recipient personal
data, and absolute paths. Remaining risks include organization production key
custody, external chain-head anchoring, Work Item/Case ownership, scheduler
time authority, KPI measurement, SLA timers, and report routing; none grants a
fallback execution path.

## Immutable Work Items and Persistent Cases

WORK-200 addresses raw-source elevation, source event replay, semantic
collision, duplicate Case creation, Work Item/Role/scope substitution, stale
Case requests, KRN run reuse, evidence substitution, WorkReport-only false
completion, failed-task false terminal state, terminal reopen, ledger rollback,
and silent abandonment.

Source envelopes and Work Items contain only bounded IDs, trust labels, and
hash references. They cannot grant capability, policy, activation, adapter, or
mutation authority. Admission requires exact active Role, delegation,
organization, work class, source allowlist, pack, integration, capability,
risk, policy, calendar, freshness, and deduplication state before Goal or Task
work begins.

The Desktop Case ledger verifies protected DACL fingerprints, atomic
append-only SHA-256 state, monotonic sequence/time, immutable Work Item and
Case identities, one-time Task/attempt/KRN-run use, Role and audit chain heads,
and terminal immutability. The coordinator revalidates the full owner Role
Instance and ownership expiry before every Task. Durable-write failure poisons
the coordinator before later mutation.

Closure evaluates typed outcome and evidence requirements against exact
current hashes and trust/freshness floors. Failure, timeout, infrastructure
error, budget exhaustion, clarification, block, suspension, and generated
reports remain non-terminal. Unsafe evidence cannot become completion;
revocation or expiry requires escalation. Remaining risks include external
ledger-head anchoring, production SLA time authority, legal retention, Radar
source authentication, Queue/Scheduler concurrency, and future ownership
transfer. None creates a fallback execution path in WORK-200.
