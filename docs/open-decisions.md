# Open Decisions

## Phase 0 Repository Survey

- No existing Git repository metadata was found in this workspace.
- No existing Rust, Mojo, C, or C++ source code was present outside the work
  order documents.
- No proprietary high-efficiency runtime API or public contract was provided.
- No existing source pack implementation was present.

## Deferred Decisions

- Proprietary package handles, calls, errors, cancellation, and threading
  remain deferred until real runtime API details are available.
- Mojo backend exploration is deferred until a Rust baseline and benchmark
  identify a real bottleneck.

## Phase 1 Decisions

- `domain.yaml` rejects unknown fields at every typed manifest level.
- D2I source contract version `0.1` is the only accepted Phase 1 version.
- Source files are limited to 16 MiB and structured record files to 100,000
  records.
- All symbolic links are rejected to avoid cycles, duplicate identity, and
  platform-dependent traversal semantics.
- `sources.lock` is deterministic JSON and is excluded from inventory input.
- Fingerprints exclude timestamps and include normalized path, byte size, and
  SHA-256 content hash.
- JSON Schema draft 2020-12 is supported with bundled relative references;
  network, root-absolute, and traversal references are rejected.
- The exact procedure/rule source schema remains intentionally narrow until
  typed Domain IR is introduced in Phase 2.

## Phase 2 Decisions

- Compiler, package-format, runtime-ABI, and domain versions are separate.
- Package format 1.0.0 uses six schema-version-1 FlatBuffers roots with fixed
  file identifiers.
- Planus 1.1.1 generates committed Rust bindings; ordinary builds do not
  require native code-generation tools.
- Bounded loops are acyclic graph nodes with explicit limits. Graph back edges
  are rejected.
- High-criticality lowering inserts policy-gate and human-review nodes.
- The package content hash is the SHA-256 of deterministic `hashes.sha256`;
  payload and manifest hashes avoid circular metadata.
- Output is a verified directory package committed from a sibling staging
  directory.
- Phase 2 packages are unsigned build candidates. Signature enforcement is
  deferred and must not be implied by successful hash verification.

## Phase 3 Decisions

- The reference runtime is a correctness baseline and uses only safe Rust
  executor traits; it is not the proprietary runtime adapter.
- Verified package bytes back an immutable in-memory artifact map to avoid
  verification/load time-of-check-time-of-use gaps.
- Package targets may use `any` only for portable, built-in Rust executors.
- Executor timeout is enforced at the scheduler boundary. Hard cancellation
  and process isolation are deferred with native executors.
- Deterministic replay compares timing-independent decision hashes while still
  returning newly measured timings.
- The three MVP executor implementations remain safe Rust built-ins behind
  package-selected IDs.

## Phase 4 Decisions

- Executor descriptors include capability, schemas, target, ABI, resources,
  security, license, and canonical artifact hash.
- Compatibility, quality, and safety are hard gates. Cost weights cannot make
  an unsafe candidate feasible.
- Selection operates on the non-dominated feasible set. Forced bindings must
  pass the same hard gates.
- Selection reports retain feasible, rejected, Pareto, normalized cost, forced
  binding, fallback, and explanation data under a `skill:capability` key.
- Build lowering fails when quality regression leaves a capability without a
  safe selected executor, even when a human-review fallback is declared.
- Small-first cascades are optional and materialized as an explicit confidence
  failure edge to the selected fallback executor.
- Runtime benchmark memory and allocator measurements remain unavailable until
  a reviewed platform collector is introduced.

## Phase 5 Decisions

- `RuntimeAdapter` is a safe Rust, object-safe D2I boundary. It does not model
  an undocumented external call signature.
- Adapters declare package format, runtime ABI, target, executor kind, memory,
  and network capabilities before load.
- Compatibility checks inspect only selected graph executors, not unused
  candidates retained for provenance.
- `RuntimeErrorCode` is the stable comparison layer; implementation-specific
  messages are diagnostic and are not conformance identity.
- The mock adapter delegates to the reference runtime. The proprietary
  placeholder always returns `AdapterUnavailable` after compatibility checks.
- Conformance requires identical decision hashes for valid vectors, valid
  output schemas, and equal stable error categories for error vectors.
- Adapter timing reports are automated diagnostics, not performance claims.

## Phase 6 Decisions

- Native ABI v1 is a C-compatible function table exported as
  `d2i_module_v1`; v1 requires a 64-bit host and fixed-width fields.
- Rust owns call buffers and opaque-handle lifetime. Modules cannot allocate
  host-visible result memory or free/retain host buffers.
- Larger function tables are accepted for forward-compatible extension, while
  ABI version changes remain explicit compatibility breaks.
- Native libraries are trusted only after canonical-root, regular-file, size,
  SHA-256 allowlist, symbol, descriptor, and function validation.
- Arrow C Data and DLPack support is optional and borrowed-only in Phase 6.
  Ownership transfer, release callbacks, and device synchronization are
  deferred.
- ABI copy metrics cover the host/module boundary. Copies inside a native
  implementation are not observable by the host.
- In-process loading is not a security boundary. Untrusted native executors
  require a future isolated worker and hard resource enforcement.

## Phase 7 Decisions

- The only experimental kernel is case-retriever match scoring, selected from
  the existing 8 ms compact-retriever profile. Parsing, routing, policy, and
  package code remain Rust.
- Rust first removes repeated query normalization, then scores a batch of
  three-bit masks into deterministic integer points.
- The candidate ABI is the stateless `d2i_score_match_masks_v1` symbol with
  caller-owned arrays and zero observable boundary copies.
- Mojo is pinned to 1.0.0b2 and built manually. Cargo never probes, installs,
  or invokes it.
- Exact correctness and a same-host p50 speedup of at least 1.20x are hard
  adoption gates. Build complexity is three tools/steps versus Rust's one.
- Mojo was unavailable on the validation host. The candidate is rejected until
  a hash-allowlisted library produces a reproducible qualifying report.
- The Rust baseline remains the production path; deleting the candidate source
  and feature does not alter package metadata or runtime behavior.

## Phase 8 Decisions

- Episode schema v1 is strict and binds experience to build and package hashes.
- Experience storage is an append-only SHA-256 chain with role, age, build, and
  entry-count policy. No mutation or automatic deletion API is exposed.
- Deterministic split groups use the situation hash; duplicates are reduced and
  untrusted, unknown, or base-mismatched records are quarantined.
- Retrieval, rule, refit, and routing adaptations remain non-executable
  proposals in a separate candidate bundle.
- Existing packaged gold data is mandatory. Any critical-error increase,
  regression, leakage, poisoning flag, or distribution shift rejects
  promotion.
- Promotion records are Ed25519-signed and hash-chained. Their state approves a
  future build input and does not designate a production package.
- Enterprise key custody, evaluator attestation, approval service integration,
  retention deletion, and rollout orchestration remain deferred.
- External datasets are candidates until a strict offline registry proves
  dataset/component license coverage, immutable source and evidence revisions,
  required human reviews, compliance plans, and local artifact hashes. A
  repository license is not assumed to cover imported records.
- Desktop-agent dataset admission classifies third-party, executable, and
  credential/session content explicitly. Executable-looking content requires
  security review and is never run by registry tooling.
- AndroidControl and Android in the Wild data are treated as CC-BY-4.0, and
  Mind2Web data as CC-BY-4.0; their repository source-code licenses do not
  replace dataset licenses.
- Ambiguous names such as `Bash-Instruct` and
  `CodeLlama-Instruct-Dataset` remain unregistered until an official immutable
  source and dataset-level license evidence are identified.

## Phase 9 Decisions

- Embodied integration is a separate product and dependency leaf rather than a
  compiler or reference-runtime module.
- D2I owns cognition, high-level planning, and memory. Dedicated external
  systems own safety decisions, emergency behavior, and motor control.
- Sensor and action schemas are backend-neutral JSON contracts. No ROS message
  package or DDS representation is selected.
- `safety_loop` is a recognized deadline class but prohibited for D2I action
  planning.
- ROS 2 and hardware boundaries use narrow traits and fail-closed placeholders;
  undocumented APIs and QoS behavior are not inferred.
- Simulation replay uses trace time and compares intent hashes and safety
  statuses without dispatch.
- Robot memory is a separate append-only chain and does not mutate a D2I
  package.
- Fleet promotion is a signed staged-rollout authorization, not a deployment.
  It requires externally verified package signatures and a distinct verified
  rollback package.
- Concrete ROS 2, safety-controller, hardware, simulation-engine, and fleet
  deployment integrations remain deferred pending reviewed contracts.
- Runtime activation requires a ready manifest plus fresh signed binding
  evidence whose ROS identity, endpoints, message hashes, QoS, executor,
  safety, and hardware observations exactly match. The manifest pins the
  evidence attestor key.
- Certified evidence is consumed by a manifest-pinned append-only activation
  ledger before a one-shot adapter binding is available. Duplicate evidence,
  observation rollback, expiry, and chain tampering fail closed.
- `OfflineConformanceRos2Transport` supports deterministic adapter tests only;
  it must never be presented as a concrete ROS 2 or DDS implementation.

## Desktop Autonomy Foundation Decisions

- Desktop autonomy is a separate product and dependency leaf.
- Runtime decisions cannot directly invoke an OS API. They produce typed,
  hash-bound action intentions.
- Capability and risk are derived from the operation enum in trusted Rust.
- External communication, credential, destructive, and privileged operations
  always require a preparation-bound Ed25519 approval.
- Adapter execution is a prepare/commit protocol with a short-lived opaque
  permit and precondition recheck.
- The audit ledger is append-only and payload-free. A prepared action without a
  terminal result blocks unattended recovery.
- Concrete Windows UI Automation, loopback W3C WebDriver, canonical-root file
  write, and managed-process adapters require exact dual-signed runtime
  certification and one-time append-only ledger activation.
- Each Windows capability group has a distinct descriptor and Job Object worker
  with immutable hash-pinned configuration, bounded protocol, timeout,
  process-count, memory, and kill-on-close controls.
- UI actions use exact process/executable/title identity and unique
  AutomationId control patterns. Browser actions use pinned sessions, origins,
  CSS selectors, and no JavaScript. Process launch uses direct argv and
  termination is limited to managed children.
- Job Objects are not principal or network sandboxes. Process children use a
  zero-capability AppContainer. Browser deployments may use the concrete,
  browser-hash-pinned WFP loopback-only provider; authenticated non-loopback
  hostname/origin allowlists remain a future proxy or callout decision.
- Clipboard, credential providers, secure-desktop UI, browser download/upload,
  and arbitrary-coordinate control remain unavailable.
