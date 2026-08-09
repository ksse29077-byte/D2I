# D2I Compiler

D2I is an Open Autonomous Digital Workforce OS that compiles an organization's
Domain, Role, Authority, Application Semantics, Organizational Memory, Work
Sources, and execution means into bounded autonomous digital employees capable
of general office and computer work. D2IC is its compile-time subsystem.

D2I Compiler (D2IC) is a Rust-first compiler project for turning a versioned
Domain Source Pack into a deterministic, verifiable, offline D2I Intelligence
Package.

This repository has completed Phase 9 and now includes a pre-learning desktop
autonomy foundation. Phase 9 provides a separate embodied-intelligence product
with typed sensor/action contracts, ROS 2 and hardware adapter boundaries,
deadline and safety separation, deterministic simulation replay, robot memory,
and signed fleet rollout metadata. Desktop autonomy adds typed PC actions,
deny-by-default policy, preparation-bound approval, durable audit, offline
conformance, concrete bounded local read-only access, and signed activation of
isolated Windows UI Automation, WebDriver, file-write, and process adapters.

## Workspace

- `crates/d2i-core`: manifest contracts, secure source inventory, parsers,
  typed IR, DAG validation, hashes, locks, and diagnostics.
- `crates/d2i-schema`: generated bindings for package `.fbs` schemas.
- `crates/d2i-compiler`: source lowering and deterministic package tooling.
- `crates/d2i-eval`: executor contracts, matching, Pareto selection, graph
  optimization, and runtime benchmark reports.
- `crates/d2i-runtime-api`: runtime, executor, registry, context, and result
  contracts.
- `crates/d2i-runtime-ref`: correctness-oriented package loader, scheduler,
  MVP executors, replay, and runtime CLI.
- `crates/d2i-runtime-adapter`: adapter contract, mock and proprietary
  placeholder, compatibility checker, ABI mapping, and conformance reports.
- `crates/d2i-ffi`: isolated C ABI v1 types, native module loader, host-owned
  buffers, copy metrics, and the published C header.
- `crates/d2i-kernel`: deterministic Rust score kernel, optional native
  candidate adapter, and controlled comparison benchmark.
- `crates/d2i-learning`: experience schema, tamper-evident store, candidate
  builder, offline evaluation gates, and signed promotion ledger.
- `crates/d2i-application-semantics`: immutable application packs and
  deterministic UIA/Web observation-to-Element-Grounder payload bridges.
- `crates/d2i-action-candidates`: sealed semantic-target/capability bindings
  and deterministic fixture bridges to Cognitive IR v1 `ActionProposal`.
- `crates/d2i-action-selection`: actual Grounder-result validation,
  deterministic multi-candidate generation, Plan Ranker metadata bridges,
  selected-proposal rebinding, and non-authoritative policy-ready actions.
- `crates/d2i-policy-admission`: delegated authority, trusted policy,
  bounded confirmation, activation eligibility, and non-executable Cognitive
  admission contracts.
- `crates/d2i-trusted-action-execution`: audit-safe binding of one admitted
  Cognitive action to an exact target, input hash, preparation, and terminal
  adapter-attempt receipt.
- `crates/d2i-cognitive-recovery`: deterministic failure classification,
  bounded recovery budgets and history, fresh-cycle retry, replan,
  clarification, escalation, terminal results, and legacy projection.
- `products/d2i-embodied`: separate robot integration contracts, simulation
  replay, safety-gated hardware boundary, robot memory, and fleet promotion.
- `products/d2i-desktop`: separate PC autonomy contracts, capability policy,
  signed approval, hash-chain audit, signed Windows runtime binding, and
  capability-isolated adapters. KRN-300 adds independent one-shot UIA/WebDriver
  re-observation and Verification v2. KRN-400 adds a protected durable recovery
  ledger and coordinator that persists bounded decisions before mutation,
  rejects replay, and requires wholly fresh retry trust chains.
  KRN-500 adds the first complete authenticated single-task runtime through
  actual standalone modules, UIA execution, independent verification, bounded
  recovery, final goal verification, and a machine-verifiable WorkReport.
- `crates/d2i-role-contract`: strict deterministic Role source compilation,
  immutable contracts, Ed25519 approval/delegation, persistent Role Instance
  lifecycle contracts, one-time task admission, and exact existing
  authority/recovery projections. `products/d2i-desktop` owns the protected
  Role ledger and role-bound KRN-500 gate.
- `crates/d2i-work-case`: strict hash-only Work Item normalization and
  admission, deterministic deduplication, immutable Case ownership,
  requirements, evidence, lifecycle, closure, terminal records, replay
  reports, and an execution-free inspection CLI. `products/d2i-desktop` owns
  the protected persistent Case ledger and actual role-bound KRN coordinator.
- `crates/d2i-work-intake`: exact Radar source registrations, signed
  `WorkSourceApprovalV1`, bounded typed Work Signals, deterministic
  event-to-Work mapping, replay-safe checkpoints, Intake receipts/cycle
  reports, and a one-shot authority-free source trait. `products/d2i-desktop`
  owns its protected approval-bound Intake ledger and exactly-one-Case crash
  recovery.
- `crates/d2i-work-queue`: deterministic Queue projection and scheduling,
  exclusive Case leases, audited ownership reassignment, and non-executable
  planner grants.
- `crates/d2i-situation-model`: approved Case context, provenance-separated
  Situation Models, explicit unknown/conflict state, strict JSON, and stable
  canonical hashes.
- `crates/d2i-intelligence-provider`: model-neutral goal, situation, and
  planning provider contracts, recorded replay, evaluation reports, and
  strict model-result admission.
- `crates/d2i-adaptive-planner`: one-step semantic planning with exact
  capability, target, value, precondition, postcondition, Case, lease, and
  generation binding. `products/d2i-desktop` owns the protected planner ledger
  and pinned local-model Windows process boundary.
- `crates/d2i-episodic-memory`: terminal-only reference/hash Episodes, signed
  approved summaries, exact Role-policy-bounded query, historical context,
  retention/tombstone, strict schemas, and deterministic replay.
- `crates/d2i-case-learning`: quarantined learning candidates, offline
  evaluation/review records, and zero-production-mutation export bundles.
  `products/d2i-desktop` owns their protected current-user store, ledger,
  index, crash repair, and actual memory-aware Qwen/KRN product evidence.
- `crates/d2i-windows-host`: narrow Windows Job Object, token/AppContainer,
  current-user DPAPI, protected DACL, process identity/version, reparse-point,
  atomic-move, and WFP loopback-egress boundary.
- `crates/d2i-cli`: source and package command presentation.
- `docs`: architecture, package, runtime ABI, threat model, benchmark, and ADR
  skeletons.
- `examples/equipment-maintenance`: validated equipment-maintenance source pack.

## Phase Boundary

Phase 9 keeps cognition/planning/memory separate from safety and motor control.
The ROS 2 and hardware implementations are fail-closed placeholders until
reviewed external APIs are supplied. A production binding also requires fresh,
signed runtime evidence that exactly matches the reviewed integration manifest
and one-time admission through a persistent activation ledger. Fleet promotion
signs staged-rollout metadata but never deploys or mutates a package.

The desktop product permits canonical-root reads and independently activated
Windows UI Automation, loopback WebDriver, canonical-root file writes, and
managed process actions. Every Windows binding requires fresh dual-signed
evidence and one-time ledger admission. Clipboard and credential adapters
remain fail-closed. Process children use zero-capability AppContainer network
isolation. Browser bindings require signed egress evidence and can pin the
concrete Windows WFP loopback-only provider to an exact browser image. A
deployment self-test launches the pinned Edge/EdgeDriver pair and requires
loopback delivery plus non-loopback denial before functional attestation.
After an admitted mutation, the mutation worker is not reused for verification.
A new read-only activation must produce a fresh exact-target observation before
the action can be classified as passed, failed, inconclusive, unsupported, or
unsafe.
Recovery then deterministically chooses a budgeted read-only re-observation,
wholly fresh trusted retry, equivalent alternate capability, bounded replan,
typed clarification, hash-only escalation, completion, continuation, or stop.
Unsafe outcomes never authorize an automatic second mutation.

## CLI

```text
cargo run -p d2i-cli -- validate examples/equipment-maintenance
cargo run -p d2i-cli -- inspect --json examples/equipment-maintenance
cargo run -p d2i-cli -- validate --write-lock examples/equipment-maintenance
cargo run -p d2i-cli -- compile examples/equipment-maintenance --out build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- eval examples/equipment-maintenance
cargo run -p d2i-cli -- explain build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- benchmark build/equipment-maintenance.d2ip --iterations 3
cargo run -p d2i-cli -- adapter-check build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- adapter-conformance build/equipment-maintenance.d2ip --iterations 1
cargo run -p d2i-cli -- adapter-abi
cargo run -p d2i-kernel --release --bin d2i-kernel-bench -- --out build/phase7-kernel-benchmark.json
cargo run -p d2i-learning -- --help
cargo run -p d2i-learning -- dataset-check examples/learning/dataset-registry.candidates.json
cargo run -p d2i-learning -- dataset-check examples/learning/desktop-agent-dataset-registry.candidates.json
cargo run -p d2i-learning -- dataset-verify approved-registry.json local-dataset-root
cargo run -p d2i-embodied -- readiness examples/embodied/integration-contract.template.json
cargo run -p d2i-embodied -- certify reviewed-integration.json runtime-binding.json
cargo run -p d2i-embodied -- ledger-init reviewed-integration.json robot-ledger robot-ledger-v1 deployment-agent-v1 10000
cargo run -p d2i-embodied -- ledger-check robot-ledger
cargo run -p d2i-desktop -- policy-check examples/desktop/desktop-policy.template.json
cargo run -p d2i-desktop -- adapter-check examples/desktop/offline-adapter.json
cargo run -p d2i-desktop -- audit-check desktop-audit
cargo run -p d2i-cli -- verify build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- diff build/old.d2ip build/new.d2ip --json
cargo run -p d2i-runtime-ref --bin d2i-runtime -- run --package build/equipment-maintenance.d2ip --request examples/equipment-maintenance/requests/vibration.json
cargo run -p d2i-runtime-ref --bin d2i-runtime -- replay --package build/equipment-maintenance.d2ip --record build/replay.json
```

Commands never perform network requests. The compiler CLI uses exit codes
`0/2/3/4/5/6`, where `6` is an evaluation regression. The runtime uses `6` for
execution failures and `7` for replay mismatches.

## Standalone Cognitive Modules

The root Cargo workspace excludes `modules/*`. Create and check modules without
changing the root manifest or lockfile:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/new-module.ps1 `
  -ModuleId my-module

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/my-module
```

Use `scripts/modules/check-all-modules.ps1` after a Core Cognitive IR, Module
SDK, schema, or module tooling change.

Run the complete Windows Safe Execution Kernel product gate with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/e2e/run-first-kernel-e2e.ps1 `
  -Mode All
```

Run the Work Item / Case v1 product gate, including the WORK-100 regression
and actual role-bound KRN evidence closure, with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-item-case-v1.ps1 `
  -Mode All
```

Run the Work Radar and Work Intake v1 gate, including WORK-100/200 regression,
the General Office source-to-Case E2E, Office/HR/IT/Safety compatibility,
signed source approval, replay, tamper, and crash recovery, with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-radar-intake-v1.ps1 `
  -Mode All
```

Run the Work Queue, deterministic Scheduler, and Case Ownership v1 gate,
including the WORK-300 multiple-Case E2E, crash recovery, signed reassignment,
exclusive leases, 128-Case replay, and WORK-100/200/300 regression, with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-queue-scheduler-v1.ps1 `
  -Mode All
```

Run the Situation Intelligence and Adaptive Planner v1 product gate with the
approved local artifacts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-situation-adaptive-planner-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-planner\completion
```

`All` covers deterministic WORK-500 contracts. Only `Completion` can set
`product_intelligence_evidence=true`; it additionally requires actual model
evaluation, adaptive Windows KRN execution, regressions, and terminal cleanup.

Run the WORK-600 product gate with the same approved local artifacts:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-episodic-memory-learning-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-memory\completion
```

It seals actual WORK-500 Path A/B as exactly-one Episodes, preserves the
canonical General Office hash-only policy, runs an actual signed-summary Path
C where fresh observation omits SetValue, quarantines a two-Episode candidate,
and proves 128-Episode deterministic replay with zero production mutation.

Run the WORK-700 Role Operations gate after WORK-600 with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-role-reporting-sla-escalation-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-operations\completion
```

It preserves immutable Case SLA baselines, applies only approved pause time,
calculates evidence-covered Role KPIs, creates non-authoritative reports,
publishes to protected internal inboxes, and tracks exactly-once escalation,
acknowledgement, and resolution. It adds no external delivery or background
service. WORK-700, WORK-800, and WORK-900 are complete; Track W is complete.
EDGE-100 and OFFICE-100 through OFFICE-400 are also complete. The next active
task is `D2I-OFFICE-500 - PDF and Document Interchange`.

Run the OFFICE-300 deterministic spreadsheet contracts, package security,
query/context slicing, worker, and predecessor regressions with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-spreadsheet-work-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-office300-spreadsheet-work/all
```

The spreadsheet plane scans workbook data in a private typed index and sends
only deterministic bounded typed facts to Qwen. Product `Completion` passed
with pinned Qwen/llama.cpp, sealed OFFICE-200 evidence, installed desktop
Excel, an exact temporary Excel WFP policy, signed certification, and zero
owned residual state.

Run the OFFICE-400 semantic presentation contracts, bounded PPTX security,
context/fact/plan checks, private-desktop PowerPoint smoke, and regressions
with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-presentation-work-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-office400-presentation-work/all
```

The presentation plane keeps a 120-slide template and 160,000-cell workbook
outside model context. It sends at most eight semantic slide references and
sixteen OFFICE-300 typed facts to Qwen, then lowers only a bounded slide plan.
Actual PowerPoint chart work runs on a private Windows desktop with exact
PowerPoint/Excel WFP denial, fresh reopen, PNG rendering, signed certification,
and zero owned residual state.

Run the deterministic WORK-800 contracts, schemas, protected store,
observation fixture, replay, and predecessor regression with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-open-digital-employee-shadow-v1.ps1 `
  -Mode All `
  -OutputRoot target\d2i-workforce-shadow\all
```

The separate `Completion` mode requires the pinned Qwen3-4B and llama.cpp
artifacts plus `-ReferenceMode Interactive`. It runs a sealed 60-Case holdout,
five Windows Shadow sessions, blinded commitment and independent adjudication,
signed readiness, WORK-700 internal publication, WORK-600 quarantine, and
cleanup gates. Shadow readiness never grants execution or activation.

Use `-Resume` after a transient failure. A step is skipped only when its
canonical checkpoint, current normalized inputs, produced artifact hashes,
dependency hashes, cleanup result, and zero-residual state all verify. Use
`-Fresh` to discard WORK-800 checkpoints. The explicit
`-ReuseVerifiedPredecessorEvidence` switch verifies sealed WORK-700 evidence;
it never substitutes for the WORK-800 holdout, interactive evidence,
readiness, or report.

Run the deterministic WORK-900 contracts, strict schemas, Role fixture,
protected store, negative suite, replay, and predecessor regressions with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-limited-autonomy-human-exception-v1.ps1 `
  -Mode All `
  -OutputRoot target\d2i-work900-all
```

The separate `Completion` mode requires sealed WORK-800 evidence and the
pinned Qwen3-4B/llama.cpp artifacts. It independently compiles and approves
General Office Role 1.4.0, runs one bounded eight-Case duty cycle through
actual Radar/Intake, Queue, model, Policy, activation, and KRN paths, and
proves five zero-touch routine closures plus three exactly-once human
exceptions. Use `-Resume` for a transient failure or `-Fresh` to discard safe
checkpoints. Readiness and autonomy admission remain non-executable evidence.
See `docs/workforce/limited-autonomy-human-exception-v1.md`.

EDGE-100 adds a bounded enterprise API execution plane. Signed Connector Packs
fix exact semantic operations, schemas, capabilities, targets, origins, and
limits. Models cannot supply URLs, HTTP methods, headers, raw bodies, or
credentials. Mutations preserve Policy, one-shot activation, and KRN authority
and require optimistic concurrency, deterministic idempotency, and fresh remote
verification before closure.

Run deterministic EDGE-100 gates with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/edge/run-enterprise-api-plane-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-edge-enterprise-api/all
```

Actual Completion additionally requires the pinned Qwen3-4B/llama.cpp and
sealed WORK-900 evidence. It uses separate loopback server and connector worker
processes, eight Work Items/Cases, actual socket reads and writes, bounded
recovery, five verified closures, three human exceptions, protected evidence,
and cleanup. Use `-Resume` after a transient failure. See
`docs/execution-planes/enterprise-api-v1.md` and ADR 0037.

OFFICE-100 adds pinned public capability-source assessment and a safe local
artifact workspace. It does not execute public MCP servers or edit Office file
contents. Run the deterministic contract, schema, negative, recovery, and
regression gates with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-office-capability-workspace-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-office-capability-workspace/all
```

`Completion` additionally requires `-ReuseVerifiedPredecessorEvidence` and a
sealed EDGE-100 evidence root. It creates only synthetic files in a fresh
temporary approved workspace, runs Cases A-J, verifies cleanup, and writes a
signed completion certification. See
`docs/office/general-office-capability-workspace-v1.md` and ADR 0038.

OFFICE-200 adds application-neutral document semantics, first-class bounded
HWPX and DOCX package backends, and an interactive-current-user Word COM
compatibility worker. Each Policy admission and activation performs one
semantic mutation, saves a new generation, and requires an independent fresh
reopen before verification. Legacy HWP remains separately license-gated.

Run deterministic contracts, schemas, package attacks, file backends, and
regressions without elevation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-document-work-v1.ps1 `
  -Mode All `
  -OutputRoot target/office200-all `
  -Fresh
```

`Completion` additionally requires sealed OFFICE-100 evidence, pinned
Qwen3-4B/llama.cpp, installed desktop Word, and one elevated interactive
deployment session for the exact temporary WINWORD WFP policy. It verifies 16
Cases, 12 actual model calls, HWPX/DOCX/Word mutations, semantic equivalence,
fresh reopens, signed certification, and zero residual state. See
`docs/office/document-work-v1.md` and ADR 0039.

## Checks

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

These commands cover the Core workspace. Standalone modules are covered by
their module-local checker and local `Cargo.lock`.
