# D2I Compiler

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
- `products/d2i-embodied`: separate robot integration contracts, simulation
  replay, safety-gated hardware boundary, robot memory, and fleet promotion.
- `products/d2i-desktop`: separate PC autonomy contracts, capability policy,
  signed approval, hash-chain audit, signed Windows runtime binding, and
  capability-isolated adapters.
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

## Checks

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

These commands cover the Core workspace. Standalone modules are covered by
their module-local checker and local `Cargo.lock`.
