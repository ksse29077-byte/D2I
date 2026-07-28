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

## Next Task

Write an RFC for connecting Cognitive IR v1 to real desktop policy,
activation, and audit implementations through the new traits. Do not start
that integration until the RFC is reviewed.
