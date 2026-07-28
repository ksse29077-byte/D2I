# Equipment Maintenance Source Pack

This is the Phase 9 reference source pack used to verify that embodied
extensions remain outside the core package format. It includes versioned executor
descriptors, benchmark profiles, target cost weights, typed IR lowering,
deterministic package compilation, and offline reference-runtime evaluation.

The intended MVP skill is `diagnose_fault`.

Validate it from the repository root:

```text
cargo run -p d2i-cli -- validate examples/equipment-maintenance
cargo run -p d2i-cli -- eval examples/equipment-maintenance
cargo run -p d2i-cli -- compile examples/equipment-maintenance --out build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- verify build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- explain build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- benchmark build/equipment-maintenance.d2ip --iterations 3
cargo run -p d2i-cli -- adapter-check build/equipment-maintenance.d2ip
cargo run -p d2i-cli -- adapter-conformance build/equipment-maintenance.d2ip --iterations 1
cargo run -p d2i-learning -- --help
cargo run -p d2i-runtime-ref --bin d2i-runtime -- run --package build/equipment-maintenance.d2ip --request examples/equipment-maintenance/requests/vibration.json --record build/equipment-maintenance-replay.json
cargo run -p d2i-runtime-ref --bin d2i-runtime -- replay --package build/equipment-maintenance.d2ip --record build/equipment-maintenance-replay.json
```

The evaluation bundle contains 50 synthetic cases spanning normal, negative,
ambiguous, edge, unsupported, and critical requests.

The default balanced target selects `case-retriever-compact`. A latency-heavy
selection profile selects `case-retriever-fast`; the low-quality candidate is
excluded before cost comparison.

Expected request fields:

- `equipment_id`
- `symptom`
- optional `error_code`
- optional sensor snapshot
- optional recent maintenance summary

Expected result fields:

- normalized symptoms
- candidate fault codes
- recommended check sequence
- evidence
- confidence
- human review flag
