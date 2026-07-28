# Cognitive IR v1 Contract

Cognitive IR v1 is a strict, versioned JSON/Rust contract for the model-free
cognitive task loop:

```text
GoalSpec -> ObservationSnapshot -> WorldState -> ActionProposal
-> policy/activation traits -> ActionExecutor trait -> reobserve
-> PostconditionVerifier -> RecoveryDecision -> WorkReport
```

All public Cognitive IR v1 values carry `schema_version = 1`, reject unknown
JSON fields, reject unknown enum values, and are validated again in Rust before
the reference executor consumes them.

## Canonical Hash Rule

The stable hash format is `sha256:<hex>`. The baseline computes hashes from
UTF-8 JSON emitted by Rust `serde_json` over structs that use fixed field order
and `BTreeMap` for maps. Timing measurements are logical counters, not wall
clock values, when deterministic replay is required.

`ObservationSnapshot.state_hash` is derived from the observation source,
target binding, trust labels, observable elements, and redaction metadata. It
does not include observation ID or sequence, so identical observable state has
the same hash across fixture runs.

## Unknown Fields And Compatibility

Unknown fields are rejected in Rust with `serde(deny_unknown_fields)` and in
JSON Schema with `additionalProperties: false`. A future v2 must either add a
new schema ID or a documented migration path. v1 readers fail closed on other
versions rather than silently accepting partial semantics.

Backward-compatible v1 additions are limited to new optional fields that do not
change executor safety decisions. Any new action kind, trust label semantics,
loop behavior, package embedding, Runtime ABI mapping, or irreversible action
support requires an ADR or RFC.

## Package And Runtime ABI

Cognitive IR v1 is not embedded into the immutable D2I package format by this
baseline. The package format and runtime ABI are unchanged. Integration with
production packages requires a separate compatibility RFC.
