# ADR 0002: Typed IR and Deterministic Package Format

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I compiler maintainers

## Context

Phase 2 must turn validated YAML/JSON sources into runtime-independent typed IR
and a deterministic, verifiable package. It must support execution branches,
parallel groups, bounded loops, validation, policy gates, and human review
without implementing a runtime. Package compatibility must not be coupled to
compiler releases, domain versions, or the future native ABI.

The workspace has no system `flatc` or CMake. Requiring native code generation
for every build would violate the reproducible Rust-first baseline.

## Decision

1. `d2i-core` owns typed Domain, Skill, Execution, Policy, and Evaluation IR.
   Every source-derived element references a validated provenance record.
2. Execution IR remains acyclic. A bounded loop is one node with an explicit
   maximum iteration count; graph back edges are invalid.
3. High-criticality skills receive compiler-inserted policy-gate and
   human-review failure nodes before returning.
4. `d2i-schema` contains `.fbs` contracts and committed Planus-generated Rust
   bindings. Normal builds require only the Planus runtime.
5. Six FlatBuffers roots separate manifest, domain, skills, execution,
   policies, and evaluation data.
6. Compiler version `0.2.0`, package format `1.0.0`, runtime ABI marker
   `0.1.0`, and the domain version evolve independently.
7. A package is a deterministic directory. A sorted hash manifest verifies
   every artifact, and its own bytes define the package content hash.
8. The writer stages, verifies, and then renames output. Existing output and
   output inside the source pack are rejected.

## Consequences

- Identical source content creates byte-identical packages and build IDs.
- Runtime Phase 3 can consume verified FlatBuffers metadata without loading
  compiler source formats.
- Generic rule conditions/actions and evaluation request/expected values remain
  canonical strings inside typed records because their complete DSL is not yet
  frozen.
- Generated schema code is an explicit low-level serialization boundary;
  handwritten compiler crates continue to forbid unsafe code.
- Hash verification does not provide authenticity. Phase 2 packages are
  unsigned candidates even when source policy says signing is required.
- Changing required schema fields, identifiers, or semantics requires a
  compatibility decision and likely a package-format version change.
