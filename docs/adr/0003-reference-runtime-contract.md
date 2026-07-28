# ADR 0003: Reference Runtime Contract

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I runtime maintainers

## Context

Phase 3 needs a deterministic correctness baseline that verifies packages,
activates only compiled modules, enforces graph bounds and policy fallback, and
returns auditable results without depending on a model framework, network
service, native ABI, or the proprietary runtime.

## Decision

1. `d2i-runtime-api` defines safe Rust contracts for runtime, executor,
   registry, task context, package loading, replay, and Decision Envelopes.
2. `d2i-runtime-ref` verifies the whole package before constructing immutable
   indexes or binding executors.
3. The scheduler executes the compiled DAG with deterministic ready ordering,
   parallel batches, bounded retries, timeout observation, failure edges,
   policy gates, and human-review fallback.
4. Phase 3 ships only three package-bound, side-effect-free Rust executors:
   term normalization, sparse case retrieval, and procedure decision.
5. Every envelope contains package/build identity, activated modules, source
   evidence, confidence, policy result, node timings, warnings, and replay key.
6. Replay re-executes the recorded request and compares a timing-independent
   decision hash bound to the package content hash.

## Consequences

- The runtime never loads package-provided code and performs no network access.
- Target and executor incompatibility fail before request execution.
- Timeout returns control at the scheduler boundary, but cannot forcibly stop
  an arbitrary Rust thread. Built-in executors therefore remain bounded and
  side-effect-free; stronger isolation is required before native plugins.
- Runtime timings are diagnostic measurements, not deterministic values or
  benchmark claims.
- Automatic executor selection, native ABI, proprietary adapters, and learning
  remain outside Phase 3.
