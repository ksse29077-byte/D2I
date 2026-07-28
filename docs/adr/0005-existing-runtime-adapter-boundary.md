# ADR 0005: Existing Runtime Adapter Boundary

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I runtime maintainers

## Context

Phase 5 must prepare integration with an existing proprietary high-efficiency
runtime. Its real API, package handle, error table, cancellation semantics, and
threading contract have not been provided. Inventing those details would create
an unsafe and misleading dependency.

## Decision

1. `d2i-runtime-adapter` defines an object-safe `RuntimeAdapter` with only D2I
   package load and Decision Envelope execution boundaries.
2. `AdapterContract` declares supported package format, runtime ABI, target,
   executor kinds, resident memory, and network policy.
3. Compatibility is checked against fully verified package bytes and selected
   graph bindings before adapter load.
4. `MockRuntimeAdapter` delegates to the reference runtime and proves package,
   request, output, error, and report wiring.
5. `ProprietaryRuntimeAdapterPlaceholder` is deliberately nonfunctional. It
   returns `AdapterUnavailable` until actual API documentation or code exists.
6. Conformance runs identical valid vectors plus invalid-request and
   unsupported-skill vectors, validates output schemas, compares
   timing-independent decisions and stable `RuntimeErrorCode` values, and
   emits independent latency summaries.
7. Phase 5 ABI mapping is metadata for the safe Rust contract. Native C ABI,
   dynamic loading, and buffer ownership remain Phase 6 work.

## Consequences

- The existing runtime can be connected without changing compiler or package
  contracts once its real API is supplied.
- Mock conformance proves the integration harness, not proprietary runtime
  correctness or performance.
- External error messages are not equality keys; stable mapped categories are.
- No proprietary API, native symbol, handle, memory layout, or speed claim is
  fabricated.
