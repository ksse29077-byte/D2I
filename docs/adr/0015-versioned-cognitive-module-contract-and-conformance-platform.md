# ADR 0015: Versioned Cognitive Module Contract and Conformance Platform

- Status: Accepted
- Date: 2026-07-28
- Decision owners: D2I cognitive core, module platform, runtime, and security maintainers

## Context

ADR 0014 defines Cognitive IR v1 and a deterministic, model-free
`CognitiveExecutor`. Independent teams now need to build narrow cognitive
modules without importing compiler internals, receiving adapter authority, or
depending on a production runtime ABI that has not been specified.

The repository already has immutable package, runtime adapter, policy,
activation, and audit boundaries. This decision adds a development and
conformance contract only. It does not embed modules in production packages,
load native artifacts, or connect modules to concrete Windows execution.

## Decision

1. A module does not import `d2i-core`, mutate D2I internal state, or receive a
   raw adapter, policy, activation, audit, filesystem, or network handle.
2. Every call crosses a versioned `ModuleInvocationEnvelope`, and every
   response crosses a versioned `ModuleResultEnvelope`.
3. Inputs and outputs must pass their declared JSON Schema and typed Rust
   contract validation before they are used.
4. Modules return capability proposals, reductions, rankings, verification
   results, recovery advice, reports, or other typed transformations. They do
   not execute host side effects.
5. Side-effect authority remains exclusively behind `CognitiveExecutor`
   policy and activation gates.
6. Network use is declared in the manifest and denied by default. The v1
   reference runner rejects modules that require network access.
7. Side effects, privileged operations, raw secret input, and persistent data
   retention default to false.
8. Deterministic modules must produce identical canonical result hashes for
   repeated calls with the same invocation and replay context.
9. Time, memory, input, output, logical operation, retry, concurrency, and
   collection limits are explicit and bounded.
10. Panic, abnormal termination, timeout, resource exhaustion, malformed
    output, schema mismatch, and replay mismatch fail closed with a structured
    `ModuleError`.
11. Web, document, email, UI, and other externally sourced text remains
    untrusted data. It is never promoted to an executable instruction by the
    module contract or SDK.
12. Confidence semantics are declared per capability. Confidence is either a
    finite value in the inclusive range `0..1` or explicitly not applicable.
13. A module artifact is bound to its manifest by SHA-256. The manifest hash is
    SHA-256 over canonical JSON with the optional self-hash field omitted.
14. Modules with unclear data provenance, incompatible licenses, undeclared
    dependencies, hidden network requirements, or incomplete security
    metadata are not production candidates.
15. Rust native reference modules and future Mojo or isolated-process modules
    share the same language-neutral JSON Schema, canonical JSON, hash, error,
    and replay contracts.
16. Rust is the v1 reference SDK. A Mojo C ABI or IPC loader, floating-point
    cross-platform policy, and zero-copy optimization are future work.
17. The v1 work defines the language-neutral contract and reference runner but
    does not change the production package format or Runtime ABI. Such a
    change requires a separate RFC and compatibility review.

## Canonical Representation

Canonical JSON is UTF-8, contains no insignificant whitespace, recursively
sorts object keys by Unicode code point, preserves array order, rejects
duplicate keys, and accepts only finite JSON numbers. SHA-256 hashes use the
`sha256:<64 lowercase hexadecimal characters>` form.

The manifest hash excludes `identity.manifest_sha256`. A loader computes the
hash, validates an explicitly supplied value when present, and exposes the
computed hash in the runtime `ModuleIdentifier`.

## Execution Modes

- `in_process_rust_reference` is implemented for deterministic reference and
  conformance use.
- `isolated_process_reference`, `future_native_abi`, and
  `future_mojo_worker` are reserved declarations. The v1 runner fails closed
  rather than attempting to launch them.

## Consequences

- Module teams can implement and test independently against a stable contract.
- The module SDK remains independent of CognitiveExecutor and Windows concrete
  adapters.
- Cognitive IR values can be carried as typed module payloads without granting
  execution authority.
- Static manifest validation and deterministic reference execution are
  available now; production loading and activation remain deliberately
  unresolved.

## Validation

- strict contract and manifest round trips
- unknown field, version, enum, hash, schema, and identifier rejection
- manifest tamper, artifact mismatch, path traversal, and schema substitution
  rejection
- panic, timeout, resource budget, output size, secret leakage, and untrusted
  content negative fixtures
- deterministic replay and stable report/hash checks
- reference `RuleBasedWorkReporter` conformance
- intentionally invalid module fixtures
- unchanged CognitiveExecutor and Windows concrete test behavior
