# Rust and Mojo Interoperability Roadmap

The module contract is language-neutral. Rust is the v1 reference SDK and
runner. A future Mojo worker must use the same invocation/result envelopes,
JSON Schema, canonical JSON, SHA-256, stable errors, trust semantics, resource
limits, and deterministic replay metadata.

Not defined in v1:

- a Mojo toolchain version or package dependency
- a concrete C ABI or IPC protocol
- native artifact discovery and loading
- process sandbox creation and termination
- cross-language memory ownership or zero-copy buffers
- floating-point canonicalization across platforms
- production activation, policy, audit, or package bindings

Before implementation, an RFC must specify ABI/IPC version negotiation,
buffer ownership, cancellation, hard timeout, process isolation, resource
accounting, crash mapping, schema transfer, artifact attestation, and Windows
security integration.

Floating-point modules need an explicit tolerance and platform-determinism
policy. Zero-copy is a later measured optimization; it may not weaken schema,
hash, provenance, or isolation checks.
