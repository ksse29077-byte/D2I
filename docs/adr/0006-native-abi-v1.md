# ADR 0006: Native ABI v1 And Host-Owned Buffers

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I runtime maintainers

## Context

Phase 6 requires Rust-native and C-compatible executor modules to cross one
stable boundary without coupling the package format to a model framework,
backend language, or vendor allocator. Native code is unsafe by nature, while
the rest of the Rust workspace forbids handwritten unsafe code.

## Decision

1. `d2i-ffi` is the only handwritten crate that permits unsafe code.
2. ABI v1 is a 64-bit C function table exported by `d2i_module_v1`.
3. The host verifies canonical path, regular-file type, size, SHA-256 allowlist,
   symbol, version, table size, identity, and required functions before use.
4. Rust owns input/output allocations and the opaque handle lifecycle. Modules
   receive synchronous borrowed views and may never free or retain them.
5. The byte-view hot path contains no JSON serialization and records explicit
   boundary-copy and host-allocation metrics.
6. Arrow C Data and DLPack views are optional borrowed adapters with no
   ownership transfer in v1.
7. In-process modules are trusted artifacts. Untrusted native execution is
   deferred until process isolation and hard resource controls exist.

## Consequences

- Rust and C modules execute through the same compact contract.
- A repeated host shutdown cannot destroy the same handle twice.
- Appending function-table fields can remain compatible; semantic or layout
  breaks require a new ABI version.
- Metadata checks cannot prevent a malicious in-process module from arbitrary
  memory corruption or transitive dependency loading.
- Mojo can be explored later as another ABI implementation without changing
  package metadata.
