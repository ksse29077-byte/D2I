# ADR 0020: Application Semantics And Observation Fixture Bridge

## Status

Accepted

## Context

The Windows read-only Observation Plane already emits valid Cognitive IR v1
snapshots, and Element Grounder v1 already ranks observed elements. The missing
boundary was an application-owned semantic vocabulary and a deterministic way
to prove that real or synthetic UIA/Web observations can become valid Element
Grounder inputs.

Linking a standalone module into `d2i-desktop`, adding application fields to
Cognitive IR v1, or embedding executable selectors in semantic metadata would
violate existing ownership and authority boundaries.

## Decision

Create the additive Core crate `d2i-application-semantics`.

The crate:

- owns strict Application Pack and observation-fixture contracts
- verifies sealed pack, source, target-binding, and observation hashes
- consumes the existing Cognitive IR v1 `ObservationSnapshot`
- emits a version-pinned Element Grounder v1 JSON payload
- validates fixture oracles outside the module payload
- performs no module invocation or action execution

Application packs use exact target-binding comparisons and contain only
semantic vocabulary. They do not contain executable locators or authority.

Core compatibility tests compile the standalone module's input schema from its
repository artifact. Core does not add a Cargo dependency on the module
implementation.

## Rationale

A separate pure crate keeps application semantics reusable across UIA and Web
without moving platform records into Cognitive IR. Keeping the fixture oracle
outside the payload prevents a test answer from leaking into module input.
Exact binding and canonical hashes make stale or substituted application
metadata observable and fail closed.

## Alternatives

### Extend Cognitive IR v1

Rejected. Application vocabulary is not a universal cognitive primitive, and
changing Cognitive IR would force unnecessary module and schema migration.

### Link Element Grounder Into Core

Rejected. Repository Decoupling v1 requires standalone module implementations
to remain outside the Core dependency graph.

### Store Executable Locators In Application Packs

Rejected for v1. A semantic pack does not grant action authority. Executable
locator selection belongs to a future capability- and policy-bound action
proposal contract.

### Let Fixtures Supply A State Hash

Rejected. The bridge computes the Cognitive IR hash so stale or hand-edited
fixtures cannot declare their own validity.

## Security Consequences

- untrusted observed text remains data
- redactions and trust labels are preserved
- raw secret-like pack/request metadata is rejected
- duplicate, absent, ambiguous, stale, and tampered bindings fail closed
- no adapter, network, filesystem, process, browser, or action authority is
  introduced

## Compatibility And Rollback

The change is additive and can be rolled back by removing the new crate,
schema, documentation, and `d2i-desktop` re-export. Cognitive IR v1, Module
Contract v1, Element Grounder v1, package data, and Runtime ABI artifacts need
no migration.
