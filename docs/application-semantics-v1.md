# Application Semantics Contract v1

## Purpose

Application Semantics v1 connects an immutable application-specific vocabulary
to an already validated Cognitive IR v1 `ObservationSnapshot`. It produces the
module-owned JSON payload accepted by Element Grounder v1 without loading or
linking the module implementation into Core.

The contract is implemented by `d2i-application-semantics` and defined by:

- `schemas/cognitive/application-semantics-v1.schema.json`
- `crates/d2i-application-semantics`
- ADR 0020

## Boundaries

The crate is deterministic and side-effect-free. It has no adapter, policy,
activation, audit, filesystem, process, browser, network, credential, module
loader, or execution authority.

It consumes only:

- an immutable `ApplicationPack`
- a valid Cognitive IR v1 `ObservationSnapshot`
- a bounded `ElementGrounderBridgeRequest`

It emits a JSON payload identified as `element-grounding-input-v1`, version 1.
The payload is data. Producing it does not invoke a module or create an action.

## ApplicationPack

An application pack contains:

- schema, pack, application, version, and provenance identity
- allowed observation sources (`uia` and/or `web_driver`)
- exact required entries from the observation target binding
- one or more bounded semantic targets
- a canonical SHA-256 digest

Each semantic target declares a stable target ID, canonical label, aliases,
expected observed kinds, and required, excluded, or contextual terms.

`pack_sha256` is calculated over compact deterministic JSON with the
`pack_sha256` member omitted. Rust maps and sets use stable ordering. Any field
change invalidates the sealed pack.

Application packs do not contain executable locators, action arguments,
credentials, approval evidence, or adapter handles.

## Observation Binding

Before producing a payload, the bridge:

1. validates the sealed application pack
2. validates the Cognitive IR observation and its `state_hash`
3. requires the observation source to be allowed by the pack
4. exactly compares every required target-binding entry
5. resolves exactly one semantic target from the pack
6. binds goal, observation, plan generation, trust labels, and replay metadata
7. computes a stable payload hash

Missing or changed bindings, stale observation hashes, unsupported source
kinds, duplicate targets, unknown fields, and oversized inputs fail closed.

## Element Grounder Bridge

The generated payload preserves the source observation without rewriting its
elements, trust labels, redactions, target binding, or provenance. Pack aliases
and context terms are deduplicated and sorted before they are added as bounded
context terms.

The bridge does not include the fixture oracle in the module payload.
`expected_element_id` exists only in the surrounding test artifact. Element
Grounder must independently derive its result from the supplied observation.

Core tests compile the standalone Element Grounder v1 input schema and validate
every generated payload against it. Core has no Cargo dependency on the module
implementation.

## ObservationFixture

`ObservationFixture` is a synthetic authoring contract for UIA and Web
observations. It contains Cognitive IR elements, redactions, provenance, and
bounded grounding cases but no declared state hash. The bridge computes and
validates the Cognitive IR v1 hash before any case is produced.

Each grounding case carries:

- stable case and semantic-target IDs
- bounded target text
- an expected observed element ID retained outside the module payload
- a maximum candidate count from 1 through 64

An oracle must name exactly one existing, non-status, non-redacted element.
Duplicate, absent, redacted, or raw-secret-bearing oracle elements fail closed.

## Trust And Secrets

Observed UI or web text remains data even when it resembles an instruction.
The original `observed_ui_state`, `untrusted_web_content`, and
`untrusted_document_content` labels are preserved.

The bridge never promotes an observation to authenticated instruction,
approved policy, or executable authority. Existing redactions remain intact.
Pack metadata, semantic terms, request text, and evidence reject raw
secret-like assignments and authorization material.

## Compatibility

Application Semantics v1 is additive:

- Cognitive IR v1 is unchanged.
- Cognitive Module Contract v1 is unchanged.
- Module SDK public APIs are unchanged.
- Element Grounder v1 schemas and implementation are unchanged.
- Runtime ABI and package format are unchanged.
- Windows observation schemas, audit, activation, and redaction behavior are
  unchanged. The read-only loopback WebDriver observation transport retries
  only transient connection or incomplete-framing failures, at most three
  attempts inside the existing observation deadline. Mutation commands never
  enter this retry path.

A future incompatible pack, bridge, hashing, trust, or payload mapping change
requires a new contract version.
