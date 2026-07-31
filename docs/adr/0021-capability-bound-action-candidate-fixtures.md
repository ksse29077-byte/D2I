# ADR 0021: Capability-Bound Action Candidate Fixtures

## Status

Accepted

## Context

Application Semantics v1 can bind an immutable semantic target to a validated
UIA or Web observation and can produce Element Grounder fixtures. The next
boundary must prove that a uniquely grounded fixture target can become a valid
Cognitive IR v1 `ActionProposal` without treating observed content as
authority or granting a module access to an adapter.

Cognitive IR v1 is frozen. Its `ActionProposal`, `CapabilityDescriptor`, and
the runtime `ActionCandidateProvider` trait already express the required
runtime handoff. However, `ActionProposal.arguments` is intentionally generic,
and `CapabilityDescriptor` does not carry application-target or observed-kind
bindings. A stricter additive bridge is required before an action-candidate
module can be implemented.

## Decision

Create the additive Core crate `d2i-action-candidates`.

The crate:

- leaves Cognitive IR v1, Module Contract v1, and `ActionCandidateProvider`
  unchanged
- seals an `ActionCapabilityBinding` over one Application Pack hash, semantic
  target, observation source, sorted observed-element kinds, closed action
  kind, and exact `CapabilityDescriptor`
- accepts only six closed fixture actions: UIA invoke, set text, toggle and
  WebDriver click, type text, select
- carries text/select values by SHA-256 only
- requires exact goal, world-state, observation, plan-generation, current
  plan-node, capability-registry, grounding-case, and element-kind bindings
- copies risk, confirmation, and capability identity from the trusted
  descriptor rather than caller or observed content
- emits an existing Cognitive IR v1 `ActionProposal` with strict typed
  arguments, canonical hashes, safe identifier/hash evidence, and validity
  limited to the source observation sequence
- remains deterministic, side-effect-free, offline, and fixture-only

The fixture grounding oracle is allowed only because it remains outside an
Element Grounder module payload and is already validated by Application
Semantics v1. A future production adapter must consume a validated unique
grounding result instead of this oracle.

## Contract Review

No Core contract migration is required:

- `ActionProposal v1` remains the action-candidate output.
- `CapabilityDescriptor v1` remains the Registry record.
- `ActionCandidateProvider::next_candidate` remains the runtime trait.
- `ModuleResultEnvelope v1` can carry a future module-owned candidate payload.
- The Module SDK public API and Cognitive IR JSON Schema remain unchanged.

The additive binding contract supplies fixture-specific strictness that does
not belong in universal Cognitive IR. A future production capability registry
may require richer input-schema, activation-scope, credential, network, and
adapter metadata, but that is not inferred or added in this change.

## Alternatives

### Extend Cognitive IR v1

Rejected. Application target and observed-element kind bindings are not
universal cognitive primitives, and a frozen Core contract migration is not
needed for fixture evidence.

### Add Actions To Application Packs

Rejected. Application packs remain semantic vocabulary without executable
authority.

### Emit `DesktopOperation` Directly

Rejected. A cognitive proposal must still pass policy, activation, approval,
and trusted adapter mapping. The bridge never creates executable locators,
coordinates, handles, or desktop operations.

### Implement The Standalone Provider Module Now

Rejected for this task. The contract and fixture bridge must stabilize before
module implementation and conformance evaluation.

## Security Consequences

- observed labels, values, locator hints, and untrusted instructions never
  enter proposal authority fields
- raw text action values and secret-like postconditions are rejected
- unknown fields and arbitrary argument keys are rejected
- unavailable, stale, substituted, irreversible, or plan-unbound
  capabilities fail closed
- proposal risk and confirmation cannot be lowered independently of the
  capability descriptor
- no policy, activation, approval, adapter, filesystem, process, UI, browser,
  credential, clipboard, or network authority is introduced

## Compatibility And Rollback

The change is additive. Removing the new crate, schema, documentation, and
desktop re-export restores the prior state. Application Semantics v1,
Cognitive IR v1, Module Contract v1, package data, Runtime ABI, Windows
bindings, and standalone modules require no migration.
