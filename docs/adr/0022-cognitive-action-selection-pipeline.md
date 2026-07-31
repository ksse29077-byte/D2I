# ADR 0022: Cognitive Action Selection Pipeline v1

## Status

Accepted

## Context

Application Semantics v1 can produce schema-pinned Element Grounder input, and
Action Candidate Provider v1 proves a fixture oracle can become one
capability-bound Cognitive IR v1 `ActionProposal`. The production-facing Core
boundary still needs to validate an actual Element Grounder result, generate
multiple proposals, pass metadata to the standalone Plan Ranker, and reconnect
the selected ID/hash pair to the original proposal.

Two existing contracts cannot express that orchestration directly:

- a Cognitive IR v1 `ProposeAction` node fixes one capability, while ranking
  requires several capability candidates
- `CapabilityDescriptor` does not contain the version, schema, cost,
  likelihood, or trusted pre-admission metadata required by Plan Ranker v1

Cognitive IR v1, both standalone module contracts, and desktop policy and
activation boundaries are frozen for this work.

## Decision

Create the additive Core crate `d2i-action-selection`.

The crate:

- strictly mirrors and validates Element Grounder v1 output without linking
  the module implementation
- accepts candidates only after `unique_match`, exact observation lookup, kind
  agreement, and redaction, status-element, credential, and secret checks
- seals a `GroundedTargetBindingV1` that contains IDs and hashes but no fixture
  oracle, locator, selector, coordinate, handle, URL, raw input, or credential
- introduces `ActionSelectionContextV1` for an unbound `SelectCapability` plan
  node with a sorted, unique allowlist of at most 64 capabilities
- leaves the original `PlanGraph` immutable
- carries Plan Ranker-only metadata in sealed
  `CandidateRankingProfileV1`
- validates supplied `CandidateAdmissionProfileV1` gate statuses and evidence
  without generating, upgrading, or interpreting them as policy or activation
  authority
- generates deterministic capability-bound proposals and a canonical
  `ActionCandidateSetV1`
- emits the exact Plan Ranker v1 metadata payload plus an out-of-payload index
  back to proposal hashes
- validates externally returned Plan Ranker output with complete input
  coverage, exact ID/hash pairs, contiguous ranks, and exact gate reasons
- reconnects rank 1 to the unchanged original proposal
- emits `PolicyReadyActionV1` as read-only future policy input

Well-formed candidates whose capability is not selected or available may be
reported as structured exclusions. Invalid bindings, substituted hashes,
source/kind mismatches, stale lifecycle values, secrets, and malformed
profiles fail the entire request.

## Contract Resolution

`ActionSelectionContextV1` is additive and does not modify Cognitive IR v1. It
requires the current plan node to be `SelectCapability` with no
`capability_id`; the allowed candidates live in the sealed context.

`CandidateRankingProfileV1` supplies only metadata missing from the frozen
`CapabilityDescriptor`. `CandidateAdmissionProfileV1` is trusted
pre-admission evidence, not `PolicyDecision`, approval, `ActivationPermit`, or
execution authority. Every profile binds the exact proposal ID/hash,
capability binding hash, goal, generation, and observation hash.

## Alternatives

### Extend Cognitive IR v1

Rejected. Multi-candidate orchestration and module-specific ranking metadata
do not require a public IR migration.

### Link Standalone Module Implementations

Rejected. Core compiles module schemas and fixtures only in integration tests.
Loading and invocation remain future production integration work.

### Reuse The Fixture Oracle

Rejected. The new path consumes an actual Grounder result and keeps
`bridge_fixture_action_candidate` unchanged as an earlier test asset.

### Treat Ranker Gates As Policy Decisions

Rejected. The ranker receives supplied metadata and does not grant authority.
Actual policy, confirmation, and activation remain downstream.

## Security Consequences

- untrusted labels, values, matched features, and Grounder evidence never
  choose action kind, risk, gate status, cost, or likelihood
- candidate arguments use closed action variants and hash-only text/select
  inputs
- Plan Ranker receives no proposal arguments, semantic text, observed values,
  locators, credentials, permits, or decisions
- missing output candidates, arbitrary fallback selection, ID/hash
  substitution, stale sequences, and profile mutation fail closed
- strict JSON parsing rejects duplicate and unknown fields
- canonical SHA-256 uses lowercase output and omits each artifact's own hash
- the crate performs no filesystem, process, network, UI, browser, policy,
  activation, approval, or action side effect

## Compatibility And Rollback

The change adds one Core crate, schema, ADR, and documentation. Cognitive IR
v1, Module Contract v1, Module SDK, Element Grounder, Plan Ranker, package
format, Runtime ABI, desktop policy, activation, adapters, and executor flows
remain unchanged. Removing the new additive assets restores the prior state.
