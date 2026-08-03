# ADR 0018: Bound Cognitive Verification Contract v2

- Status: Accepted for implementation
- Date: 2026-07-29
- Decision owner: D2I cognitive core owner
- Tracking: Core RFC #19; blocked Verifier module #18

## Context

Cognitive IR v1 establishes a one-step execute, reobserve, and verify loop, but
its verifier boundary cannot independently prove that an execution belongs to
the supplied proposal or that an observation was collected after that
execution attempt. `ActionExecution` has no execution, proposal, goal, plan, or
source-observation identifiers. `PostconditionVerifier` receives no goal or
pre-execution observation.

The v1 result also uses a Boolean per-postcondition outcome. It cannot preserve
the difference between a failed comparison, insufficient evidence, an
unsupported comparison, and an unsafe state. The open Verifier module must not
invent these lifecycle and verdict semantics inside a module-local schema.

## Decision

Add Cognitive Verification Contract v2 as an additive Core contract. Cognitive
IR v1 remains unchanged.

The v2 contract consists of:

- `VerificationGoalSpecV2`;
- `VerificationActionProposalV2`;
- `BoundActionExecutionV2`;
- `VerificationRequestV2`;
- `VerifiablePostconditionV2`;
- `VerificationResultV2`;
- `PostconditionVerifierV2`;
- `schemas/cognitive/cognitive-verification-v2.schema.json`.

The contract composes existing validated Cognitive IR v1
`ObservationSnapshot` values. It does not add observation authority or modify
an observation provider.

## Lifecycle Binding

A verification request contains the original goal, proposal, execution
record, source observation, and post-execution observation. Validation requires
all of the following:

1. Goal IDs match across the goal, proposal, and execution.
2. Proposal IDs match across the proposal and execution.
3. Plan generation IDs match across the proposal and execution.
4. Source observation ID, stable hash, and sequence match across the proposal,
   execution, and source snapshot.
5. The proposal validity sequence includes its source observation.
6. The post-execution observation has a distinct observation ID and a sequence
   strictly greater than the source observation sequence.
7. Observation source kind and target binding remain identical.
8. Both snapshots pass their existing state-hash validation.

Sequence establishes collection order. State hash establishes stable observable
content. Observation ID prevents reuse of the same snapshot record. Target
binding prevents a result from silently switching to another process, window,
session, origin, file, or fixture target.

## Verifiable Postconditions

The contract does not interpret arbitrary `target_state` strings. A v2
postcondition identifies one element and one frozen observable field:

- `element_exists`;
- `element_value`;
- `element_current_value`;
- `element_kind`.

The expected value remains typed JSON data. Supported comparison semantics are:

- `element_exists`: `equals` with a Boolean;
- `element_kind`: `equals` or `not_equals` with a string;
- `element_value`: `equals`, `not_equals`, string `contains`, Boolean `exists`,
  and integer `greater_or_equal` or `less_or_equal`.
- `element_current_value`: the same comparisons over the exact typed
  `value.current_value` member, without widening to sibling UI metadata.

Ordered floating-point comparison is unsupported to avoid cross-platform
rounding policy. Missing values are inconclusive, not failed, except an
explicit `element_exists` comparison. Duplicate matching element IDs are
conflicting evidence and are inconclusive.

UI, Web, document, email, labels, and values remain data. Observation text
cannot introduce a criterion, change an operator, or declare itself successful.

## Verdict And Progress Laws

Executor status and action verification are separate fields. A successful
executor status cannot produce a passed action verdict unless every required
action postcondition passes and no unexpected change is reported.

The terminal verdicts are:

- `passed`: every required observable condition passed;
- `failed`: a required supported comparison returned false;
- `inconclusive`: evidence was missing or conflicting;
- `unsupported`: the execution or comparison is outside this contract;
- `unsafe`: an unexpected or unsafe observable change prevents a pass.

For a successful execution, required verdict priority is `unsafe`,
`unsupported`, `inconclusive`, `failed`, then `passed`. Unsupported executor
status produces `unsupported`; failed, denied, or timed-out execution produces
`failed`.

Goal progress is derived independently:

- `complete` only when the action passed and all required goal criteria passed;
- `in_progress` when the action passed but a supported goal criterion failed;
- `blocked` when the action did not pass or required goal evidence is
  inconclusive, unsupported, or unsafe;
- `not_started` is invalid after an execution attempt.

Deterministic rule verification declares confidence `not_applicable`.

## Module Contract Mapping

Module Contract v1 remains unchanged. A verifier invocation carries one
serialized `VerificationRequestV2` payload. The adapter must require:

- envelope `goal_id` equals request `goal.goal_id`;
- envelope `source_observation_hash` equals
  `request.fresh_observation.state_hash`;
- envelope `plan_generation_id` equals
  `request.proposal.plan_generation_id`;
- the SDK replay invocation hash covers the complete request payload.

The module result payload is `VerificationResultV2`. Envelope provenance,
canonical output hash, replay metadata, evidence, and warnings remain mandatory
and do not replace the result's lifecycle and provenance fields.

A future runtime adapter may implement `PostconditionVerifierV2` by invoking a
conforming module. It receives no action executor or host authority. Production
module loading is not added by this decision.

## Compatibility

- Cognitive IR v1 types, schema, executor laws, and fixtures are unchanged.
- Strict v1 readers continue to reject schema version 2 values.
- Strict v2 readers reject v1 values and unknown fields.
- No automatic v1-to-v2 conversion exists because absent execution and
  observation bindings cannot be reconstructed safely.
- Package format, Runtime ABI, policy, activation, audit, Windows adapters, and
  immutable production packages are unchanged.

## Security Consequences

The new contract fails closed on stale observations, reused observation
identities, goal/proposal/execution/plan substitution, state-hash mismatch,
target switching, result binding mismatch, duplicate evidence, unsupported
comparisons, resource overrun, and unknown fields.

The contract is side-effect-free. It grants no execution, confirmation,
policy, activation, audit, network, filesystem, process, UI, credential,
clipboard, or persistent-storage authority.

## Rejected Alternatives

### Modify Cognitive IR v1 in place

Rejected because strict v1 readers reject unknown fields and the additions
change safety decisions.

### Parse arbitrary target strings inside the Verifier module

Rejected because it creates an unreviewed parallel Core contract.

### Trust executor success

Rejected because an accepted action call does not prove the expected state
change occurred.

### Put lifecycle IDs only in module-local schemas

Rejected because the runtime boundary would still have no shared mapping or
validation law.

### Change the package format or Runtime ABI

Rejected because the development/runtime cognitive contract does not require
production package embedding.

## Validation

- strict Rust and JSON Schema round trips;
- unknown field and wrong version rejection;
- goal, plan, proposal, execution, and observation mismatch rejection;
- stale and reused observation rejection;
- target-binding and state-hash validation;
- execution-success/postcondition-failure separation;
- action-success/goal-incomplete separation;
- conflicting and unsupported comparison behavior;
- deterministic canonical request and result hashes;
- existing Cognitive IR v1 and workspace regression tests.
