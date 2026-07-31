# Cognitive Action Selection Pipeline v1

## Purpose

Cognitive Action Selection Pipeline v1 is the deterministic Core boundary
from actual Element Grounder output to non-authoritative future policy input:

```text
ElementGroundingResultV1
  -> ValidatedGroundingSelectionV1
  -> ActionCandidateSetV1
  -> PlanRankerInputBridgeV1
  -> externally produced PlanRankingOutputV1
  -> ValidatedPlanRankingV1
  -> BoundSelectedActionV1
  -> PolicyReadyActionV1
```

The implementation is:

- `crates/d2i-action-selection`
- `schemas/cognitive/action-selection-pipeline-v1.schema.json`
- ADR 0022

The crate never invokes Element Grounder or Plan Ranker. It has no dependency
on a standalone module crate, Windows, UIA, WebDriver, policy, activation, or
an adapter.

## Grounder Result

`ElementGroundingResultV1` is a strict mirror of the actual module output.
Only `unique_match` may select an element. `ambiguous`, `not_found`, and
`unsupported` validate as terminal no-candidate outcomes.

A unique result must bind the exact goal, plan generation, and observation
hash. The selected ID must exist exactly once in both the observation and
Grounder candidates, and the kind and trust labels must agree. Redacted,
status, credential, and secret-like elements fail closed.

The module's labels, matched features, and evidence remain data. They are not
copied into action arguments or authority fields.

## Grounded Target

`GroundedTargetBindingV1` seals:

- Application Pack and Grounder result hashes
- observation ID, hash, sequence, and source kind
- goal and plan generation
- semantic target
- selected element ID and kind
- trust labels and bounded evidence IDs

It deliberately excludes fixture case/oracle fields, selectors, locators,
Automation IDs, runtime IDs, coordinates, WebDriver and COM handles, URLs,
raw text, credentials, policy decisions, approvals, and activation permits.

## Selection Context

`ActionSelectionContextV1` preserves Cognitive IR v1 unchanged. It binds an
existing `SelectCapability` node whose `capability_id` is absent and supplies
a sorted, unique list of 1 to 64 allowed capability IDs. Goal, generation, and
current step must agree with `GoalSpec`, `WorldState`, and `PlanGraph`.

Candidate generation never edits the plan.

## Candidate Profiles

`CandidateRankingProfileV1` supplies Plan Ranker metadata not present in the
frozen `CapabilityDescriptor`:

- capability semantic version
- input and output schema identities and versions
- normalized cost millionths
- success likelihood millionths

`CandidateAdmissionProfileV1` carries the externally supplied 11 hard-gate
statuses and bounded evidence for every gate. It is not a policy result,
activation permit, approval, or execution authority. The pipeline validates
the profile but does not fabricate or upgrade a gate.

Both profiles bind the proposal ID/hash, capability and binding hash, goal,
plan generation, and source observation hash.

## Candidate Generation

`build_grounded_action_proposal` deterministically creates the proposal that
profiles must bind. `build_grounded_action_candidate` verifies those sealed
profiles and creates one record.
`build_grounded_action_candidates` creates the canonical set.

Every candidate requires:

- the same pack, target, observation, Grounder result, goal, world, and plan
- exact source kind, selected element kind, action kind, operation, and
  capability binding
- a capability admitted by selection context and WorldState
- reversible semantics
- at least one expected postcondition
- finite confidence
- no raw secret or executable locator

Candidate records are ordered by `candidate_hash`, then `candidate_id`.
Duplicate IDs or hashes and more than 64 candidates fail closed. An input
order change does not change the candidate set or hash.

An unavailable or unallowed otherwise well-formed capability may produce a
bounded `RejectedCandidateBuildV1`. If all candidates are excluded, the
result is structured `no_candidates`. Integrity and safety failures never
become exclusions.

## Plan Ranker Bridge

`PlanRankerInputBridgeV1.payload` exactly matches the Plan Ranker v1 input
schema. It contains bounded metadata only. Proposal arguments, semantic text,
observed labels/values, locators, credentials, policy decisions, and
activation permits are absent.

`candidate_index` remains outside the module payload and maps each exact
candidate ID/hash pair back to the original proposal and profile hashes.

Core returns the payload to an external caller. It does not load or invoke the
module.

## Ranker Result

`PlanRankingOutputV1` strictly mirrors the actual output schema. Validation
requires:

- schema and ranking policy version 1
- exact ranked/no-eligible selected/null rules
- contiguous ranks beginning at 1
- selected ID/hash equal to rank 1
- each input candidate present exactly once in ranked or rejected output
- no unknown, omitted, duplicated, overlapping, or ID/hash-substituted entry
- ranked cost and likelihood equal to the sealed profile
- rejected reasons equal to all and only non-passed supplied gates in contract
  order

The omission policy is fail closed. Plan Ranker cannot change or reconstruct a
proposal.

## Selected And Policy-Ready Actions

`BoundSelectedActionV1` is available only for a validated ranked result. It
finds exactly one original candidate by ID/hash and revalidates proposal,
profile, goal, world, plan, observation, target, element, capability, and
sequence bindings.

`PolicyReadyActionV1` is a read-only projection for a future policy boundary.
It copies exact risk, reversibility, confirmation requirement, expected
postconditions, and proposal identity. Its name does not imply approval or
execution permission.

It contains no `PolicyDecision`, approval signature, activation permit,
adapter handle, executable locator, raw text bytes, credential, or execution
authority.

## Canonical Hashing

Objects use compact canonical JSON with recursively sorted keys. Set-like
arrays are sorted before sealing; Plan Ranker ranked order is preserved.
Self-hashes omit their own field. SHA-256 strings are lowercase and prefixed
with `sha256:`.

The pipeline seals Grounder result, grounded target, selection context,
ranking and admission profiles, candidate, candidate set, Ranker input,
Ranker output validation, selected action, policy input, and policy-ready
identities.

Strict parsing rejects duplicate keys, unknown fields, trailing JSON,
excessive size, nesting, and node count. Rust validation rejects non-finite
numbers.

## Boundary

The pipeline performs no module invocation, loader discovery, registry access,
policy evaluation, confirmation request, activation, desktop mapping,
prepare/commit, UI action, re-observation, verification, recovery, replan,
filesystem access, process launch, network access, or Runtime ABI/package
change.

The next contract is Cognitive Policy Admission v1. It is not implemented by
this pipeline.
