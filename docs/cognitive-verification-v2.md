# Cognitive Verification Contract v2

Cognitive Verification Contract v2 is the side-effect-free data boundary for
checking one action execution against a fresh observation and the original
goal contract.

It is additive. Cognitive IR v1 and its `CognitiveExecutor` remain unchanged.

## Data Flow

```text
VerificationGoalSpecV2
  + VerificationActionProposalV2
  + BoundActionExecutionV2
  + source ObservationSnapshot v1
  + fresh ObservationSnapshot v1
  -> VerificationRequestV2
  -> PostconditionVerifierV2
  -> VerificationResultV2
```

The verifier does not execute, observe, retry, recover, plan, approve, activate,
audit, or access the host.

## Binding Requirements

`VerificationRequestV2::validate` requires:

- one matching goal ID;
- one matching proposal ID;
- one matching plan generation ID;
- one matching source observation ID, hash, and sequence;
- a distinct fresh observation ID;
- a fresh sequence greater than the source sequence;
- unchanged observation source kind and target binding;
- valid source and fresh state hashes.

The stable state hash intentionally ignores observation identity and sequence.
Freshness therefore requires all three independent checks: sequence ordering,
distinct observation ID, and stable target binding.

## Supported Facts

`VerifiablePostconditionV2` can address:

| Field | Supported operation | Expected type |
| --- | --- | --- |
| `element_exists` | `equals` | Boolean |
| `element_kind` | `equals`, `not_equals` | string |
| `element_value` | `equals`, `not_equals` | any JSON value |
| `element_value` | `contains` | string |
| `element_value` | `exists` | Boolean |
| `element_value` | `greater_or_equal`, `less_or_equal` | integer |
| `element_current_value` | same as `element_value` | any JSON value |

`element_current_value` addresses only the typed `current_value` member of an
element value. It supports exact text-state verification without accidentally
making volatile UIA focus metadata part of the postcondition.

Missing evidence is `inconclusive`. Duplicate matching element IDs are
conflicting evidence and are also `inconclusive`. Decimal ordered comparisons
are `unsupported`; integer comparison avoids platform floating-point policy.

The verifier compares only criteria supplied by the typed goal and proposal.
Text inside an observation cannot create a rule or force a successful verdict.

## Result Semantics

`execution_status` is copied from the executor. `action_verdict` is an
independent postcondition decision.

For required action postconditions, verdict priority is:

```text
unsafe > unsupported > inconclusive > failed > passed
```

An action passes only when execution succeeded, every required action
postcondition passed, and `unexpected_changes` is empty.

Goal progress is separate:

- `complete`: action passed and every required goal criterion passed;
- `in_progress`: action passed but at least one supported goal criterion failed;
- `blocked`: action did not pass, or required goal evidence is unavailable,
  conflicting, unsupported, or unsafe.

Deterministic verification uses `confidence = "not_applicable"`.

## Module Envelope Mapping

The v2 payload uses Module Contract v1 without changing its envelope:

| Envelope field | Required request match |
| --- | --- |
| `goal_id` | `request.goal.goal_id` |
| `source_observation_hash` | `request.fresh_observation.state_hash` |
| `plan_generation_id` | `request.proposal.plan_generation_id` |

The complete payload is covered by the envelope invocation hash. The result
payload is `VerificationResultV2`; the Module Result Envelope continues to
carry canonical output hash, replay metadata, resource usage, timings,
provenance, evidence, and warnings.

Production module loading and package/ABI mapping remain out of scope.

## Canonical Hashes

`VerificationRequestV2::canonical_hash` and
`VerificationResultV2::canonical_hash_against` use the repository's stable
JSON/SHA-256 rule. No wall-clock time, random value, platform handle, or
unordered map contributes to the hash.

## Limits

The Core contract bounds:

- postconditions and result records: 256 each;
- evidence entries: 256;
- warning entries: 128;
- unexpected-change entries: 128;
- serialized values: the existing 2 MiB Cognitive IR artifact bound;
- observation elements: the existing 10,000 element bound.

A module manifest may set lower limits but cannot exceed its declared resource
budget.

## Compatibility

There is no implicit v1-to-v2 migration. V1 lacks the execution and source
observation bindings needed to construct a safe v2 request. Callers must
produce v2 values at the point where those bindings are known.

See ADR 0018 for the decision, security analysis, and rejected alternatives.
