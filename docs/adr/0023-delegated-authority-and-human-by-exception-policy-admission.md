# ADR 0023: Delegated Authority and Human-by-Exception Cognitive Policy Admission

## Status

Accepted

## Context

`PolicyReadyActionV1` seals an exact selected action but intentionally contains
no policy decision, approval, activation token, adapter handle, or execution
authority. The next trusted execution stage needs a deterministic answer to
four separate questions:

1. Is the action within delegated organizational authority?
2. Does a trusted policy snapshot allow, deny, or escalate it?
3. Is confirmation required and, if so, is one exact short-lived grant valid?
4. Does a fresh read-only activation projection make the capability eligible?

Candidate admission gates and Plan Ranker output cannot answer these questions.
UI, Web, document, or model text is untrusted and cannot supply policy facts.
The complete Role Contract, production policy service, user authentication UI,
and Windows activation consumption are later boundaries.

## Decision

Add the side-effect-free Core crate `d2i-policy-admission`.

The crate seals:

- `DelegatedAuthorityContextV1`, a minimal future Role Contract projection
- `TrustedPolicySnapshotV1`, fixture-grade trusted policy data
- `PolicyEvaluationRequestV1`, including the exact `PolicyReadyActionV1`,
  `GoalSpec`, duplicated lifecycle bindings, and canonical hashes
- `PolicyDecisionV1` with closed outcomes and reason codes
- `ConfirmationChallengeV1` and trusted `ConfirmationGrantV1`
- a bounded in-memory `GrantConsumptionLedgerV1`
- `ActivationEligibilityContextV1`, a read-only projection of runtime binding
  and activation-ledger state
- `CognitiveActivationAdmissionV1`, input to the next trusted execution stage

All time, nonce hashes, IDs, expected runtime binding, and expected ledger head
are caller inputs. The crate creates no wall-clock values, randomness, process
identity, filesystem state, network request, UI action, adapter, or token.

## Decision Matrix

Rules are evaluated fail-closed in this order:

1. Exact binding mismatch, expired authority/policy, policy identity mismatch,
   forbidden capability/target, and unsupported irreversible action deny.
2. High criticality, mandatory escalation, unknown policy facts, unknown risk
   policy, scope outside the role, capability outside authority, and risk above
   the confirmable ceiling escalate.
3. Goal `always`/risky policy, proposal-required confirmation, policy-mandatory
   confirmation, confirmation-capability membership, or risk above the
   autonomous ceiling but within the confirmable ceiling requires confirmation.
4. Only an allowed autonomous capability within the autonomous risk ceiling
   and complete trusted policy facts may allow autonomously.

Therefore risk above the autonomous ceiling but not above the confirmable
ceiling requires confirmation. Risk above the confirmable ceiling escalates.
High criticality always escalates in v1. Unknown never allows.

`deny` means a known prohibition or invalid/stale sealed input. `escalate`
means the current role lacks authority or trusted facts and an organizational
decision is required. Confirmation cannot change either outcome.

## Human-by-Exception

Routine reversible actions within delegated authority can proceed to the next
activation boundary without per-action human approval. Legal, irreversible,
high-criticality, ambiguous, policy-unknown, or out-of-authority work is
confirmed or escalated. This removes routine approval touches without weakening
execution trust.

## Confirmation

A challenge exists only for `require_confirmation`. It binds the exact
decision, action, proposal, actor, role, organization, capability, target,
risk, nonce hash, and a maximum five-minute interval.

A grant is trusted input from a future authenticated boundary. It must match the
challenge, action, identity, organization, and interval exactly. A bounded
in-memory ledger consumes `one_time_use_id` once within the current artifact
lifecycle. Durable cross-process and restart-safe grant consumption remains the
responsibility of Trusted Action Execution Binding v1.

## Activation

`ActivationEligibilityContextV1` contains no adapter handle or one-shot token.
It seals organization, application, integration, runtime binding, adapter kind,
activation scope, ledger chain head, capability binding, and current
observation.

`CognitiveActivationAdmissionV1` can be created only from:

- `allow_autonomous`, or
- `require_confirmation` plus an exact active challenge and unconsumed grant.

It remains data. It cannot instantiate an adapter or bypass the Windows
activation ledger. Trusted Action Execution Binding v1 must combine it with an
actual one-shot `ActivatedWindowsBinding`.

## Compatibility

An additive `AuditOutcomeProjectionV1` is JSON-compatible with the existing
Desktop `AuditOutcome`. It exists for compatibility testing and audit
presentation only. The production `CognitiveExecutor`, `ActionPolicyEvaluator`,
and `ActivationGate` are not connected to the new crate in this change, and
`allowed=true` is not redefined as adapter authority.

Cognitive IR v1, Action Selection Pipeline v1, Element Grounder, Plan Ranker,
Module Contract, Module SDK, Runtime ABI, Windows activation ledger, package
format, and existing Desktop execution order remain unchanged.

## Alternatives

### Extend Cognitive IR v1

Rejected. Delegated authority and policy admission are downstream of stable
planning IR and can remain additive.

### Treat Candidate Admission Gates as Policy

Rejected. Ranker metadata is not a trusted policy decision and has no current
organization or authority state.

### Connect Directly to Windows Activation

Rejected. Policy admission and one-shot platform activation are distinct trust
boundaries. Joining them here would let a policy record become execution
authority.

### Build Full Role Contract or Policy Service

Rejected for v1. Narrow projections prove the contract while Work Track and
production policy services remain explicitly out of scope.

## Security Consequences

- strict JSON rejects duplicate and unknown fields
- all strings and collections are bounded
- set-like arrays are sorted and duplicate-free
- lowercase SHA-256 omits each artifact's own hash and recursively sorts keys
- Goal, Plan generation, Observation, proposal, selection, capability,
  application, and binding substitutions fail closed
- raw secrets, credentials, locators, selectors, coordinates, adapter handles,
  activation tokens, and absolute paths are rejected
- no fallback can turn deny, escalate, or unknown into allow
- no filesystem, process, network, UI, browser, activation, or adapter side
  effect exists

## Rollback

The change is additive. Removing the new crate, schema, ADR, documentation, and
dev-only Desktop compatibility test restores the previous runtime behavior.
