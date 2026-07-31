# Cognitive Policy Admission v1

## Purpose

Cognitive Policy Admission resolves Human-by-exception policy around one exact
`PolicyReadyActionV1`. It is deterministic Core data processing and performs no
action.

```text
PolicyReadyActionV1
+ DelegatedAuthorityContextV1
+ TrustedPolicySnapshotV1
+ Confirmation state
+ ActivationEligibilityContextV1
  -> PolicyDecisionV1
  -> optional ConfirmationChallengeV1
  -> optional validated ConfirmationGrantV1
  -> CognitiveActivationAdmissionV1
```

The authoritative machine-readable contract is
`schemas/cognitive/cognitive-policy-admission-v1.schema.json`.

## Trust Boundaries

- Model, UI, Web, and document output is not policy.
- Plan Ranker and `CandidateAdmissionProfileV1` are not policy authorities.
- Authority is a bounded projection of a future Role Contract, not a permit.
- A policy decision does not authorize an adapter.
- A challenge is a request for confirmation, not approval.
- A grant can release only its exact `require_confirmation` decision.
- Eligibility is read-only evidence, not Windows activation.
- Admission is data for Trusted Action Execution Binding v1, not an adapter
  handle or one-shot activation token.

## Delegated Authority

`DelegatedAuthorityContextV1` binds organization, actor, role, policy set,
allowed/forbidden/autonomous/confirmation capability sets, risk ceilings,
application pack, integrations, strict semantic scope, validity, evidence, and
canonical hash.

All set-like arrays are sorted and duplicate-free. Autonomous and confirmation
sets are subsets of allowed capabilities and disjoint from forbidden
capabilities. The autonomous ceiling cannot exceed the confirmable ceiling.

## Trusted Policy

`TrustedPolicySnapshotV1` is supplied by a trusted fixture boundary. It records
policy identity, organization, effective or unknown state, allowed risk
classes, denied/confirmation/escalation capabilities, forbidden targets,
validity, evidence, and hash.

Unknown state and a risk absent from the trusted allow set never allow
autonomous execution.

## Exact Request

`PolicyEvaluationRequestV1` embeds the full `PolicyReadyActionV1`, `GoalSpec`,
authority, and policy snapshot. It duplicates and seals policy-ready, selection,
proposal, Goal, plan generation, observation hash/sequence, capability,
application pack, semantic target, capability binding, risk, and confirmation
bindings. Substitution is denied or rejected.

## Outcomes

| Outcome | Meaning |
| --- | --- |
| `allow_autonomous` | Delegated, policy-allowed, autonomous capability, within autonomous risk ceiling |
| `require_confirmation` | Not forbidden, within confirmable scope, but Goal/proposal/policy/authority requires confirmation |
| `deny` | Explicit prohibition, stale/invalid authority or policy, exact-binding failure, or unsupported irreversible action |
| `escalate` | Role authority or trusted facts are insufficient, including high criticality |

Risk above the autonomous ceiling and within the confirmable ceiling requires
confirmation. Risk above the confirmable ceiling escalates. High criticality
escalates in v1.

## Confirmation

Challenges and grants have caller-supplied IDs, hashes, and time values and a
maximum 300-second TTL. Grants match challenge, action, actor, role,
organization, and timing exactly. Confirmation cannot override deny or
escalate.

`GrantConsumptionLedgerV1` rejects reuse within one bounded in-memory artifact
lifecycle. Completed `D2I-KRN-200` joins admission to the durable one-shot
Windows activation ledger; the policy crate itself remains side-effect free.

## Eligibility and Admission

Eligibility seals organization, integration, application, runtime binding,
adapter kind, activation scope, activation ledger chain head, capability set,
capability binding, and fresh observation. Admission checks caller-trusted
expected runtime/ledger/adapter values, scope, capability, and freshness.

An admission contains IDs and hashes only. It has no selector, locator,
coordinate, raw input, credential, token, adapter handle, or operation payload.
Actual execution authority exists only after completed `D2I-KRN-200` combines
it with an exact one-shot `ActivatedWindowsBinding`. Completed `D2I-KRN-300`
then performs independent re-observation and postcondition verification.

## Canonical JSON

- JSON Schema Draft 2020-12
- unknown and duplicate key rejection
- bounded records and collections
- closed enums and reason codes
- canonical sorted set arrays
- recursive object-key sorting
- lowercase `sha256:` plus 64 hex digits
- self-hash field omitted from its own digest
- finite JSON numbers only
- caller-supplied time and nonce hashes
- no absolute paths or raw secret/locator data

## Desktop Compatibility

`AuditOutcomeProjectionV1` has the same JSON fields as the existing Desktop
`AuditOutcome`. The Desktop crate consumes it only in a dev-only compatibility
test. Production `ActionPolicyEvaluator`, `ActivationGate`, and
`CognitiveExecutor` remain unchanged and unconnected.

## Non-goals

This version does not implement full Role Contract, Work Radar/Queue, policy
service, confirmation UI, credential prompt, Windows activation consumption,
`DesktopOperation`, adapter prepare/commit, execution, re-observation,
Verifier v2, recovery, Runtime ABI changes, package changes, module loading,
LLM/API calls, or network access.
