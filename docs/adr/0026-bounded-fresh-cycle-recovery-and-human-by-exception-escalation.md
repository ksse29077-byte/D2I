# ADR 0026: Bounded Fresh-Cycle Recovery and Human-by-Exception Escalation

## Status

Accepted

## Context

KRN-300 produces immutable verified-action evidence after a separately
activated read-only observation. A failed, inconclusive, unsupported, or
unsafe verdict is not authority to repeat the action. Blind reuse of a
proposal, admission, activation, receipt, target snapshot, or mutation worker
would bypass the trust boundaries established by KRN-100 through KRN-300.

The existing Cognitive IR v1 `RecoveryDecision` is a stable compatibility
contract. It is too small to carry durable budgets, replay evidence, typed
clarification, or escalation data, but changing it would create unrelated
schema and module drift.

## Decision

KRN-400 adds a separate Cognitive Recovery Control v1 contract:

1. `RecoveryTriggerV1` binds a supported lifecycle stage to one closed reason.
2. A deterministic classifier gives unsafe or security-relevant failures
   priority over retryability.
3. `RecoveryBudgetV1` atomically accounts for total cycles, retries,
   re-observations, replans, clarification requests, and a deadline. Budgets
   never increase during recovery.
4. `RecoveryHistoryV1` records bounded hash-only outcomes and consumes prior
   proposal, admission, activation, and receipt identities.
5. `RecoveryDecisionV1` chooses only complete, continue, re-observe, fresh
   retry, alternate capability, replan, clarification, escalation, or stop.
6. Every mutating retry is a wholly fresh KRN-100 through KRN-300 cycle. Old
   proposal, admission, activation, receipt, observation, or worker authority
   is never reused.
7. Replanning returns a complete validated `PlanGraph`; it cannot widen the
   goal, authority, policy digest, or excluded failing capability set.
8. Clarification uses deterministic typed questions and one-shot typed
   answers. Escalation carries hashes, bounded reason codes, and safe-state
   summaries, never raw payloads or credentials.
9. `CognitiveRecoveryCoordinatorV1` persists decisions and budget/history
   changes before invoking a mutation closure. Audit or ledger failure stops
   before mutation.
10. The Desktop product owns a current-user protected, hash-chained recovery
    ledger. The Core crate owns no filesystem, process, network, adapter, UIA,
    WebDriver, model, or Windows API.
11. The legacy Cognitive IR v1 decision is produced only by a deterministic
    projection from the additive terminal result.

Human involvement is by exception: unsafe/security outcomes, exhausted
authority, explicit policy, or unresolved bounded uncertainty escalate;
ordinary recoverable failures remain autonomous within declared limits.

## Alternatives Rejected

- Retrying the same proposal or activation: permits blind replay and stale
  authority reuse.
- Extending Cognitive IR v1 `RecoveryDecision`: creates schema drift across
  Core and standalone modules.
- Letting a production LLM choose recovery: makes safety and budget decisions
  nondeterministic and introduces an external dependency.
- Putting the durable ledger in the Core crate: mixes platform storage and ACL
  behavior into a portable decision contract.
- Treating every failure as escalation: preserves a human approval bottleneck
  and defeats bounded autonomous recovery.

## Consequences

A failed or inconclusive action can be safely re-observed, retried through a
wholly fresh trust chain, replanned, clarified, escalated, or stopped without
blind replay. The first complete Goal-to-WorkReport flow, production planner,
clarification UI, and escalation-recipient routing remain outside KRN-400.
