# Cognitive Recovery Control v1

## Purpose

Cognitive Recovery Control v1 consumes KRN-100 through KRN-300 evidence and
selects one bounded next step after a terminal or pre-terminal failure. It
does not execute an adapter, grant authority, close a Case, or generate a
complete WorkReport.

The normative JSON contract is
`schemas/cognitive/cognitive-recovery-control-v1.schema.json`. Every artifact
uses schema version 1, strict unknown-field rejection, bounded collections and
strings, canonical JSON, and lowercase `sha256:` identities.

## Control Flow

```text
RecoveryTriggerV1
  -> RecoveryClassificationV1
  -> RecoveryDecisionV1
  -> complete | continue | reobserve | fresh retry | alternate capability
     | replan | clarification | escalation | stop
  -> RecoveryCycleResultV1
```

Unsafe and security-relevant classifications dominate retryable or
information-gap classifications. Ambiguity never becomes an arbitrary action
selection. Exhausted budget, expired deadlines, policy denial, missing
authority, duplicate evidence, or unknown state fail closed.

## Budgets And History

`RecoveryBudgetV1` independently bounds total recovery cycles, fresh retries,
read-only re-observations, replans, clarification requests, and completion
time. A transition consumes all applicable counters atomically and may never
increase a counter or deadline.

`RecoveryHistoryV1` contains at most 64 ordered entries. Entries retain only
typed IDs and hashes. Proposal, admission, activation, and execution-receipt
identities are one-use, and repeated failure fingerprints are detected before
another blind attempt.

## Fresh Recovery

A mutating retry requires a new proposal, policy decision, admission,
activation, target observation, preparation, execution receipt, independent
re-observation, and verification result. Every identity must differ from the
consumed cycle and all hashes must bind to the same goal, plan, policy,
machine, session, target, Edge/EdgeDriver where applicable, and audit chain.

Read-only re-observation is separately budgeted and must produce a newer
observation without carrying mutation material. Alternate-capability recovery
is allowed only inside a declared equivalent-capability group. Replanning
must return a complete acyclic bounded `PlanGraph` without authority widening.

## Clarification And Escalation

Clarification requests contain deterministic question codes, typed answer
shapes, lifecycle hashes, and a deadline. Responses are one-shot and must
match request, goal, runtime binding, type, and TTL. Raw secrets, untrusted
instruction text, locators, paths, and payload values are forbidden.

Escalation requests contain only hashes, closed severity and authority enums,
bounded reason codes, safe-state summaries, and recommended next actions.
Actual recipient routing and user-facing clarification UI are future work.

## Durable Desktop Coordination

`products/d2i-desktop/src/cognitive_recovery.rs` owns the Windows-side
coordinator and recovery ledger. The ledger is current-user ACL protected,
strictly parsed, size bounded, atomically replaced, and chained by canonical
record hashes. It persists accepted triggers, classifications, decisions,
budget/history updates, challenge consumption, terminal outcomes, and audit
record hashes. Restart restores the exact durable state; corruption, replay,
truncation, or audit failure prevents mutation.

The Core crate remains deterministic and side-effect free. It has no direct
filesystem, process, network, UIA, WebDriver, Windows, or model dependency.

## Compatibility And Boundary

`project_legacy_decision` maps the additive terminal result to the existing
Cognitive IR v1 `RecoveryDecision`; the legacy type and schema are unchanged.
KRN-400 does not implement KRN-500, full Goal-to-WorkReport closure, a
production CognitiveExecutor connection, an adaptive/LLM planner, or external
network access.
