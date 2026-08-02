# ADR 0029: Immutable Work Items and Verified-Closure Case Lifecycles

## Status

Accepted

## Context

WORK-100 can admit one task for an active Role and KRN-500 can produce a
verified task report, but neither contract represents durable organizational
work. A task failure, timeout, clarification, or generated `WorkReport` must
not silently discard or close the underlying work. Source text also cannot be
allowed to create authority, choose capabilities, or bypass Role, policy, and
Windows activation gates.

The product needs a deterministic boundary between source intake and Goal or
Task execution, followed by one persistent record that retains every verified
attempt until a valid terminal disposition exists.

## Decision

`d2i-work-case` owns platform-neutral Work Item and Case contracts. A caller
provides a strict `WorkItemSourceEnvelopeV1` containing only bounded IDs,
trust labels, and hashes. `WorkItemV1` is an immutable generation-1 normalized
candidate. Its canonical deduplication key distinguishes `new`,
`duplicate_open`, `duplicate_terminal`, and source-ID/content `conflict`.

Work Item admission precedes Goal compilation, module invocation, policy
admission, Windows activation, and mutation. It intersects the source,
organization, work class, Application Pack, integration, capability, risk,
calendar, policy, delegation, and active Role Instance. An admitted Work Item
may create at most one Case; each Case binds exactly one Work Item. WORK-200
does not support merge, split, reopen, ownership transfer, queue claims, or
scheduler leases.

`CaseContractV1` immutably binds the admitted Work Item, generation-1
accountable Role ownership, typed outcome and evidence requirements, absolute
SLA deadlines, allowed execution scope, and bounded attempt/recovery limits.
The ownership record is organizational accountability, not execution
authority. Every Case Task still requires fresh Role admission, policy
admission, activation, and adapter evidence.

`CaseInstanceV1` has the non-terminal states `opened`, `active`,
`awaiting_clarification`, `blocked`, `awaiting_verification`, and
`escalation_pending`. The only terminal outcomes are `verified_complete`,
`explicit_refusal`, and `escalated`. Failure, timeout, infrastructure error,
budget exhaustion, clarification, and Role suspension never create a terminal
completion. A revoked or expired Role blocks new work and requires escalation.

`CaseTaskRequestV1` binds one current Case generation and one exact role-bound
KRN context. `CaseTaskAttemptV1` binds the immutable KRN run record,
`WorkReport`, final verification, recovery results, and evidence references.
`CaseClosureEvaluationV1` is side-effect-free and can propose closure only
when all typed requirements, trust floors, freshness rules, audit integrity,
ledger integrity, and ownership checks pass. A `WorkReport` by itself is never
completion evidence.

`d2i-desktop` owns an ACL-protected organization-scoped Case ledger. It uses a
bounded append-only SHA-256 chain, atomic state replacement, DACL fingerprint
verification, one-time Work Item/Task/attempt/KRN-run consumption, and terminal
mutation rejection. `WorkCaseCoordinatorV1` persists authority-sensitive
state before executing or accepting a result, validates a fresh exact Role
Instance, and poisons itself after a durable-write failure.

The existing role-bound KRN-500 runner additionally emits its complete
hash-bound run, final verification, WorkReport, Role context, and terminal Role
Instance for Case verification. This is additive and does not change KRN,
Role Contract, Cognitive IR, Runtime ABI, package format, or module contracts.

## Safety Properties

- Source envelopes and Work Items contain no raw body, locator, payload,
  credential, private key, or personal-data subject value.
- Work Item priority, risk, and capability requirements grant no authority.
- Duplicate or conflicting source events cannot create another Case.
- One KRN run cannot be consumed twice or bound to two Cases in one ledger.
- Case failure and clarification remain durable non-terminal states.
- Unsafe evidence cannot become verified completion and requires escalation.
- Terminal Cases cannot reopen or accept later tasks or evidence.
- Case ownership is not a queue lease, scheduler assignment, or activation.

## Alternatives

Treating each KRN `WorkReport` as a completed Case was rejected because it
would collapse task output and independently verified organizational success.
Extending the Role ledger with Case state was rejected because Role lifecycle
and work lifecycle have different cardinality and retention. Implementing
Radar, Queue, Scheduler, or ownership transfer now was rejected because those
belong to later Workforce tasks and would prematurely create discovery and
dispatch authority.

## Consequences

An admitted Work Item can become a persistent, role-owned Case that retains
every verified Task attempt and remains open until verified completion,
explicit refusal, or escalation.

The exact next task is `D2I-WORK-300 - Work Radar and Work Intake`. This ADR
does not start it.
