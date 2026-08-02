# Work Item and Case Contract v1

## Purpose

WORK-200 adds the durable unit of organizational work above Role Contract v1
and the verified single-task Kernel. It separates intake facts, accountable
ownership, execution attempts, evidence, and terminal disposition.

```text
WorkItemSourceEnvelopeV1
  -> WorkItemV1 normalization and deduplication
  -> WorkItemAdmissionDecisionV1
  -> CaseContractV1 + CaseInstanceV1
  -> zero or more CaseTaskRequestV1 / CaseTaskAttemptV1
  -> EvidenceIndexV1 + CaseClosureEvaluationV1
  -> CaseTerminalRecordV1
```

This layer does not discover work and does not dispatch workers. Work Radar,
connectors, Queue, Scheduler, leases, reassignment, ownership transfer, and
distributed claims are outside v1.

## Work Item Boundary

`WorkItemSourceEnvelopeV1` accepts only approved source kinds, explicit source
and event IDs, organization identity, caller timestamps, trust labels,
hash-only provenance, attachment references, and evidence IDs. Raw email,
document, sensor, action, locator, credential, or secret content is forbidden.

`WorkItemV1` is immutable with `work_item_generation = 1`. It carries bounded
opaque subject references, requested outcome/evidence classes, the closed
priority set `routine | normal | elevated | urgent`, Cognitive IR v1 risk,
exact Application Pack references, integrations, required capabilities,
semantic targets, due time, trust labels, and canonical self-hash.

Canonical normalization sorts set-like collections, rejects duplicate and
unknown JSON keys, prohibits wildcard identifiers, excludes transport values,
and computes lowercase `sha256:` digests from recursively ordered JSON.

`WorkItemDeduplicationKeyV1` binds organization, source system/event, work
class, subject-set hash, scope, and semantic payload hash. Duplicate open or
terminal work cannot create another Case. Reusing a source ID with different
semantics is a conflict and never an overwrite.

## Admission

`WorkItemAdmissionRequestV1` binds the full Work Item and source envelope to an
active `RoleInstanceV1`, immutable Role Contract and signed delegation,
trusted operational time, exact policy set, and deduplication result.

Outcomes are `admitted`, `denied`, `duplicate`, `clarification_required`,
`escalation_required`, `inactive_role`, and `outside_operating_window`.
Only `admitted` can create a Case. Admission creates no Goal, policy decision,
Windows activation, or adapter authority.

## Immutable Case Contract

One `CaseContractV1` binds exactly one Work Item and exactly one generation-1
`CaseOwnershipBindingV1`. Ownership pins the accountable Role Instance,
contract, delegation, organization, responsibility, work class, and expiry.
It is not a lease or execution permit.

The contract includes:

- typed `CaseSuccessRequirementV1` outcome checks and acyclic aggregates;
- typed `CaseEvidenceRequirementV1` producer, artifact, trust, freshness,
  redaction, retention, and minimum-count rules;
- `CaseSlaBindingV1` absolute deadlines derived from the selected Role SLA;
- exact allowed packs, integrations, capabilities, semantic targets, limits,
  reporting obligations, and mandatory escalation reasons.

The contract cannot expand the source Work Item or Role scope. Merge, split,
reopen, or in-place mutation is rejected.

## Runtime Lifecycle

`CaseInstanceV1` uses this closed state set:

```text
opened -> active
opened|active|blocked -> awaiting_clarification
active -> blocked|awaiting_verification|escalation_pending
awaiting_clarification|blocked|awaiting_verification -> active or escalation_pending
awaiting_verification -> terminal(verified_complete)
opened|active|blocked|awaiting_clarification -> terminal(explicit_refusal)
escalation_pending -> terminal(escalated)
```

Task failure, timeout, infrastructure error, clarification, budget exhaustion,
and Role suspension do not terminate the Case. Revocation or expiry prevents a
new Task and requires escalation. Terminal state cannot reopen.

`CaseBlockV1` retains bounded missing-information, dependency, inactive-Role,
policy, infrastructure, evidence, verification, or budget blockers.

## Task and Evidence Binding

`CaseTaskRequestV1` is a short-lived one-time request. It binds the current
Case Instance hash, task sequence, ownership, exact role-bound KRN admission
and context, instruction and Goal hashes, Application Pack, integration,
capabilities, addressed requirements, and required evidence. The coordinator
rechecks the current full Role Instance, ledger head, contract/delegation,
organization, active status, and expiry before accepting it.

`CaseTaskAttemptV1` binds one immutable KRN run, WorkReport, optional final
verification, verified action results, recovery results, execution receipts,
outcome, requirements, and evidence references. A failed or unsafe attempt
cannot claim satisfied requirements.

`EvidenceIndexV1` rejects duplicate IDs, artifact hashes, and reference hashes.
It becomes immutable at terminal closure. `CaseClosureEvaluationV1` evaluates
only exact current artifacts and typed requirements; prose and WorkReport-only
completion are rejected.

## Persistence

`products/d2i-desktop/src/case_instance.rs` provides the protected
`CaseLedgerV1` and `WorkCaseCoordinatorV1`. The ledger verifies DACL
fingerprints, a monotonic append-only hash chain, atomic replacement, exact
Role/audit heads, deduplication, one-time Task/attempt/KRN consumption, and
terminal immutability on every reopen.

A durable write failure poisons the coordinator. Corruption, rollback, replay,
stale Case state, Role substitution, scope expansion, or terminal mutation
fails closed before a new module invocation or Windows activation.

## CLI

The inspection CLI performs no Task execution:

```powershell
cargo run -p d2i-work-case --bin d2i-case -- work-item validate --input work-item.json
cargo run -p d2i-work-case --bin d2i-case -- case inspect --case case-instance.json
cargo run -p d2i-work-case --bin d2i-case -- case verify --bundle case-bundle.json
cargo run -p d2i-work-case --bin d2i-case -- terminal verify --input terminal-record.json
```

## Product Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-item-case-v1.ps1 `
  -Mode All
```

The runner covers Core/schema replay, ledger lifecycle and corruption,
duplicate rejection, non-terminal failure/clarification/suspension, AI Safety
reference fixtures, WORK-100 regression, actual role-bound Windows KRN-500
evidence, verified Case closure/reopen, sensitive artifact scanning, and zero
reported residuals. Results are written below `target/d2i-workforce-case/` as
logs plus a hash-bearing `finished.json`.

## Open Boundary

The exact next task is `D2I-WORK-300 - Work Radar and Work Intake`. It will
produce approved source envelopes and Work Items; it must not implement Queue,
Scheduler, Case claim, or ownership transfer.
