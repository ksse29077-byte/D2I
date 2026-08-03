# ADR 0030: Bounded Work Radar and Exactly-One-Case Intake

## Status

Accepted

## Context

WORK-100 establishes immutable approved Role Contracts, signed delegation,
and protected Role Instances. WORK-200 establishes hash-only Work Items,
deterministic duplicate classification, admission, and one-Work-Item/one-Case
persistence. A person still had to repeatedly inspect an approved system,
recognize an event as work, decide whether it was a duplicate, and manually
register the Work Item and Case.

Work discovery is an untrusted observation boundary. It must not silently
become connector authority, a scheduler, a queue lease, a credential path, or
an alternate route around WORK-100/200 admission.

## Decision

`d2i-work-intake` owns platform-neutral WORK-300 contracts and deterministic
processing. `d2i-desktop` owns current-user protected Intake ledger storage.
Neither layer changes Cognitive IR v1, Role Contract v1, Work Item/Case v1,
Runtime ABI, module contracts, policy, activation, or adapter contracts.

The flow is:

```text
approved Role observation source
  -> exact Radar registration
  -> signed WorkSourceApprovalV1 verification
  -> bounded one-shot typed signal batch
  -> source checkpoint and freshness validation
  -> exactly one exact mapping
  -> existing WorkItemSourceEnvelopeV1
  -> existing normalize_work_item
  -> existing classify_duplicate
  -> existing admit_work_item
  -> existing Case ledger and WorkCaseCoordinatorV1
  -> durable Intake receipt
  -> durable source checkpoint
```

### Hash-only observation boundary

A `WorkSignalV1` contains typed IDs, monotonic sequence/cursor state, immutable
artifact hashes, opaque subject and structured-input references, trust labels,
provenance hashes, and evidence IDs. Raw bodies, documents, API responses,
credentials, tokens, personal values, locators, selectors, or commands are
rejected. Untrusted content cannot add work class, application, integration,
capability, semantic target, priority, risk, or authority.

### Exact registration and mapping

An approved Radar registration must equal one enabled read-only Role
observation source, including source kind, integration, Application Pack,
event classes, trust floor, freshness, Role/approval/delegation/instance
hashes, and organization. Wildcards and `all`/`any` aliases are invalid.

Registration shape alone is not approval. A separate Ed25519-signed
`WorkSourceApprovalV1` binds the exact registration hash, organization, Role
Contract and Instance, Role approval, delegation, signer identity, evidence,
and bounded validity period. Both scan request and durable Intake artifacts
bind its hash. This was selected over adding source-specific transitions to the
generic Role ledger because it keeps source revocation and signer rotation in
an additive, independently verifiable artifact without changing WORK-100.

An Intake mapping is immutable and deterministic. Exactly one mapping must
match registration, source, and event class. Its Work class, outcome/evidence
classes, pack, integration, capability, semantic targets, risk, trust, and
structured-input kinds must remain within the Role and signed delegation.
Missing or ambiguous input becomes a typed disposition; no LLM, embedding,
fuzzy match, locale rewrite, random choice, floating-point score, wall clock,
or unordered map iteration participates.

### Delivery and checkpoint semantics

Radar delivery is at least once. Case creation is exactly once per WORK-200
deduplication identity. A checkpoint binds the registration, source sequence
or opaque cursor, event and signal hash, prior checkpoint, cycle, and protected
Intake ledger head. Rollback, same-sequence substitution, changed event
content, unsupported cursors, or gaps beyond the explicit bound fail closed.

The Desktop ledger writes a receipt before advancing its checkpoint. The
receipt pre-binds the exact next checkpoint. If the process stops after Case
creation but before either Intake write, restart reconstructs WORK-200
deduplication state, returns `duplicate_open`, creates no second Case, and
repairs the receipt/checkpoint. If it stops after the receipt, only the
pre-bound checkpoint may be repaired. Durable-write failure poisons the open
writer. DACL drift, non-regular/reparse files, duplicate JSON keys, hash-chain
rollback, stale writers, tampering, and replay are rejected.

### Adapter authority

`RadarSourceAdapterV1` exposes only one bounded `scan_once`. It receives an
explicit registration, verified signed source approval, checkpoint, caller
time/deadline, and resource bounds, and returns immutable typed signals. It cannot poll in the background, commit
a checkpoint, create a Case, execute a process, use a credential, access the
network, invoke UIA/Web, or bypass admission. WORK-300 provides only a local
fixture adapter; production enterprise connectors belong to EDGE-100.

## Rejected Alternatives

- Giving Radar a generic connector or filesystem/network API would combine
  observation and authority.
- Treating source text as a Goal or command would bypass exact mapping and
  trust labels.
- Advancing a checkpoint before Case/disposition durability could silently
  lose work.
- Creating a new deduplication implementation would split the WORK-200 source
  of truth.
- Starting a daemon, Queue, Scheduler, lease, claim, reassignment, or ownership
  transfer would prematurely implement WORK-400.

## Consequences

One approved event can be found without a prompt and become at most one
persistent Case. Replays are visible and deterministic. Radar remains an
authority-free observation plane, and every admitted Case still depends on
WORK-100/200 governance.

General Office Operations Employee is the canonical product fixture. HR, IT,
and Safety fixtures prove that exact mapping handles Role-owned domain IDs
without hard-coding a taxonomy in Core. No free-form classifier is introduced.

Remaining production work includes enterprise source authentication and
transport, external chain-head anchoring, multi-source atomicity, deployment
key custody, Queue/Scheduler concurrency, Case claim/lease/ownership, and
production schedule time authority. These are not fallback paths.

The exact next task is `D2I-WORK-400 - Work Queue, Scheduler and Case
Ownership`. This ADR does not start it.
