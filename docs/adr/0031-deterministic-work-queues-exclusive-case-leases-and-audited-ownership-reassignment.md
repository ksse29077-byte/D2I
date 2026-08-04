# ADR 0031: Deterministic Work Queues, Exclusive Case Leases, and Audited Ownership Reassignment

## Status

Accepted

## Context

WORK-300 can create persistent Cases, but a human still had to assemble open
Cases, choose the next Case, prevent concurrent work, and move accountability
when a Role Instance became unavailable. The immutable WORK-200
`CaseOwnershipBindingV1` records the generation-1 accountable owner and cannot
be rewritten to represent current operational ownership.

## Decision

The Case ledger remains the source of truth for Case state. A Queue entry is a
hash-bound projection of one current non-terminal Case, not a second Case
store. Missing entries are repaired from the Case ledger; duplicate or stale
projections fail closed.

Current ownership is an additive append-only overlay. Generation 1 is derived
exactly from the immutable origin binding. Later generations require an exact
transfer record, the latest ownership-state hash, no active lease, and a
signed ownership pool whose Role, organization, work class, responsibility,
application, integration, capability, risk, lifetime, and capacity bounds all
contain the transfer.

Scheduling is a caller-invoked, one-shot pure function. It receives trusted
time and exact Role, Case, ownership, lease, calendar, and ledger heads. It
does not read a wall clock, locale, environment variable, random source, or
network. Eligible entries use the following lexicographic order:

1. resolve deadline breached
2. begin deadline breached
3. escalation attention
4. integer aging-adjusted priority
5. resolve deadline
6. escalation deadline
7. enqueue sequence
8. Case ID
9. Case Contract hash

A claim creates an exclusive, bounded, hash-chained lease. A lease coordinates
planning ownership only; it is not policy admission, activation, a credential,
an adapter token, or execution authority. A `CaseWorkGrantV1` is likewise a
non-executable, one-time, hash-only handoff for WORK-500.

Desktop persists Queue entries, current ownership, lease history, transfer
history, grants, operation receipts, and external protected-audit hashes in a
current-user DACL-protected, strict-JSON, append-only hash chain. Appends use a
single-writer lock and atomic replacement. Reopen verifies every record before
reconstructing snapshots, current ownership, leases, and replay indexes.

## Consequences

- Case and origin ownership contracts do not drift.
- Input order cannot alter selection or artifact hashes.
- Lease expiry does not silently transfer accountability.
- Owner suspension can only produce attention or an approved deterministic
  transfer to the exact signed pool.
- Crash windows between Case creation, Queue reconciliation, lease reporting,
  transfer projection, and lease expiry recover without duplicate Cases or
  concurrent claims.
- WORK-500 may consume a valid Work Grant as planner input, but WORK-400 does
  not create Goals, Plans, Tasks, policy decisions, activation, or actions.

## Alternatives

A background scheduler service was rejected because it adds clock, lifecycle,
and privilege state before a one-shot contract is proven. Mutable ownership in
`CaseContractV1` was rejected because it destroys origin accountability.
Floating-point scores and random load balancing were rejected because they
weaken replay. A lease as execution permission was rejected because it would
bypass the Safe Execution Kernel trust chain.

## Rollback And Migration

WORK-400 is additive. Disable Queue coordination and retain the WORK-200 Case
and WORK-300 Intake ledgers unchanged. A future schema version must migrate by
replaying verified v1 records into a new ledger; it may not edit v1 history in
place.
