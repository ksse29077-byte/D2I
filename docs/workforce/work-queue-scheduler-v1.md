# Work Queue, Deterministic Scheduler, and Case Ownership v1

WORK-400 removes the manual step of collecting persistent Cases, selecting the
next eligible Case, preventing duplicate planning, and reassigning an
unavailable owner. It does not execute work.

## Contract Boundary

`d2i-work-queue` is platform-neutral and side-effect free. It owns strict
Queue policy, signed ownership pool, current ownership, Queue projection,
one-shot Scheduler, exclusive lease, audited transfer, non-executable Work
Grant, canonical JSON, SHA-256, schemas, CLI inspection, and replay.

`d2i-desktop::work_queue` owns the current-user protected single-writer ledger,
DACL fingerprints, regular-file checks, bounded strict JSON, atomic replace,
hash-chain replay, crash recovery, and Role/Case/Intake/audit hash bindings.

The immutable WORK-200 Case Contract and generation-1 origin ownership remain
unchanged. The Case ledger is authoritative. Queue entries are replaceable
projections; current ownership is an append-only overlay.

## Scheduler

One trusted caller supplies the tick time, operational calendar projection,
resource budget, and exact Role, Case, Queue, and ownership ledger heads. The
Scheduler examines at most 128 entries and selects with a fixed lexicographic
tuple. Aging uses bounded integer buckets and changes order only. Blocked,
clarification, escalation-attention, owner-unavailable, leased, and terminal
lanes never become implicit execution candidates.

## Lease And Transfer

One Case has at most one active lease. A new claim advances the latest lease
epoch and chain hash. Renewal is bounded and only valid for the exact active
owner. Release, expiry, and revocation are durable terminal lease transitions.
They do not transfer ownership.

Automatic transfer is limited to closed reasons and a signed exact ownership
pool. It requires no active lease, a non-terminal Case, matching organization,
Role Contract, responsibility, work class, application, integration,
capability, risk, capacity, and ledger heads. History is never deleted.

## Non-Authority

Queue entries, decisions, leases, ownership states, transfers, receipts, and
Work Grants contain no natural-language instruction, raw target, locator,
credential, policy decision, activation token, adapter input, or command. The
inspection CLI cannot mutate a ledger or claim a Case.

## Verification

```powershell
cargo test -p d2i-work-queue --all-features
cargo test -p d2i-desktop --test work_queue_scheduler

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-queue-scheduler-v1.ps1 `
  -Mode All
```

The official runner writes hash-bearing evidence under
`target/d2i-workforce-queue/`. Replay uses 128 distinct synthetic Cases for 100
identical runs and compares ordering, snapshot, decision, lease, grant,
ownership, operation count, and normalized report hashes.

## Limits

There is no background service, distributed Queue, production connector,
planner, Goal, Task, policy admission, activation, adapter call, Case closure,
SLA delivery, or recipient routing in v1.
