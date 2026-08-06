# Role Reporting, SLA, and Escalation v1

WORK-700 applies immutable Role Contract declarations to verified Case,
Queue, Planner/KRN, Episode, and protected audit evidence in a bounded
one-shot Role Operations Cycle.

## Authority

The authoritative sources remain:

- Case ledger and Case Contract for lifecycle, terminal outcome, evidence, and
  immutable `CaseSlaBindingV1` deadlines.
- Queue/Ownership ledger for current owner, exclusive lease, and first claim.
- Planner/KRN and protected audit for accepted work, execution, verification,
  recovery, and escalation evidence.
- Episode store for terminal historical references only.

Operations artifacts are projections. A profile, SLA state, metric, snapshot,
report, publication receipt, escalation acknowledgement, or resolution grants
no capability, policy admission, confirmation, activation, execution, Case
reopen, or completion authority.

## Contracts

`RoleOperationsProfileV1` is signed and exact-bound to organization, Role
Contract, delegation, Role Instance scope, policy, calendar, closed metric
bindings, milestone mapping, pause allowlists, report frequencies, internal
routes, and finite resource limits.

Core accepts only trusted caller time. Fixed measurement windows are chained,
non-overlapping, and bounded. SLA runtime states preserve every baseline
deadline and derive effective deadlines by checked addition of approved pause
seconds. Missing, stale, future, duplicated, overlapping, unauthorized, or
post-terminal evidence fails closed.

KPI formulas are a closed generic enum and use integers or millionths. Values
are emitted only for complete non-conflicting evidence. Zero population is
`not_applicable`; incomplete false-completion review coverage is
`insufficient_evidence`.

Reports require an exact enabled obligation, trigger, report class, routing
class, retention class, and evidence set. Publication is limited to a signed
registry of protected internal inbox IDs. Receipts make no external-delivery
claim.

Escalation source kind, source hash, reason codes, severity, authority impact,
organization, Role, and route must agree. Mandatory human-exception reasons
cannot be downgraded to operational attention. Acknowledgement and resolution
are separately signed and bounded.

## Persistence

Desktop stores immutable artifacts under a current-user/SYSTEM protected root:

```text
manifest.json
ledger.json
index.json
objects/<semantic-sha256>.json
```

The ledger is append-only and hash-chained. The index is derived and replaced
atomically. A single `coordinator.lock` protects writers. Restart may repair a
stale index from verified ledger/object state; it never replays side effects.
Rollback, object mutation, DACL drift, reparse points, identity collisions, and
unverified signed escalation records are rejected.

## Reference E2E

The General Office Role 1.2.0 fixture is separately compiled and bound to new
approval, delegation, and Role Instance artifacts. It reuses actual WORK-600
Completion evidence and evaluates:

- Case A: on-time verified completion.
- Case B: approved 100-second pause and on-time completion.
- Case C: overdue resolution, exactly-once breach, report, and operational
  attention route.
- Case D: `policy_unknown` mandatory human handoff, authenticated
  acknowledgement, and bounded resolution with no Case reopen.
- Case E: explicit refusal counted separately from verified completion.

The same generic formulas are replayed with opaque General Office, HR, IT, and
Safety fixture IDs. The deterministic fixture covers 128 Cases for 100
identical replays.

## Commands

```powershell
cargo run -p d2i-role-operations --bin d2i-operations -- profile verify --input profile.json
cargo test -p d2i-role-operations --all-features
cargo test -p d2i-desktop --test role_operations

powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-role-reporting-sla-escalation-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-operations\completion
```

`All` validates deterministic contracts, schemas, persistence, replay, and
regressions. Only `Completion` may set `role_operations_evidence=true`; it
reruns WORK-600 Completion and the actual five-Case operations E2E.

## Deferred

v1 has no external email/chat/SMS/webhook delivery, recipient directory,
background service, polling, cron, free-form formula, automatic target or Role
change, production connector, or Shadow Mode comparison. Those boundaries are
not implied by an internal receipt.
