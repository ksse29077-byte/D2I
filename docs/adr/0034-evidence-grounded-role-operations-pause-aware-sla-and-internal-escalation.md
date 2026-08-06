# ADR 0034: Evidence-Grounded Role Operations, Pause-Aware SLA Accounting, and Exactly-Once Internal Escalation Routing

## Status

Accepted

## Context

WORK-600 provides reference-only terminal Case memory, but no component applies
the KPI, SLA, reporting, or escalation declarations already present in an
immutable Role Contract. Deriving these results from Episode summaries would
make historical projections authoritative. Reading an OS clock in Core,
editing `CaseSlaBindingV1`, accepting arbitrary formulas, or routing directly
to a person or external endpoint would create separate integrity, authority,
privacy, and replay failures.

## Decision

`d2i-role-operations` is a platform-neutral one-shot operations engine. A
signed `RoleOperationsProfileV1` exact-binds a Role Contract, delegation, Role
Instance scope, closed KPI formulas, authoritative milestone sources, pause
conditions, measurement windows, and opaque internal routing classes. The
profile can narrow Role declarations but cannot add a KPI, change a target,
expand a pause, capability, authority, report obligation, or route.

Core receives a hash-chained trusted caller time projection and never reads an
OS clock. `CaseSlaBindingV1` remains immutable. A `CaseSlaRuntimeStateV1` keeps
its baseline acknowledge, begin, resolve, and escalation deadlines and adds
only approved pause seconds to produce effective deadlines. Receipt comes
from Work Item admission, acknowledgement from the first exclusive Queue
lease or explicit Case acknowledgement, begin from the first accepted Case
Task, admitted Planner step, or Kernel binding, resolution from the terminal
Case timestamp, and escalation from a durable escalation item.

A pause identifies its approved event class and optional Case block or
clarification reason. It must match a Role-declared pause condition, signed
approval requirement, evidence classes, single and cumulative bounds, Case,
SLA binding, chain predecessor, and trusted time. Overlap, rollback,
future/post-terminal intervals, missing evidence, and arithmetic overflow fail
closed. Breaches use `(Case, SLA binding, milestone)` as their exactly-once
identity.

KPI IDs remain Role-owned while formulas come from a closed generic enum.
Calculations use integer counts or millionths only. Missing or conflicting
evidence suppresses the value and returns `insufficient_evidence` or
`conflicting_evidence`; a zero population is `not_applicable`, never success.
False-completion rate requires complete authoritative review coverage.

Role snapshots and reports contain bounded IDs, hashes, counts, coverage, and
redaction evidence only. They do not change a Case, grant execution, declare
completion, or satisfy an activation requirement. A reporting trigger must
exactly match an enabled Role obligation and all required evidence must be
present before report generation.

Routing registries are separately signed and contain only opaque routing
classes and protected internal inbox IDs. They contain no email address,
phone number, personal recipient, URL, webhook, or arbitrary endpoint. A
durable internal publication receipt means only that the local inbox object
was recorded; it never claims external delivery.

Existing Case and Recovery escalation artifacts remain the source for human
exceptions. Operational attention is distinct from a mandatory authorized
human handoff. Reason code, source artifact, severity, organization, Role, and
route are exact-bound. Acknowledgement and resolution are separately signed,
bounded records. Neither is an execution approval, activation token, Case
reopen permission, or policy override.

Desktop owns a current-user/SYSTEM DACL-protected content-addressed store,
append-only hash-chain ledger, atomic derived index, single-writer coordinator,
rollback/tamper checks, and deterministic index-only crash repair. Recovery
does not rerun a model, KRN, adapter, publication, acknowledgement, or
resolution.

WORK-700 runs only on demand. It adds no daemon, service, timer thread, cron,
external connector, or polling loop. Continuous shadow observation and
comparison belong to WORK-800.

## Consequences

- Role, Case, Queue/Ownership, Planner/KRN, Episode, and protected audit source
  ownership remains unchanged.
- General Office Role 1.2.0 is separately compiled, approved, delegated, and
  instantiated without capability or authority expansion.
- Office, HR, IT, finance, and safety identifiers remain opaque fixture data;
  Core has no domain branch.
- Reports and escalation records improve supervision without becoming
  execution authority.
- External delivery, recipient directories, background scheduling, and
  automatic policy or KPI changes remain unavailable.

## Alternatives

Mutating Case SLA deadlines was rejected because it destroys the admitted
baseline. Episode-based accounting was rejected because memory is
non-authoritative. Free-form formulas and model classification were rejected
because v1 must replay exactly. Direct email, chat, webhook, or personal
routing was rejected because WORK-700 owns only protected internal
publication. A persistent service was deferred to the separately governed
Shadow Mode lifecycle.

## Rollback And Migration

WORK-700 is additive. Disabling the one-shot cycle leaves WORK-100 through
WORK-600 and KRN behavior unchanged. Store rollback, object mutation, DACL
drift, stale approvals, or index/object disagreement fail closed. A stale
derived index may be rebuilt only from the verified ledger and immutable
objects. New formulas, pause semantics, routing, or lifecycle states require a
new schema/profile version; v1 objects and ledger history are not rewritten.
