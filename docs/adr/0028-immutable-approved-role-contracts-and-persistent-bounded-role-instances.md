# ADR 0028: Immutable Approved Role Contracts and Persistent Bounded Role Instances

## Status

Accepted

## Context

KRN-500 completes one authenticated task, but it does not answer which
organizational role may accept that task repeatedly. Existing
`DelegatedAuthorityContextV1` and `RecoveryPolicyProfileV1` are task-scoped
projections. They must not become owners of Role governance, approval,
delegation, lifecycle, calendars, KPI/SLA declarations, or reporting duties.

Embedding Desktop's `AuthenticatedTaskInstructionV1` in a Core crate would
reverse the dependency boundary. Treating role prose, UI text, or an approved
contract as an execution permit would also collapse declaration, delegation,
policy admission, and one-shot activation into one unsafe artifact.

## Decision

`d2i-role-contract` owns a platform-neutral, deterministic compiler from a
strict YAML/JSON `RoleSourcePackV1` to an immutable `RoleContractV1` bundle.
The contract is an organizational maximum, not an execution permit. An
Ed25519-signed `RoleContractApprovalV1` approves one exact organization,
contract ID, version, hash, signer, and validity interval. A separately signed
`RoleDelegationGrantV1` delegates only explicit subsets to one Role Instance.

`RoleInstanceV1` is a persistent runtime identity with the closed states
`provisioned`, `active`, `suspended`, `revoked`, and `expired`. Only an active,
unexpired instance can admit a task. Upgrades create a new immutable contract
version and a new instance generation; the same ID/version with a different
hash is an in-place mutation and is rejected.

Core receives a hash-only projection of the authenticated instruction and
compiled GoalSpec. `RoleTaskAdmissionRequestV1` binds one Role Instance,
contract, delegation, work class, Application Pack, integration, capability
set, semantic targets, risk, policy snapshot, trusted operational time, and a
short validity interval. A non-admitted decision contains no authority,
recovery, or KRN context. An admitted decision projects only the intersection
needed for this task into the existing `DelegatedAuthorityContextV1` and
`RecoveryPolicyProfileV1` contracts.

The decision's `admission_sha256` is a canonical base digest that excludes its
three optional projection hash fields and its own hash. The projections and
`RoleBoundKernelTaskContextV1` bind that base digest, and the completed
decision then binds their hashes. This explicit two-step rule avoids a digest
cycle while preserving substitution detection.

`d2i-desktop` owns the ACL-protected, atomic, append-only Role ledger. It
replays lifecycle transitions, contract registration and approval, task
admission consumption, task start/terminal state, audit cross-references, and
contract version collisions before returning current state. Corruption,
rollback, duplicate requests, duplicate admissions, terminal reactivation, or
ACL drift fails closed.

The role-enabled KRN-500 fixture deterministically constructs the expected
GoalSpec before launching any module host, performs Role admission, records
task start, then invokes the actual Goal Compiler. Execution continues only if
the actual GoalSpec equals the pre-admitted GoalSpec. The KRN root stage and
`KernelTaskRunRecordV1` contain the Role context hash. The ordinary KRN path
retains its previous serialization because the new field is optional and
omitted when absent.

## Safety Properties

- Role prose, KPI, SLA, reporting, and memory declarations grant no authority.
- Approval is not delegation; delegation is not policy admission; Role task
  admission is not Windows activation.
- Wildcard capabilities, applications, integrations, work classes, and
  semantic targets are rejected.
- Delegation and runtime projections cannot exceed the immutable contract.
- Revoked or expired instances cannot be resumed or upgraded.
- Raw locators, payloads, credentials, recipient personal data, private keys,
  and absolute paths are excluded from Role and ledger artifacts.
- KPI and SLA declarations do not claim measured outcomes.
- Work Item, Case, Radar, Queue, Scheduler, ownership, and report delivery are
  not implemented by WORK-100.

## Alternatives

Extending `DelegatedAuthorityContextV1` into a persistent Role object was
rejected because it would mix organizational governance with one-task policy
projection. Storing Role state in Core was rejected because protected DACL,
atomic filesystem persistence, and Windows audit are product responsibilities.
Linking a standalone Goal Compiler into Core was rejected to preserve
Repository Decoupling v1.

## Consequences

An approved persistent Role Instance can now consistently admit or reject
role-scoped tasks and project the exact authority and recovery contexts needed
by the verified Safe Execution Kernel. The next task is
`D2I-WORK-200 - Work Item / Case Contract v1`; this ADR does not start it.
