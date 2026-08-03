# Work Radar and Work Intake v1

WORK-300 removes the repeated human step of checking approved systems,
recognizing work, deciding duplicate status, and manually registering a Work
Item and Case.

## Ownership

`crates/d2i-work-intake` owns strict source registration, signed Work Source
approval, Work Signal, exact mapping, checkpoint, disposition/receipt, cycle report, one-shot source trait,
canonical hashing, validation, and the deterministic bridge into WORK-200. It
has no Desktop, filesystem, Windows, process, network, credential, module,
activation, or adapter dependency.

`products/d2i-desktop/src/work_intake.rs` owns the current-user protected,
single-writer Intake ledger. Existing `d2i-role-contract`, `d2i-work-case`,
Role ledger, Case ledger, and `WorkCaseCoordinatorV1` remain authoritative.

## Contracts

- `ApprovedRadarSourceRegistrationV1` exactly binds one enabled read-only Role
  source and finite cycle/record/reference/evidence budgets.
- `WorkSourceApprovalV1` is Ed25519-signed organizational approval for one
  exact registration hash, Role Contract/Instance, delegation, signer, and
  bounded lifetime. Missing, expired, altered, or cross-organization approval
  is rejected before `scan_once`.
- `WorkSignalV1` carries only authenticated typed IDs, hashes, opaque refs,
  trust labels, sequence/cursor state, provenance, and evidence.
- `WorkIntakeMappingProfileV1` maps one source/event class to one bounded Work
  class without expanding Role or delegation scope.
- `RadarCheckpointV1` prevents rollback, replay, source substitution, changed
  event content, unsupported cursor behavior, and unbounded gaps.
- `WorkIntakeReceiptV1` records the exact source, WORK-200 artifacts, duplicate
  result, disposition, Case hashes when applicable, ledger heads, and next
  checkpoint.
- `RadarCycleReportV1` deterministically aggregates bounded resource use and
  ordered receipt hashes.

All JSON is strict Draft 2020-12, rejects unknown or duplicate fields, and uses
canonical JSON SHA-256. Collections and strings are explicitly bounded.
Retries are zero and source concurrency is one in v1.

## Dispositions

The closed outcomes are `admitted_case_created`, `duplicate_open`,
`duplicate_terminal`, `admission_denied`, `clarification_required`,
`escalation_required`, `inactive_role`, `outside_operating_window`,
`stale_source`, `unsupported_event_class`, `malformed_signal`,
`integrity_conflict`, `quarantined`, and `no_work`.

Only existing WORK-200 `admitted` may create a Case. Every rejection stops
before Goal, module, policy execution, activation, adapter, credential, or
process work.

## Crash and Replay

Case durability precedes the Intake receipt; receipt durability precedes the
checkpoint. Restart reconstructs Role, Case, and Intake ledgers. A Case-created
but unreceipted signal is reclassified by WORK-200 as `duplicate_open`, creates
no second Case, and repairs receipt/checkpoint state. A receipt-only crash may
advance only the pre-bound checkpoint. Tampering or write failure fails closed.

## Reference Roles

The canonical product E2E uses `General Office Operations Employee`. A signed
approval permits one `internal-record-updated` fixture signal, which maps
exactly to `office.record.update`, passes existing WORK-200 admission, and
creates one persistent Case. It reuses the name-save Application Pack only as
an immutable internal employee-record target; WORK-300 executes no action.

General Office, HR, IT Service, and AI Safety fixtures pass the same mapping
engine in deterministic replay. Their IDs live only in Role-owned examples and
tests; Core treats them as opaque strings. The Safety Role remains an optional
domain-specific compatibility fixture, not the product definition.

WORK-300 supports approved event class to exact Intake mapping. It does not
perform free-form document understanding, LLM classification, embedding
similarity, fuzzy work-class inference, or runtime taxonomy generation. A
future classifier must sit behind a separate versioned module boundary.

## Inspection CLI

```powershell
cargo run -p d2i-work-intake --bin d2i-intake -- profile validate --input mapping.json
cargo run -p d2i-work-intake --bin d2i-intake -- source-approval validate --input source-approval.json
cargo run -p d2i-work-intake --bin d2i-intake -- signal validate --input signal.json
cargo run -p d2i-work-intake --bin d2i-intake -- checkpoint verify --input checkpoint.json
cargo run -p d2i-work-intake --bin d2i-intake -- receipt verify --input receipt.json
cargo run -p d2i-work-intake --bin d2i-intake -- cycle replay --bundle cycle-bundle
```

The CLI performs no polling, network access, Case mutation, Task execution,
Windows activation, or credential work. Standalone source-approval validation
checks strict shape and canonical hash only; signature, registration, signer,
and TTL verification occurs in the scan/evaluation APIs where trusted keys and
caller time are available. Cycle replay validates every bundled receipt hash
against the report.

## Product Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-work-radar-intake-v1.ps1 `
  -Mode All
```

`All` runs Core/schema checks, protected Desktop persistence, the General
Office E2E, Office/HR/IT/Safety and schedule compatibility, 100 deterministic
replays of a maximum 128-event batch with identical receipt ordering,
checkpoint, cycle hash, and bounded resource metrics, 100 duplicate-recovery
replays, crash recovery, approval/tamper/stale/conflict negative
tests, official WORK-100/200 regressions, sensitive-output scanning, and zero authority/process/credential/activation residual assertions. It writes
a hash-bearing `finished.json` below `target/d2i-workforce-intake/`. The report
embeds the normalized maximum-batch metrics, receipt/checkpoint/cycle hashes,
and normalized summary hash; wall-clock timing remains informational.

## Boundary

WORK-300 contains no background Radar service, production enterprise API,
schedule engine, Queue, Scheduler, lease, claim, reassignment, ownership
transfer, Case Task, KRN invocation, UIA/Web action, or production adapter.

The exact next task is `D2I-WORK-400 - Work Queue, Scheduler and Case
Ownership`. It has not started.
