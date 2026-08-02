# Role Contract v1

Role Contract v1 defines the first persistent organizational boundary above
the verified single-task Kernel.

```text
Role Source Pack
  -> deterministic compile
  -> immutable RoleContractV1
  -> signed organization approval
  -> signed subset delegation
  -> persistent RoleInstanceV1
  -> one-time RoleTaskAdmissionV1
  -> task authority and recovery projections
  -> role-bound KRN-500
```

## Ownership

`d2i-role-contract` owns strict parsing, canonical hashing, compilation,
approval and delegation verification, lifecycle contracts, task admission,
and platform-neutral projections. It has no Desktop, Windows, UIA, network, or
filesystem-mutation dependency.

`d2i-desktop` owns the protected Role Instance ledger, lifecycle persistence,
protected audit, restart recovery, task replay consumption, and role-bound
KRN entry.

## Contract Rules

- A Role Contract is a maximum declaration, never an execution permit.
- Approval and delegation are separate Ed25519 artifacts with exact hashes,
  signer IDs, organization binding, and caller-supplied validity.
- Delegation may narrow, never expand, scope, work classes, applications,
  integrations, capabilities, risk, or validity.
- Only an active and unexpired Role Instance can admit work.
- Every task request and admission is one-time in the protected ledger.
- A rejected task contains no authority, recovery profile, or KRN context.
- The KRN validates exact instruction, GoalSpec, Application Pack,
  integration, capability, authority, recovery, admission, Role Instance, and
  ledger-start bindings before creating its root stage.

Empty organization scope sets mean no additional restriction for that scope
dimension. They do not mean wildcard authority. Weekly windows are normalized
and overlapping windows are rejected. The trusted caller supplies a bounded
`RoleOperationalTimeContextV1`; WORK-100 does not implement a scheduler.

KPI, SLA, reporting, memory, escalation, and Human-by-Exception fields are
machine-readable declarations. WORK-100 does not calculate KPI values, run
SLA timers, deliver reports, route recipients, create Cases, or claim Case
ownership.

## CLI

```powershell
cargo run --locked -p d2i-role-contract --bin d2i-role -- validate `
  --source examples/workforce/kernel-e2e-operator/role.yaml

cargo run --locked -p d2i-role-contract --bin d2i-role -- compile `
  --source examples/workforce/kernel-e2e-operator/role.yaml `
  --output target/role-bundle

cargo run --locked -p d2i-role-contract --bin d2i-role -- verify `
  --bundle target/role-bundle
```

## Official Verification

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-role-contract-v1.ps1 `
  -Mode All
```

Modes are `Compile`, `Lifecycle`, `Admission`, `KernelE2E`, `Negative`, and
`All`. `All` compiles both examples twice, compares deterministic bundles,
runs Role runtime negative tests, and performs the actual role-bound Windows
KRN-500 name-save path.

## Examples

`kernel-e2e-operator` grants only the exact KRN-500 fixture pack,
`windows-kernel-e2e`, `uia.set_value`, and `uia.invoke`. It proves two actual
UIA actions, independent verification, terminal WorkReport binding, Role
ledger closure, and zero execution residuals.

`ai-safety-operations-employee` is the canonical future vertical declaration.
It references safety work classes, KPI/SLA definitions, evidence, escalation,
and Human-by-Exception rules, but does not create or execute a Case.

## Non-Goals

Work Item and Case instances, Work Radar, Work Intake, Queue, Scheduler, Case
ownership, adaptive planning, episodic memory storage, KPI measurement, SLA
timer execution, report delivery, and the AI Safety production adapter remain
unimplemented by WORK-100. WORK-200 subsequently added the Work Item and Case
contracts; the active next task is `D2I-WORK-300`.
