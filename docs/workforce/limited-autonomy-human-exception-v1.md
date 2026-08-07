# Limited Autonomy and Human-by-Exception v1

## Scope

WORK-900 turns a separately approved General Office Role into one bounded,
one-shot autonomous duty cycle. It removes per-Case selection, prompting,
execution approval, result inspection, and completion handling for routine
Cases. A person remains responsible for deployment approval and intervenes
only for a typed exception, pause, resume, disable, drain, or revoke.

This is not a background service, a general autonomous desktop agent, or an
execution-plane expansion. The v1 coordinator handles at most eight Cases,
one at a time, and then exits.

## Authority Chain

The live chain is:

```text
WORK-800 readiness evidence
-> AutonomyReadinessBindingV1
-> finite LimitedAutonomyProfileV1
-> signed AutonomyDeploymentApprovalV1
-> separately approved Role 1.4.0 and active Role Instance
-> current Case eligibility and AutonomyCaseAdmissionV1
-> existing Role Task Admission and Policy Decision
-> one-shot Windows activation
-> Safe Execution Kernel
```

Readiness, deployment approval, eligibility, admission, and task binding are
non-executable evidence. None is an adapter token, confirmation, policy
decision, activation record, or KRN permit. Every side effect still passes the
existing Role, delegation, Case, ownership, lease, Work Grant, policy,
activation, and trusted execution checks.

The Shadow Role 1.3.0 is unchanged and never used for live execution. The
General Office 1.4.0 Role is independently compiled, approved, delegated, and
instantiated for the `limited-autonomy` environment. Its exact autonomous
scope is:

- Application Pack: `kernel-e2e-name-save`
- Capabilities: `uia.set_value`, `uia.invoke`
- Semantic targets: `employee_name_input`, `save_button`
- Work class: `office.record.update`

Core treats those identifiers as opaque Role/Application Pack data.

## One-Step Loop

The trusted coordinator executes only this loop:

```text
claim Case
-> fresh observation
-> Situation Model
-> pinned Qwen3-4B next-step proposal
-> current autonomy and Case admission validation
-> policy
-> one-shot activation
-> one KRN action
-> fresh observation
-> independent verification
-> durable Case and health update
-> replan, recover, close, or hand off
```

It never executes a precomputed action list. Before each side effect it checks
that control state, health, Role, delegation, deployment, readiness, Case,
ownership, lease, Work Grant, capability, target, risk, policy, Application
Pack, model/runtime, and observation freshness remain current.

If pause arrives after `SetValue`, that in-flight result is observed and
recorded, but `Save` is not started. A signed resume requires all current
gates, a fresh observation, a new Situation Model, and a new plan. The runtime
cannot resume itself.

## Human Exceptions

Mandatory exception classes include ambiguity requiring clarification,
confirmation-required work, policy unknown or deny, authority or scope
conflict, irreversible or high-criticality work, verification failure,
unsafe side effect, and health trip.

`HumanExceptionHandoffV1` is bounded, hash-only, signed where required by the
governance path, durable, and exactly once. A bounded signed
`HumanExceptionResponseV1` is data, never a command. Clarification and
confirmation responses are consumed once and force fresh planning. Terminal
escalations are not reopened; follow-up work requires a new Work Item.

## Control And Health

The append-only control states are `disabled`, `eligible`, `enabled`,
`paused`, `draining`, `suspended`, `revoked`, `expired`, and
`health_tripped`. Signed monotonic commands are `enable`, `pause`, `resume`,
`drain`, `disable`, and `revoke`.

False completion, unsafe side effect, protected invariant violation,
forbidden capability, authority expansion, policy or activation bypass,
wrong target, secret leakage, repeated verification failure, identity drift,
Role/delegation revoke, Application Pack drift, and readiness invalidation
trip the synchronous fail-closed interlock. A trip stops new claims and
actions immediately. There is no automatic clear or self-resume.

## Persistence And Recovery

Desktop persists autonomy artifacts in a current-user/SYSTEM DACL-protected,
content-addressed store with an append-only canonical hash chain, atomic
derived index, one writer, rollback pin, reparse rejection, and bounded crash
repair. Recovery distinguishes action-not-started, known terminal receipt,
and unknown in-flight outcome. Unknown side effects are reobserved and
verified; they are never replayed blindly.

The common `WorkforceCheckpoint.psm1` checkpoint contract binds normalized
inputs, step-specific executable source sets, predecessor hashes, produced
artifacts, logs, cleanup, and zero residual state. Only safe terminal steps
are reusable. A changed executable source invalidates that step and all of its
dependents without forcing unrelated documentation-only replay.

## Completion Evidence

The official `Completion` mode requires sealed WORK-800 evidence, the pinned
Qwen3-4B model and llama.cpp runtime, actual WORK-300 Radar/Intake and WORK-400
Queue paths, Role 1.4.0 governance, eight model proposals, eight Windows KRN
Case scenarios, protected persistence/audit, deterministic 128 Case x 100
replay, security scan, and zero runner-owned residual state.

The canary contains five routine verified closures and three typed exception
Cases. Routine human touches are zero. The clarification Case has one bounded
human fact and resumes only from a fresh plan. Terminal exception Cases perform
no autonomous UI action after handoff. A pause-after-Set Case performs no Save
until signed resume and fresh admission.

Model process telemetry records per-invocation elapsed time, Windows Job
Object peak process/job memory, input/output bytes, and provider count. The
runner separately records Radar/Intake, Queue, governance/model, aggregate KRN,
and closure/report/certification wall-clock stages. Aggregate KRN timing is not
represented as fabricated per-component latency.

Run deterministic validation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-limited-autonomy-human-exception-v1.ps1 `
  -Mode All `
  -OutputRoot target\d2i-work900-all
```

Run the actual product gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-limited-autonomy-human-exception-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Work800EvidenceRoot C:\path\to\work800\completion `
  -OutputRoot target\d2i-work900-completion `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

Use `-Resume` only after a transient failure. It cannot reuse an ambiguous
in-flight side effect or evidence whose inputs, dependencies, artifacts,
cleanup, or residual state no longer verify.

## Boundaries

WORK-900 adds no external connector, email/chat/webhook delivery, ERP or MES
adapter, file download, cloud controller, production online learning,
automatic model/Role/policy update, background Windows service, distributed
scheduler, or Track X execution plane. Learning candidates remain quarantined
under WORK-600. Reports and escalations remain protected internal WORK-700
records.
