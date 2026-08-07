# ADR 0036: Evidence-Bound Limited Autonomy and Human-by-Exception

## Status

Accepted

## Context

WORK-800 established that a pinned local Intelligence Provider met a bounded
Shadow readiness policy. That status is evidence for design and deployment
review, not authority to claim a Case, plan an action, activate an adapter, or
mutate an application. Treating readiness, a deployment approval, or a
per-Case admission as an execution token would bypass the Role, Queue,
Policy, activation ledger, and Safe Execution Kernel boundaries.

Continuous autonomous operation also needs a way to stop immediately without
turning a one-shot completion runner into an unattended service. Ambiguous,
out-of-authority, policy-unknown, irreversible, high-criticality, or unsafe
Cases must reach a person exactly once and must not continue autonomously from
an old observation or plan.

## Decision

`d2i-limited-autonomy` owns platform-neutral governance contracts. The chain is
WORK-800 readiness, an exact `AutonomyReadinessBindingV1`, a signed
`AutonomyDeploymentApprovalV1`, a finite `LimitedAutonomyProfileV1`, an active
Role Instance, and deterministic per-Case `AutonomyCaseEligibilityV1` and
`AutonomyCaseAdmissionV1`. These artifacts are evidence only. They cannot act
as a confirmation, policy decision, activation record, adapter credential, or
KRN permit.

The General Office 1.4.0 reference Role is a new immutable contract for the
`limited-autonomy` environment. Its live scope is exactly the
`kernel-e2e-name-save` Application Pack, capabilities `uia.set_value` and
`uia.invoke`, and semantic targets `employee_name_input` and `save_button`.
The 1.3.0 Shadow Role remains non-executing and unchanged.

Desktop owns the protected append-only autonomy store and the one-shot Role
duty-cycle coordinator. Before each action it revalidates Role, delegation,
deployment approval, readiness, Case state, ownership, exclusive lease, Work
Grant, capability, target, risk, policy, one-shot activation eligibility,
fresh observation, exact model/runtime/Application Pack hashes, and health.
An action is followed by a fresh observation and independent verification
before another action may be planned. Pause during an action lets the bounded
in-flight call reach a verified terminal record but prevents the next action.

Signed monotonic commands support enable, pause, resume, drain, disable, and
revoke. Resume requires fresh exact binding validation and cannot be emitted by
the runtime itself. Any critical health count synchronously enters
`health_tripped`, stops new claims and actions, and publishes a protected
WORK-700 escalation. No automatic clear exists.

Clarification and confirmation responses contain only signed bounded hashes.
They require a fresh observation, Situation Model, and plan. Mandatory or
terminal escalation ends autonomous execution. A terminal Case is never
reopened; follow-up work is a new Work Item. Handoff and response hashes are
consumed exactly once in a replay ledger.

The coordinator is bounded and exits after at most eight Cases with maximum
concurrency one. It is not a daemon or Windows service. A future host may call
the primitive repeatedly only under a new deployment decision.

WORK-800's checkpoint implementation is generalized as
`WorkforceCheckpoint.psm1`. Checkpoints are atomic, canonical,
dependency-bound, secret-scanned, and reusable only after their artifacts and
zero-residual cleanup evidence verify. Recovery never blindly replays an
action with an unknown outcome.

## Consequences

- Routine General Office Cases can complete with zero per-Case human touches.
- People intervene for bounded clarification, confirmation, mandatory
  escalation, terminal escalation, pause, revoke, or health trip.
- Readiness and deployment evidence remain auditable without expanding actual
  execution authority.
- General Office is a fixture; Core does not branch on office, HR, finance, IT,
  or safety taxonomy.
- v1 supports one desktop Case at a time and one-shot duty cycles only.

## Alternatives

Promoting the Shadow Role in place was rejected because it would rewrite the
meaning of approved 1.3.0 evidence. Allowing readiness or admission to activate
an adapter was rejected as an authority bypass. A background service was
rejected because WORK-900 only needs a bounded lifecycle primitive. Automatic
resume or health reset was rejected because it would let the system erase a
human control or critical incident. Reusing an old plan after a response was
rejected because the observed world and authority may have changed.

## Rollback And Migration

Disable or revoke the signed autonomy state and stop invoking the bounded duty
cycle. Existing Role, Case, Queue, Policy, KRN, Shadow, Memory, and Operations
ledgers remain authoritative. Autonomy artifacts cannot be converted into old
activation records. Contract expansion, parallel desktop Cases, a long-lived
host, external notification, or new execution plane requires a new version and
ADR.
