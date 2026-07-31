# First Complete Kernel E2E v1

KRN-500 is the first complete verified single-task product path. It operates
only on the repository-owned local WinForms fixture and the fixed non-secret
value `D2I-E2E-VERIFIED-NAME`.

## Product Gate

An authenticated task is compiled by the actual Goal Compiler, grounded by the
actual Element Grounder, ranked by the actual Plan Ranker, admitted by policy,
executed through certified one-shot Windows UIA, independently re-observed,
verified, recovered when allowed, and closed by a final goal verification and
machine-verifiable WorkReport.

The fixture contains an editable name, a separate committed saved name, a save
revision, a closed save status, and a protected checkbox. Editing changes only
the buffer. Save performs the business-state commit. Final completion requires
the expected committed value, saved status, increased revision, unchanged
protected field, stable process/session/window identity, and no unexpected
security-relevant change.

## Runtime Contracts

`AuthenticatedTaskInstructionV1` binds authenticated actor, role,
organization, locale, instruction, structured success criteria, provenance,
TTL, evidence, and a canonical self-hash.

`CognitiveKernelTaskRuntimeV1` permits only the ordered states from creation
through goal compilation, observation, planning, action cycles, optional
recovery, final verification, report, and terminal state. Every transition is
linked to the previous stage hash and a strictly increasing logical tick.

`ModuleInvocationCoordinatorV1` pins the three allowed module identities,
capabilities, manifests, schemas, host executable hashes, no-network and
no-side-effect declarations, resource bounds, deadline, and one-use invocation
ID. Module processes exchange one canonical Module Contract v1 envelope.

`FinalGoalVerificationV1` is distinct from action verification. It binds the
terminal stability observation, every required criterion, protected
invariants, completed action evidence, recovery evidence, verdict, and goal
progress.

`KernelTaskRunRecordV1` binds stage, module, policy, activation, execution,
verification, recovery, final verification, and WorkReport hashes. It is
audit-safe and carries no locator, raw payload, credential, or adapter handle.

## Scenarios

- Happy: two actual UIA actions and two passed independent verifications.
- Recovery: the first save is ignored, verification fails, and one wholly
  fresh bounded recovery cycle succeeds.
- Unsafe: save changes the protected checkbox, verification is unsafe, and the
  runtime escalates without a second mutation.
- Clarification: ambiguous grounding returns a bounded typed clarification
  outcome with zero activation and zero mutation.
- Replay: stale, substituted, skipped, reused, or hash-mutated lifecycle
  evidence is rejected before additional mutation.

The normalized replay digest excludes process IDs, worker IDs, activation IDs,
timestamps, and task-run IDs. It retains semantic goal, pack, plan, grounding,
ranking, selection, verification, and WorkReport meaning.

## Deliberate Limits

This is a single local task fixture, not Role or Case autonomy. It is not a
production general-purpose module loader, adaptive planner, external model
connection, arbitrary Windows application controller, WebDriver production
expansion, credential path, or Runtime ABI/package-format change.
