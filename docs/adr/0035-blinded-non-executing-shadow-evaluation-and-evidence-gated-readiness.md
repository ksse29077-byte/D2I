# ADR 0035: Blinded Non-Executing Shadow Evaluation and Evidence-Gated Readiness

## Status

Accepted

## Context

WORK-700 can publish bounded internal Role reports, but it does not establish
whether a concrete Intelligence Provider is ready for limited-autonomy design.
Comparing model output with a human action after revealing either side, treating
the human as an automatic gold label, or letting an evaluation artifact enter
the execution path would produce biased evidence and a new authority bypass.
Capturing global keyboard, pointer, screen, clipboard, locator, or raw UI data
would also turn a narrow product evaluation into workplace surveillance.

## Decision

`d2i-shadow-mode` owns platform-neutral, bounded Shadow contracts. A signed
profile narrows an immutable Role Contract, delegation, Role Instance,
Application Pack, policy set, provider/model/runtime/prompt hashes, observation
sources, semantic targets, capabilities, recorder modes, retention, and
resource limits. Signed readiness policy, cohort, participation, assignment,
and read-only observation-grant artifacts exact-bind every participating Case.
None is execution, activation, confirmation, ownership, lease, or Case mutation
authority.

For each cycle, the AI proposal and pure counterfactual policy assessment bind
the same fresh pre-action observation as the reference workflow. Their
canonical hashes are durably committed before the reference action begins.
The proposal remains hidden until the signed semantic human step and fresh
post-action observation are durable. A reveal receipt rejects substitution,
missing commitment, stale ordering, cross-Case input, and early disclosure.
Reference controls remain disabled until a session-bound one-shot arm marker is
written after durable commitment; prewritten commands cannot cross that gate.

The AI lane may invoke the approved local Qwen3-4B Intelligence Provider and
produce a non-executable semantic proposal. It cannot claim a Case, acquire a
lease, mutate ownership, create a Case Task or Attempt, issue a production
policy/admission/confirmation/activation artifact, invoke KRN, or call UIA,
WebDriver, file, process, or another mutation adapter.

Reference evidence is recorded only through fixture-owned app-local semantic
events, authenticated explicit human-step submission, and read-only pre/post
observations. It stores bounded IDs and immediate hashes, not raw values,
locators, selectors, coordinates, keystrokes, credentials, recipient PII,
screenshots, video, clipboard data, or unrelated application state. At least
one Completion session is an actual interactive operator session; instrumented
sessions use a non-activating hidden fixture so regression tests do not steal
desktop focus.

Neither AI nor human output is a gold label. Independent adjudication uses the
current signed Role/delegation, exact Case success criteria, fresh observation,
pure policy disposition, and verifier result. Counterfactual output establishes
proposal admissibility only; it never proves that an unexecuted action would
have succeeded. Missing or conflicting evidence is represented explicitly.

The cohort is sealed before evaluation and exact-binds 60 new model-backed
holdout Cases, model/runtime/prompt hashes, scenario strata, and allowed
exclusions. Failed or invalid model output remains in the denominator. The
General Office readiness policy requires the documented integer-millionth
thresholds, five Windows sessions, one interactive session, complete evidence,
100% mandatory-escalation recall, and zero false completion, authority
expansion, forbidden capability, secret leakage, direct execution, unblinded
cycle, or critical error.

Desktop owns a current-user/SYSTEM DACL-protected content-addressed Shadow
store and protected audit. Objects are immutable, the ledger is append-only and
hash chained, the index is derived, one coordinator writes, and rollback,
mutation, reparse points, DACL drift, duplicates, and out-of-order phases fail
closed. Validation and ordering errors detected before a write do not poison a
clean store. A failure after durable mutation begins poisons it until bounded
recovery removes only unreferenced objects and rebuilds the index from the
verified ledger. Recovery never reruns a model, human action, adapter, or
publication.

Crash windows A through I map to closed read-only recovery directives derived
from the last verified durable artifact. Window J uses the WORK-600 protected
memory store's object-first repair: a durable Shadow candidate absent from the
ledger/index is recovered into exactly one quarantine record. The Shadow
candidate is a separate ingress type because reusing terminal-Episode-only
`LearningCandidateV1` would falsify provenance; it has no promotion path.

A signed `ShadowReadinessAssessmentV1` can state only
`eligible_for_work900_design`, `not_eligible`, or an evidence failure defined by
the closed contract. Readiness is evidence, not a permit. It cannot modify the
Role, policy, model, prompt, Application Pack, capability set, activation
ledger, or runtime state. Divergence enters only WORK-600 quarantine. Reports
use only the existing WORK-700 protected internal route and never claim email,
chat, webhook, SMS, or other external delivery.

Completion is resumable from verified safe checkpoints rather than failed
commands. Every checkpoint is canonical, atomic, dependency-bound, and written
only after artifact validation, cleanup, and zero-residual verification. The
source-content hash is recorded while step-specific executable and runner
hashes define invalidation, so a content-identical rebase does not force an
unsafe or unnecessary replay. Dependency invalidation is transitive.

Model holdout Cases are individually atomic. The first process seals a bounded
provider validity binding containing the exact model, runtime, and three
provider descriptor hashes. Restarts may reuse that validity window only while
its 24-hour TTL is live. This is necessary because provider descriptors include
validity timestamps; minting new descriptor times on every process would make
otherwise exact Case evidence non-resumable. Failed Cases remain in the cohort
and the aggregate is rebuilt after 60/60 verification.

Only terminal Shadow sessions can be checkpointed. Commitment without a
durable post-observation is ambiguous and therefore cannot resume an action;
recovery begins with fresh observation. Bounded, secret-scanned diagnostics
are preserved before cleanup. The terminal certification revalidates the full
checkpoint set, pinned artifacts, cohort, interactive evidence, readiness,
sensitive scan, and cleanup rather than trusting process continuity.

## Consequences

- Shadow evidence is comparable, replayable, blinded, and separate from live
  execution authority.
- General Office is the concrete readiness Role while HR, IT, and Safety remain
  cross-domain contract fixtures; Core contains no domain-specific branch.
- App-local instrumentation is required for semantic reference evidence; v1 is
  not a general desktop activity recorder.
- Completion requires actual pinned model/runtime inference and one visible
  human session, so deterministic CI alone cannot close WORK-800.
- Exact checkpoint resume reduces transient restart cost without treating a
  prior process, command, or partial human action as success evidence.
- Readiness can open WORK-900 design but cannot switch Shadow to live operation.

## Alternatives

Executing the AI proposal was rejected because it would be WORK-900 behavior.
Showing the proposal to the operator was rejected because it contaminates the
reference action. Treating the human as gold was rejected because reference
operators can make mistakes. Global hooks, screenshots, clipboard monitoring,
and background services were rejected as disproportionate surveillance.
Recorded fixtures alone were rejected because they do not provide live human
evidence. Floating-point metrics and post-hoc holdout selection were rejected
because they undermine deterministic replay and evaluation integrity.

## Rollback And Migration

WORK-800 is additive and one-shot. Disabling its runner leaves WORK-100 through
WORK-700 and the Safe Execution Kernel unchanged. Shadow artifacts cannot be
converted into execution tokens. Store rollback or tamper fails closed, while
derived-index repair uses only the verified ledger. New recorder modes,
readiness thresholds, metric formulas, observation classes, or live autonomy
semantics require a new version and ADR; v1 evidence is never rewritten.
