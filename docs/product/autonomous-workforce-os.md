# D2I Open Autonomous Digital Workforce OS

This document is the canonical product direction below `AGENTS.md` and approved
ADRs. Compiler and runtime documents retain their technical authority within
their narrower scopes.

## 1. Product Thesis

D2I is an Open Autonomous Digital Workforce OS that compiles an organization's
Domain, Role, Authority, Application Semantics, Organizational Memory, Work
Sources, and execution means into bounded autonomous digital employees capable
of general office and computer work.

D2IC is the compile-time subsystem that produces Domain, Role, Application,
Policy and Authority, Evaluation, runtime/capability binding, and Autonomous
Workforce packages. The runtime instantiates those packages as bounded Role
Instances.

## 2. Why Safe Agent Kernel Alone Is Insufficient

A safe task executor can complete a supplied action but does not discover work,
own a queue, retain Case context, meet an SLA, or close exceptions. Product
autonomy requires persistent responsibility around the Kernel, not merely
better action generation.

## 3. Human Dependency Doctrine

People define the role, delegated authority, prohibitions, KPIs, risk limits,
reporting, and escalation rules. People also handle legal approval,
irreversible change, high-risk decisions, authority limits, uncertainty, and
policy conflict.

D2I removes the requirement for a person to find, prompt, organize, judge,
review, and close every Case. The target is Human-by-exception, not
Human-in-every-loop. Human accountability remains while per-Case operational
dependency falls.

Generated prose is not completion. A Case terminates only as verified success,
explicit refusal, or escalation. Ambiguity cannot be reported as success.

## 4. Autonomy Levels L0-L5

| Level | Responsibility |
| --- | --- |
| L0 | Generate an answer |
| L1 | Draft a document or judgment |
| L2 | Execute one instructed task |
| L3 | Own one Case through completion |
| L4 | Continuously own a role and work queue |
| L5 | Coordinate roles and digital, equipment, and physical executors |

The Safe Execution Kernel is establishing the trusted L2 foundation. The first
commercial target is L4: own a category of work and its Cases through verified
closure.

## 5. Overall Architecture

```text
Autonomous Workforce Package
  -> Role Instance
     -> Work Radar and Work Intake
     -> Case/Work Queue
     -> Situation Model and Adaptive Planner
     -> Safe Execution Kernel
     -> Verified Closure
     -> Episodic Memory
     -> SLA/Outcome Tracking
     -> Exception Escalation
     -> Role-level Report
```

The Cognitive Control Plane coordinates Desktop/Enterprise Application,
API/ERP/MES/CMMS, Camera/Sensor/IoT, PLC/SCADA/OT, and
Robot/AMR/Drone planes. D2I Core owns cognition, policy, planning, memory, and
verification. PLC safety control, motor control, and emergency stop remain in
their dedicated safety layers.

## 6. Safe Execution Kernel

```text
Goal -> Observation -> World State -> Action Candidates -> Ranking
     -> Policy -> Confirmation when required -> Activation
     -> Trusted Execution -> Re-observation -> Verification
     -> Recovery -> Report
```

Models never call adapters. Ranking is not policy. Policy is not activation.
Confirmation is not an adapter token. Execution requires an exact one-shot
trusted binding, and completion requires fresh observation and postcondition
verification.

## 7. Role Instance

A Role Instance is the runtime owner of one delegated organizational role. It
binds a Role Contract, authority and policy versions, application and
capability packs, queue ownership, KPI/SLA targets, memory boundaries, and
escalation routes. Full Role Contract v1 is a Workforce-track deliverable.

## 8. Work Radar

Work Radar observes approved event sources, schedules, application states,
sensor summaries, and queue changes. It creates bounded Work Items without
treating untrusted content as policy or commands.

## 9. Case Ownership

A Case has one accountable Role Instance, explicit success criteria, current
state, deadlines, evidence, attempts, exceptions, and terminal status.
Ownership continues until verified success, explicit refusal, or escalation.

## 10. Situation Model

The Situation Model combines trusted organization state, fresh observations,
Case history, policy state, and environmental constraints. It labels unknown
and untrusted facts and never converts them into implicit permission.

## 11. Adaptive Planner

The planner selects bounded next steps from the Situation Model, authority, and
success criteria. It can re-plan after verified state change, but cannot bypass
policy, confirmation, activation, or execution contracts.

## 12. Episodic Memory

Case episodes preserve inputs by reference, decisions, evidence hashes,
actions, observations, verification, recovery, outcomes, and escalation. They
support audit and offline learning candidates, never in-place mutation of
production packages.

## 13. Human-by-Exception

Routine Cases within delegated authority progress autonomously. Confirmation
or escalation is reserved for legal, irreversible, high-criticality,
out-of-authority, uncertain, or conflicting situations. The key direction
metric is how many Cases one human intervention can bring to verified closure.

## 14. Open Digital Employee Reference Roles

`General Office Operations Employee` is the canonical reference Role. It shows
how approved internal work sources become persistent Cases for ordinary office
and computer work without embedding office vocabulary in Core.

Finance or HR Operations, IT Service Operations, and AI Safety Operations are
optional domain-specific reference Roles and cross-domain compatibility
fixtures. Their work classes, source IDs, and semantic targets belong to Role
Packs, Domain Packs, examples, or tests. Generic Core contracts treat those IDs
as opaque bounded values and never infer an industry taxonomy.

## 15. Business KPI

Technical KPIs are binding integrity, policy correctness, stale rejection,
deterministic replay, verification accuracy, critical error rate, and recovery
success.

Business KPIs are Autonomous Case Completion Rate, Human Touches per Case,
Human Minutes per Case, Verified Closure Rate, Reopen Rate, Exception Rate,
Time to Resolution, Cost per Completed Case, Cases per Human Supervisor, SLA
Compliance, False Completion Rate, and New Workflow Onboarding Cost.

## 16. Autonomous Work as a Service

The long-term commercial direction is Autonomous Work as a Service rather than
a seat-only tool. Charging units may be Role Instance, site, managed worker or
asset, completed Case, SLA, or verified cost/risk reduction.

## 17. Active Roadmap

### Track K - Safe Execution Kernel Closure

- `D2I-KRN-100`: Cognitive Policy Admission v1. **Complete**
- `D2I-KRN-200`: Trusted Action Execution Binding v1. **Complete**
- `D2I-KRN-300`: Reobserve and Cognitive Verifier v2. **Complete**
- `D2I-KRN-400`: Recovery, Retry, Replan, Clarification and Escalation. **Complete**
- `D2I-KRN-500`: First Complete Verified Single-Task E2E. **Complete**

**Track K is complete.**

The first E2E changes and saves a name field in a local test form through Goal
Compiler, Observation, Application Semantics, Element Grounder, Action
Candidate Provider, Plan Ranker, Action Selection, Policy Admission, Trusted
Execution, Reobserve, Verifier, and Work Report. It requires stale-target
rejection, zero wrong-element selections, state-hash change, postcondition
proof, audit evidence, and zero residual process, credential, or activation
state.

### Track W - Autonomous Workforce Layer

- `D2I-WORK-100`: Role Contract v1. **Complete**
- `D2I-WORK-200`: Work Item / Case Contract v1. **Complete**
- `D2I-WORK-300`: Work Radar and Work Intake. **Complete**
- `D2I-WORK-400`: Work Queue, Scheduler and Case Ownership. **Complete**
- `D2I-WORK-500`: Situation Model and Adaptive Planner. **Complete**
- `D2I-WORK-600`: Episodic Memory and Case Learning Records. **Complete**
- `D2I-WORK-700`: Role-level Reporting, SLA and Escalation. **Complete**
- `D2I-WORK-800`: Open Digital Employee Shadow Mode. **Complete**
- `D2I-WORK-900`: Limited Autonomy and Human-by-Exception Operation. **Complete**

**Track W is complete.** EDGE-100 is complete.

### Track O - General Office Capability Expansion

- `D2I-OFFICE-100`: Capability source intake and artifact workspace. **Complete**
- `D2I-OFFICE-200`: HWP/HWPX and Word document work. **Complete**
- `D2I-OFFICE-300`: Excel / spreadsheet work. **First active**
- `D2I-OFFICE-400`: PowerPoint presentation work.
- `D2I-OFFICE-500`: PDF and document interchange.
- `D2I-OFFICE-600`: Browser research and controlled download.
- `D2I-OFFICE-700`: Email, messenger, review, and feedback loop.
- `D2I-OFFICE-800`: Long-horizon multi-application project work.
- `D2I-OFFICE-900`: General Office Digital Employee E2E.

### Track X - Execution Plane Expansion

- `D2I-EDGE-100`: Enterprise API / ERP / MES / CMMS planes. **Complete**
- `D2I-EDGE-200`: Sensor / Camera / IoT observation planes.
- `D2I-EDGE-300`: PLC / SCADA / OT supervised execution.
- `D2I-EDGE-400`: Robot / AMR / Drone adapters.

## 18. Execution Planes

Desktop is the first execution plane. New planes reuse the Cognitive Control
Plane while retaining plane-specific trust, safety, activation, and
verification. No generic cognitive component may assume it owns emergency
control or physical safety interlocks.

The enterprise API plane is the second concrete plane. It hosts separately
approved, signed Connector Packs whose opaque system-family metadata can
describe ERP, MES, CMMS, or an internal API without becoming Core taxonomy.
It exposes closed semantic operations rather than arbitrary HTTP. Credentials
remain opaque outside a trusted worker, and a mutation closes only after fresh
remote verification. EDGE-100 reference evidence uses a hermetic loopback
system and does not claim vendor or customer production certification.

The General Office capability track precedes further physical execution-plane
expansion because ordinary office work depends on safe document discovery,
working copies, versions, provenance, and application-neutral semantic
operations. Public skills and MCP servers are untrusted design inputs, never
direct model execution authority. Official application APIs and SDKs remain
the primary authority for later HWP, Excel, and PowerPoint packs.

## 19. Non-goals and Safety Boundaries

D2I does not let models call adapters, treat UI/Web/document content as
authority, turn a policy record into an execution permit, bypass Windows
activation, store raw credentials in cognitive artifacts, mutate promoted
packages, or move physical emergency control into the Cognitive Core.

## 20. Current Technical Baseline

At the pre-KRN-100 baseline commit
`866a53926016824f2664dfab4e9bc600fade1cc6`, D2I has
Cognitive IR v1, deterministic model-free CognitiveExecutor, Module Contract
v1, Module SDK and Conformance Suite, Repository Decoupling v1, Windows trust
and activation/WFP/audit foundations, read-only UIA/Web Observation Plane, Goal
Compiler, Application Semantics v1, Element Grounder v1, Action Candidate
Provider v1, Plan Ranker v1, and Cognitive Action Selection Pipeline v1.

The terminal `PolicyReadyActionV1` contains no policy decision, confirmation,
activation, adapter authority, credential, or raw locator. Cognitive Policy
Admission v1 now resolves delegated authority, trusted policy, bounded
confirmation, and activation eligibility without creating execution authority.
Trusted Action Execution Binding v1 now joins one exact Cognitive admission to
one actual one-shot Windows activation, resolves a fresh UIA/Web target,
prepares without mutation, commits once, emits an audit-safe adapter-attempt
receipt, and removes raw target, input, and worker state. Adapter success is
not verified closure. KRN-300 starts an independently activated read-only
observer after the mutation worker exits, verifies exact postconditions and
protected invariants, and emits replay-consumed, audit-bound verified-action
evidence. KRN-400 now consumes that evidence through deterministic
classification, bounded budgets, replay-safe history, wholly fresh retry,
replan, clarification, escalation, or stop. The protected Desktop recovery
ledger persists each authority-sensitive transition before mutation and
restores exact budget/history state after restart.

KRN-500 now proves the complete authenticated task path through actual
standalone modules, two real UIA actions, independent verification, bounded
recovery, final goal verification, WorkReport, deterministic replay, and zero
residual authority or process state. WORK-100 adds immutable approved Role
Contracts, bounded signed delegation, persistent protected Role Instances,
one-time Role task admission, exact authority/recovery projection, and an
actual role-bound KRN-500 run.

WORK-200 now admits immutable hash-only Work Items before Goal/module/policy or
activation work, creates at most one persistent accountable Case, retains
exact role-bound KRN Task attempts and evidence, and permits only verified
completion, explicit refusal, or escalation as terminal outcomes. It removes
the following human dependency:

업무가 접수된 뒤 사람이 중복 여부, 책임 Role, 성공 조건, 증거, 시도 이력, blocked 상태와 최종 완료 여부를 별도 표·메모로 관리하던 의존성

The opened product gate is:

An admitted Work Item can become a persistent, role-owned Case that retains every verified Task attempt and remains open until verified completion, explicit refusal, or escalation.

WORK-300 now discovers bounded typed signals from exact approved Role sources,
maps them without model inference into existing WORK-200 admission, and
persists a protected receipt/checkpoint only after at most one Case exists.
It removes the need to repeatedly inspect an approved source and manually
register routine work. Replay and crash recovery cannot create a second Case.

WORK-400 now reconciles persistent Cases into a protected Queue, selects one
eligible Case with trusted-time deterministic ordering, creates an exclusive
lease and non-executable Work Grant, and recovers audited ownership transfer
from a signed exact Role pool. These artifacts grant no execution authority.
WORK-500 builds provenance-separated Situation Models from approved Case
context, runs a pinned local model behind a zero-capability process boundary,
admits only one exact semantic next step, and replans after fresh verified
state. WORK-600 seals terminal Cases as reference-only Episodes, applies exact
Role memory boundaries, uses only signed historical summaries, and exports
quarantined offline candidates without changing production intelligence.
WORK-700 applies immutable Role operations declarations to authoritative
evidence, produces pause-aware SLA and closed integer KPI projections, and
routes non-authoritative reports and escalations only to protected internal
inboxes. The active next task is
`D2I-WORK-800 - Open Digital Employee Shadow Mode`.

WORK-700 applies existing immutable Role KPI, SLA, reporting, and escalation
declarations to authoritative Case, Queue/Ownership, Planner/KRN, Episode, and
protected audit hashes. Its signed profile can only narrow a Role. Trusted
caller time and approved pause evidence produce additive SLA runtime states;
closed integer formulas produce evidence-covered metrics; reports and internal
publication receipts remain non-authoritative. Human handoff, acknowledgement,
and resolution are exactly bound but grant no execution or Case-reopen
authority. External delivery and background operation remain outside this
task. The completed five-Case General Office E2E proves approved pause handling,
breach detection, human handoff, explicit refusal, internal publication and
acknowledged escalation with zero residual runtime state.
