# D2I Industrial Autonomous Workforce OS

This document is the canonical product direction below `AGENTS.md` and approved
ADRs. Compiler and runtime documents retain their technical authority within
their narrower scopes.

## 1. Product Thesis

D2I compiles and runs a customer organization's Domain, Role, Authority,
Application Semantics, Organizational Memory, and execution means as
continuously operating autonomous digital employees. It is an Industrial
Autonomous Workforce OS.

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

## 14. AI Safety Operations Employee

The first vertical product detects expired or incomplete training, coordinates
enrollment and evidence, follows risk-assessment corrective actions, receives
inspection and near-miss Cases, manages owners and due dates, requests
evidence, retrieves rules and precedents, escalates overdue actions, maintains
audit readiness, and builds outcome evidence.

Its output is not a safety-report draft. Actions must actually be complete,
success conditions verified, open items explicit, evidence retained, and only
exceptions handed to people. This is a market entry point, not a hard-coded
limit on D2I.

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

- `D2I-WORK-100`: Role Contract v1. **First active task**
- `D2I-WORK-200`: Work Item / Case Contract v1.
- `D2I-WORK-300`: Work Radar and Work Intake.
- `D2I-WORK-400`: Work Queue, Scheduler and Case Ownership.
- `D2I-WORK-500`: Situation Model and Adaptive Planner.
- `D2I-WORK-600`: Episodic Memory and Case Learning Records.
- `D2I-WORK-700`: Role-level Reporting, SLA and Escalation.
- `D2I-WORK-800`: AI Safety Operations Employee Shadow Mode.
- `D2I-WORK-900`: Limited Autonomy and Human-by-Exception Operation.

### Track X - Industrial Execution Expansion

- `D2I-EDGE-100`: Enterprise API / ERP / MES / CMMS planes.
- `D2I-EDGE-200`: Sensor / Camera / IoT observation planes.
- `D2I-EDGE-300`: PLC / SCADA / OT supervised execution.
- `D2I-EDGE-400`: Robot / AMR / Drone adapters.

## 18. Industrial Execution Planes

Desktop is the first execution plane. New planes reuse the Cognitive Control
Plane while retaining plane-specific trust, safety, activation, and
verification. No generic cognitive component may assume it owns emergency
control or physical safety interlocks.

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
residual authority or process state. The active next task is `D2I-WORK-100`.
