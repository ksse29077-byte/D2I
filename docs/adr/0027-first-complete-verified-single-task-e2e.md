# ADR 0027: First Complete Verified Single-Task E2E

## Status

Accepted

## Context

KRN-100 through KRN-400 established policy admission, trusted one-shot
execution, independent verification, and bounded recovery as separate trust
boundaries. They did not prove that one authenticated task could cross those
boundaries through the actual standalone Cognitive Modules and actual Windows
UI Automation, then produce a task-level verified report without human
assembly.

The standalone Goal Compiler, Element Grounder, and Plan Ranker cannot become
dependencies of the Core workspace. A successful adapter receipt is not task
completion, and a passed action verification is not final goal closure.

## Decision

`d2i-desktop` owns `CognitiveKernelTaskRuntimeV1`, an ordered hash-chained
coordinator for one bounded task. The first product fixture changes and saves
a non-secret employee name in a local WinForms form through this sequence:

```text
authenticated instruction -> actual Goal Compiler -> GoalSpec
-> actual UIA observation -> Application Pack -> validated PlanGraph
-> actual Element Grounder -> candidates -> actual Plan Ranker -> selection
-> policy admission -> new Windows activation -> one-shot UIA execution
-> independent re-observation and verification -> bounded recovery if needed
-> final stability observation -> FinalGoalVerificationV1 -> WorkReport
-> immutable KernelTaskRunRecordV1
```

Each standalone module exposes a test/evaluation-only `e2e-host` executable.
It accepts exactly one bounded Module Contract v1 invocation on stdin, invokes
the module's actual implementation once, writes exactly one result envelope,
and exits. Core communicates only through canonical JSON and does not link any
module implementation. The host is not a production loader or Runtime ABI.

Trusted execution accepts both the earlier closed fixture argument shape and
the native `GroundedActionArgumentsV1`. Native grounded targets retain their
self-hash; the request must bind that exact hash. This is additive compatibility
and does not change Cognitive IR v1, Module Contract v1, Runtime ABI, or package
format.

The official Windows runner builds root and module workspaces into independent
Cargo target directories. `All` runs happy twice plus recovery, unsafe, and
clarification. The two happy runs must have the same normalized semantic hash.

## Safety Properties

- UI text and module output never become authority.
- Only unique grounded targets can produce candidates.
- Every action receives a distinct policy admission and Windows activation.
- Mutation and verification use separate workers and activations.
- Recovery retry creates a wholly fresh trust chain.
- Unsafe results escalate without another mutation.
- Clarification performs no activation or mutation.
- Core artifacts contain hashes and stable IDs, not raw locators, payloads,
  credentials, or absolute paths.
- Task completion requires final criteria passed, protected invariants passed,
  `GoalProgress::Complete`, and a hash-bound `WorkReport`.
- Module hosts, workers, app processes, activation material, payloads, and
  temporary fixture state must have zero residuals.

## Consequences

Track K is complete. D2I now has one machine-verifiable product gate proving a
complete authenticated single-task flow through actual modules and Windows
execution. This does not provide Role or Case autonomy, a general-purpose
module loader, arbitrary application support, or model-based planning.

The next work is `D2I-WORK-100 - Role Contract v1`; this ADR does not start it.
