# ADR 0014: Contract-Governed Cognitive Task Runtime

- Status: Accepted
- Date: 2026-07-28
- Decision owners: D2I cognitive core, runtime, policy, and desktop maintainers

## Context

The desktop autonomy product already has a signed, policy-gated execution
plane for concrete Windows adapters. D2I also needs a cognitive plane that can
turn a goal and observation into bounded, verifiable action proposals without
allowing a model or untrusted content to hold adapter authority.

This decision freezes the Cognitive IR v1 contract and a deterministic,
model-free reference executor. It deliberately does not implement natural
language models, GUI, real UI Automation or Web observation, WebDriver
execution, WFP, external network behavior, or production package changes.

## Decision

1. Models never call adapters directly. A model, rule, or future planner may
   only emit a typed `ActionProposal` that is validated before execution.
2. Model or planner output must pass JSON Schema validation or Rust type
   validation with strict unknown-field rejection before it can influence
   execution.
3. The runtime executes exactly one action step at a time.
4. Every action has explicit preconditions and expected postconditions.
5. After each execution attempt, the runtime must obtain a fresh
   `ObservationSnapshot`.
6. If the fresh observation does not satisfy expected postconditions, the
   remaining plan is not executed blindly.
7. All loops, retries, replans, recovery paths, and total execution steps have
   explicit upper bounds.
8. Unsupported capabilities, incomplete contracts, stale observations, stale
   plan generations, unsupported versions, and invalid enum values fail closed.
9. Web pages, documents, UI text, and fixture text are untrusted content by
   default and are never promoted into executable instructions.
10. Irreversible actions are unsupported by the baseline executor.
11. Real policy, activation, and audit implementations sit behind narrow
    traits. The reference implementation uses deterministic mocks only.
12. The baseline CognitiveExecutor is model-free, offline, and replayable from
    the same typed fixtures.

## Consequences

- Cognitive planning is portable across Windows, browser, file, process, and
  future adapters because the cognitive plane depends only on capability and
  action traits.
- The baseline executor can be used for schema, replay, recovery, and security
  tests without producing host side effects.
- Future learned planners must conform to Cognitive IR v1 rather than receiving
  adapter handles or arbitrary tool access.
- Recovery can be adaptive only within declared bounds. Unknown drift stops or
  requests human input instead of continuing the stale plan.
- Package format and Runtime ABI remain unchanged. Any attempt to embed
  Cognitive IR v1 into production packages requires a separate RFC and package
  compatibility decision.

## Validation

- Cognitive IR Rust/JSON round trip and schema tests
- strict unknown-field, enum, and version rejection
- stable observation and report hashes
- plan DAG cycle and unbounded-loop rejection
- single-step execute, reobserve, verify ordering
- stale observation and stale plan-generation rejection
- policy and activation deny before executor invocation
- bounded retry, reobserve, and replan fixtures
- deterministic replay with identical `WorkReport`
- audit fail-closed fixture
- untrusted observation content is not elevated to an action
