# ADR 0004: Executor Selection and Evaluation

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I compiler and runtime maintainers

## Context

Phase 4 must choose among rules, lookups, native functions, classical models,
neural experts, language experts, planners, device adapters, and human review
without coupling the package to a model family or allowing cost to override
quality and safety.

## Decision

1. `d2i-eval` defines a versioned executor descriptor with capability, input
   and output schemas, target, ABI, resource estimates, security flags, license,
   and canonical artifact hash.
2. Matching applies compatibility, resource, security, and benchmark quality
   thresholds as hard gates. Missing profiles are infeasible.
3. Selection computes the feasible Pareto front and applies configurable
   normalized target costs only within that front. Stable executor ID ordering
   resolves equal costs.
4. Forced bindings pass the same hard gates. No safe binding causes a compile
   diagnostic; quality regression that removes the final safe executor is a
   build failure.
5. Typed graph optimization records every action. Optional small-first
   execution is represented by an explicit confidence failure edge.
6. Packages retain descriptors, benchmark profiles, selection rationale, and
   optimization reports as hash-verified immutable artifacts.
7. `d2ic benchmark` runs bundled cases through the offline reference runtime
   and gates task success, field accuracy, critical errors, and repeatability.

## Consequences

- Candidate choice is reproducible from source inputs and package reports.
- Different target cost profiles can choose different quality-safe executors.
- Runtime startup rechecks descriptor ABI, target, network policy, and binding
  presence without loading package-provided executable code.
- Current benchmark memory fields are unavailable and no performance
  superiority claim is made.
- Native ABI, proprietary runtime integration, and production signing remain
  later-phase work.
