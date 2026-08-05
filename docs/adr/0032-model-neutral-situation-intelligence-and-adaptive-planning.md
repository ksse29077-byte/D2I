# ADR 0032: Model-Neutral Situation Intelligence and Validated Adaptive Planning

## Status

Accepted

## Context

WORK-400 ends with a non-executable `CaseWorkGrantV1`. A human still had to
interpret the approved Case context and current computer state, decide whether
information was missing or conflicting, and choose each next semantic action.
The existing Goal Compiler and Safe Execution Kernel did not provide a
model-backed, Case-bound situation and replanning boundary.

## Decision

`ApprovedCaseContextBundleV1` is the only provider context. It contains bounded
IDs and hashes for the Case, Role, ownership, lease, Work Grant, approved
artifacts, fresh observations, trust labels, and redaction evidence. It is
evidence, not authority, and excludes credentials, activation material, raw
locators, commands, and unrestricted content.

`CaseSituationModelV1` keeps observed facts, trusted system facts, approved
policy and procedure facts, authenticated assertions, model inferences,
unknowns, and conflicts in separate trust classes. Model inference cannot be
promoted to policy, authority, or observation. Missing and contradictory input
remains explicit and cannot be converted to false or silently selected.

`IntelligenceProvider` is model-neutral and exposes only bounded goal,
situation, and next-step operations. A provider has no adapter, policy,
activation, credential, process-launch, filesystem-write, or network
authority. Provider output crosses strict JSON parsing, exact lifecycle/hash
binding, typed validation, Application and Capability allowlists, Action
Selection, Policy Admission, Activation, one-step Trusted Execution,
re-observation, and independent verification.

The WORK-500 product provider is pinned Qwen3-4B Q4_K_M through pinned
llama.cpp. The executable and model hashes are verified before launch. Every
invocation is a one-shot process inside a zero-capability AppContainer and a
bounded Windows Job Object, with an environment allowlist, no shell, no
network capability, bounded output, a 45-second deadline, zero retry, and
process-tree cleanup. The model/runtime artifacts remain outside Git.

Natural-language input first produces a `GoalDraft`. Only complete, bounded,
non-expanding output is converted to the existing trusted Cognitive IR v1
`GoalSpec`. Missing or ambiguous requirements produce deterministic
clarification rather than an incomplete Goal. Untrusted instructions and
authority expansion fail closed.

Adaptive planning emits at most one semantic next-step candidate per cycle.
Candidate capability, target, approved value hash, preconditions,
postconditions, risk, and evidence must be exact subsets of the trusted
request. A plan is invalid after state, lease, ownership, Case, or generation
change. Execution is always followed by fresh observation and verification,
then situation update and replan or verified Case closure.

No unrestricted chain-of-thought is requested or persisted. Evidence is
limited to bounded reason codes, selected evidence IDs, confidence, concise
summaries, and uncertainty labels.

Product completion requires actual model load and inference, a held-out
evaluation, adaptive Windows path divergence, existing KRN execution,
independent verified closure, regressions, and zero residual execution state.
Deterministic and recorded providers remain development/replay evidence only.

## Consequences

- Models cannot call adapters or mint policy, activation, completion, or Case
  authority.
- Situation provenance and uncertainty survive model use.
- A changed observation can select a different bounded action without a fixed
  full action sequence.
- Exact recorded-result replay is distinct from live semantic replay and
  verified outcome replay; bitwise live inference determinism is not claimed.
- Crash windows A through F recover from durable hashes and require fresh
  context or observation before any later mutation.
- Core treats work-class IDs as opaque; General Office, HR, IT, and Safety
  remain fixtures, not built-in taxonomy.

## Alternatives

A rule-only provider was rejected as product completion evidence because it
does not establish natural-language intelligence. Direct model-to-adapter
execution was rejected because it bypasses semantic binding and the Safe
Execution Kernel. A fixed full plan was rejected because it becomes stale
after the first state change. A remote provider was rejected because v1 is
offline and network-denied. Persisted model reasoning traces were rejected to
avoid sensitive-data and audit-boundary expansion.

## Rollback And Migration

WORK-500 is additive. Disable the local provider and retain WORK-100 through
WORK-400 contracts and ledgers unchanged. A future provider, Situation Model,
or planner version must use new schema IDs and migrate only from verified v1
artifacts; it may not rewrite v1 ledgers. WORK-600 may consume bounded verified
episodes, but it cannot mutate provider output or production state in place.
