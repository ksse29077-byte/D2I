# Plan Ranker

Plan Ranker is a deterministic Cognitive Module that ranks bounded metadata for
prevalidated next-action candidates. It never generates or executes an action.

## Contract

- Module ID: `plan-ranker`
- Capability: `cognitive.plan-rank` version `1.0.0`
- Input: `cognitive-plan-ranking-input-v1` version `1`
- Output: `cognitive-plan-ranking-output-v1` version `1`
- Confidence: not applicable

The invocation envelope supplies goal, observation, plan-generation, trust,
provenance, replay, deadline, and resource bindings. The payload contains no
raw action arguments or lifecycle bindings.

## Ranking Policy

Every policy, activation, binding, input-schema, output-schema, risk,
side-effect, network, credential, capability, and quality gate must be
`passed`. Failed and unknown gates are rejected in that fixed order.

Eligible candidates are ordered by:

1. normalized cost ascending
2. success likelihood descending
3. candidate SHA-256 ascending by ASCII byte
4. candidate ID ascending by ASCII byte

Rejected candidates are ordered by candidate SHA-256 and then candidate ID.
Input order therefore has no effect. The implementation uses integer
millionths, bounded insertion sorting, no floating point, no clock, and no
random source.

An empty candidate set is unsupported with reason `no_candidates`. Duplicate
candidate IDs or hashes are invalid. An all-rejected set succeeds with
`no_eligible_candidate`; the caller decides whether to replan, stop, or request
input.

## Security Boundary

Gate values are prevalidated facts from trusted boundaries. A high rank is not
policy approval, activation, or execution permission. Untrusted web and
document labels are treated only as data and cannot change gates or ranking.
The module has no network, filesystem, environment, process, browser, UI,
credential, adapter, policy, activation, audit-store, or side-effect authority.

Limits are 64 candidates, 32 evidence IDs per candidate, 1 MiB input, 1 MiB
output, 8 MiB declared memory, 4,096 logical operations, 100 logical ticks,
zero retries, and one concurrent invocation.

## Verification

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/plan-ranker
```

The reference implementation is development and conformance infrastructure. It
is not connected to a production loader, package, Runtime ABI, or executor.

`e2e-host` retains that boundary. It handles one bounded Module Contract v1
invocation for KRN-500 test/evaluation, calls the actual deterministic ranker,
returns one canonical result, and exits without gaining policy or execution
authority.

`e2e-host` retains that boundary. It handles one bounded Module Contract v1
invocation for KRN-500 test/evaluation, calls the actual deterministic ranker,
returns one canonical result, and exits without gaining policy or execution
authority.
