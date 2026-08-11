# ADR 0044: D2I-Owned Semantic Experience Compilation for External World Cores

- Status: Accepted
- Date: 2026-08-11
- Owners: Cognitive Core, Learning, Desktop trust boundary
- Scope: External world-model integration foundation

## Context

The imported B_Core package contains a product-agnostic dockable semantic core,
research world-model contracts, source, sealed artifacts, and Windows
binaries. Its own integration guide requires products to translate through an
adapter rather than adding product-specific behavior to the core.

The package's public `dockable-semantic-core` ABI v1 accepts bounded `GoalIR`
and `CapabilityContract` values. It does not publish an API for ingesting an
observed world transition. SEM31 world events and SEM32 observed transitions
exist in the separate `semantic-reasoning` research crate and are not a stable
public dockable-core contract. The supplied manifest also records failed clean
reconstruction and full-workspace test gates, and the source declares
`UNLICENSED`.

Directly linking D2I to those research internals would invent an unsupported
production API, couple PC semantics to B_Core, and bypass D2I's existing
observation, execution, verification, privacy, and offline-promotion controls.

## Decision

D2I owns a platform-neutral Semantic Experience Compiler:

```text
trusted source observation
  -> admitted and receipt-bound PC action
  -> independent fresh observation
  -> Verification v2 and protected-delta result
  -> bounded context slice
  -> typed/hash-only SemanticExperienceV1
  -> quarantined offline candidate
  -> optional inert B_Core numeric projection
```

Safe booleans and signed integers retain their type. Text, URLs, paths,
compound values, DOM/UI labels, and untrusted instructions are represented
only by canonical SHA-256 digests. Secret-bearing fields and raw credential
patterns are rejected. Numeric entity, axis, capability, operator, and target
codes are deterministic and collision-checked within each experience.

The Desktop bridge must revalidate the trusted execution receipt, bound
execution, re-observation request, fresh-observation proof, Verification v2
request/result, guard profile binding, observation delta, and terminal verified
action result before compilation. The output contains exact organization,
Role, Case, policy/evidence, and observation hashes but no adapter handle,
capability grant, policy admission, activation token, executable path, raw
content, or authority.

Every experience is `quarantined_offline_only` and
`no_execution_authority`. It cannot mutate B_Core, D2I production packages,
Role/Policy/Application Packs, routing, activation, or an executing Case.

The current B_Core compatibility projection uses only the generic numeric
shape shared by the observed SEM31/SEM32 research contracts. It explicitly
sets `public_ingest_available=false` and `production_eligible=false`. D2I does
not load or execute imported B_Core binaries, vendor its source, or make it a
workspace dependency.

## Production Gate

A future production B_Core adapter requires all of the following in a separate
approved change:

1. A documented, versioned public semantic-experience ingestion ABI.
2. Exact package, source commit, ABI, semantic-state, and signer pinning.
3. Approved licensing for the intended deployment and redistribution scope.
4. Clean offline reconstruction and full workspace/all-target/all-feature tests.
5. Independent conformance, replay, poisoning, isolation, and no-authority tests.
6. Existing D2I offline evaluation and explicit candidate-promotion gates.

Package presence, a numeric projection, or a successful research run satisfies
none of these gates.

## Alternatives

### Add PC-use learning directly to B_Core

Rejected. It would make the world core product-specific and move OS trust,
credential, observation, and execution concerns into the reasoning substrate.

### Depend on `semantic-reasoning` SEM31/SEM32 internals

Rejected. Those types are research contracts outside the documented public
dockable-core ABI and can drift without a product integration guarantee.

### Commit the portable package into D2I

Rejected. The package is approximately 504 MiB, contains 81 executables and a
vendored dependency closure, is `UNLICENSED`, and has failed declared build/test
gates. D2I records only a path-free manifest descriptor and keeps the artifact
external.

## Consequences

D2I can compile verified PC experience into a small deterministic semantic
form without exposing raw desktop content or giving a model new authority.
B_Core remains product-agnostic and replaceable. Actual world-model learning is
deliberately unavailable until its public contract, license, and quality gates
are complete.
