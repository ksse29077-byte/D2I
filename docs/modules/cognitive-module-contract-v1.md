# Cognitive Module Contract v1

Contract version `1` defines a language-neutral invocation/result boundary for
side-effect-free cognitive modules. Rust types live in `d2i-module-sdk`;
canonical JSON Schema lives under `schemas/modules`.

## Authority Boundary

A module receives a typed payload and `InvocationContext`. It never receives:

- a desktop, browser, file, process, UIA, or WebDriver adapter
- policy or activation implementations
- protected audit or activation storage
- network clients, environment variables, or arbitrary filesystem handles
- mutable D2I compiler or runtime state

A module may return a goal reduction, world-state reduction, element
grounding, action candidate, plan ranking, verification result, recovery
advice, work report, retrieval result, evaluation, or generic typed
transformation. Only `CognitiveExecutor` can send an `ActionProposal` through
policy, activation, and executor boundaries.

## Identity

`ModuleIdentifier` binds:

- `module_id`
- semantic `module_version`
- `contract_version`
- `build_id`
- `artifact_sha256`
- `manifest_sha256`

IDs are bounded ASCII tokens. Hashes are lowercase
`sha256:<64 hexadecimal characters>`.

## Invocation

`ModuleInvocationEnvelope` carries identity, requested capability, exact input
schema ID/version, typed JSON payload, goal/observation/plan lifecycle
bindings, logical sequence and deadline, resource budget, trust labels,
redaction proof, provenance, deterministic replay context, correlation ID, and
trace ID.

The SDK rejects unknown fields, wrong versions, undeclared capability/schema,
expired deadlines, stale observation/plan bindings, oversized payloads,
unaccepted trust labels, raw secret fields, and resource budgets above the
manifest.

## Result

`ModuleResultEnvelope` returns exactly one terminal status:

- `succeeded`: payload present; error and unsupported reason absent
- `unsupported`: unsupported reason present; payload and error absent
- `failed`: structured error present; payload and unsupported reason absent

It also carries output schema identity, optional declared confidence, evidence,
warnings, logical resource usage/timing, replay metadata, canonical output
hash, and provenance.

## Errors

Stable error codes distinguish invalid input, unsupported input/capability,
schema/version mismatch, timeout, resource exhaustion, policy/network
prohibition, untrusted-input violation, replay mismatch, internal failure,
panic/abnormal termination, artifact mismatch, and unavailable dependencies.

Each error declares retryability, user-action requirement, a safe message,
optional redacted detail, and fallback availability.

## Canonical Hash

Canonical JSON is UTF-8, recursively sorts object keys, preserves array order,
uses no insignificant whitespace, rejects duplicate keys, limits nesting, and
accepts only finite JSON numbers. Stable hashes cover these bytes.

## Cognitive IR Mapping

- goal compiler: goal source to `GoalSpec`
- observation reducer: `ObservationSnapshot` to `WorldState`
- element grounder: observation/world state to semantic targets
- action candidate provider: `WorldState` to `ActionProposal` candidates
- plan ranker: candidates/plan to ranked plan metadata
- verifier: action execution plus fresh observation to `VerificationResult`
- recovery critic: verification failure to `RecoveryDecision`
- work reporter: goal/results/recovery/events to `WorkReport`

Future adapters may implement existing `ActionCandidateProvider`,
`WorldStateReducer`, `PostconditionVerifier`, and `RecoveryPolicy` traits by
invoking a module through this contract. The adapter must validate lifecycle
bindings and may not expose raw executor authority. Production integration is
not part of v1.
