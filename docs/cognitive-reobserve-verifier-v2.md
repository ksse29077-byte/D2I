# Cognitive Re-observation and Verifier v2

KRN-300 removes the manual step in which a person inspected the screen after
execution. An executed action can now be independently re-observed and
classified as `passed`, `failed`, `inconclusive`, `unsupported`, or `unsafe`.
Adapter success remains only an execution fact.

## Runtime Flow

```text
TrustedActionExecutionReceiptV1 + BoundActionExecutionV2
  -> ReobservationRequestV1
  -> separately activated read-only UIA/WebDriver worker
  -> fresh ObservationSnapshot + FreshObservationProofV1
  -> VerificationGuardProfileV1 + ObservationDeltaV1
  -> existing VerificationRequestV2
  -> DeterministicPostconditionVerifierV2
  -> existing VerificationResultV2
  -> VerifiedActionResultV1
```

The mutation worker is terminated before re-observation. The observation
worker accepts only the existing read-only command, reports zero action,
navigation, script, cookie, storage, clipboard, file, and process side effects,
and is explicitly shut down before its proof is emitted.

## Strict Bindings

`VerificationSpecAdapterV1` binds the exact Goal, PolicyReady action, selected
proposal, source observation, execution receipt, and execution projection.
The only accepted target grammar is:

```text
element:<element_id>:exists
element:<element_id>:value
element:<element_id>:kind
```

The element must occur exactly once. Unknown grammar, missing elements,
duplicate criteria, lifecycle substitutions, and secret-like expected values
fail closed. Object/array values can be compared to their canonical digest so
raw desired text and locator-bearing observation objects need not enter the
postcondition contract.

## Freshness and Identity

The fresh sequence is greater than the source sequence and its observation ID
is different. UIA retains process, session, executable hash, and window-title
hash. WebDriver retains browser session, origin, browser/driver hashes, WFP
policy, and functional attestation identity. One-shot activation IDs may
differ; the proof records both the normalized logical target hash and the
fresh transport/activation hashes.

## Delta and Verdicts

Guard classes are disjoint and canonical. Unlisted changes are unexpected.
Protected security changes, identity changes, unexpected changes, and an
unexpected-count limit breach are unsafe. A missing expected delta is failed.
An unavailable or ambiguous observation is inconclusive. Unsupported grammar
or comparison is unsupported. Optional criterion failure alone does not fail
the action. Goal progress is complete only when the action passed and every
required goal criterion passed.

Delta artifacts contain element IDs, field enums, reason codes, JSON types,
and before/after hashes. They never contain raw changed values. The terminal
artifact contains hashes and bounded IDs only and explicitly states that it is
not case closure or recovery authority.

## Audit and Replay

Protected audit records request, collection, delta, verification, verdict, and
abort events using IDs and hashes only. Receipt verification is single-use.
Stale requests, source/fresh substitution, malformed strict JSON, proof
mutation, repeated begin/finalize, audit failure, side effects, or abnormal
worker exit produce no successful terminal artifact.

The strict Draft 2020-12 schema is
`schemas/cognitive/cognitive-reobserve-verifier-v2.schema.json`.

## Current Limits

- KRN-300 does not perform recovery, retry, replan, clarification, escalation,
  case closure, or production CognitiveExecutor integration.
- Live WebDriver re-observation requires deployment-provided pinned Edge and
  EdgeDriver artifacts and the existing WFP functional attestation.
- The consumption ledger is process-local; durable cross-process recovery is
  owned by the next kernel phase.
