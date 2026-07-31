# ADR 0025: Fresh Re-observation and Protected-Invariant Cognitive Verification

## Status

Accepted

## Context

KRN-200 proves that one admitted action reached one certified adapter and
records the adapter-attempt result. It does not prove that the intended state
was produced. Reusing the mutation worker would retain action authority and
would let execution evidence masquerade as observation evidence.

Verification Contract v2 already defines `VerificationRequestV2`,
`VerificationResultV2`, typed postconditions, five verdicts, exact lifecycle
binding, and a side-effect-free verifier trait. Those types remain the
authoritative verification contract.

## Decision

KRN-300 adds product-owned context around, not a replacement for,
Verification Contract v2:

1. A receipt-bound `ReobservationRequestV1` requires a new one-shot read-only
   UIA or WebDriver worker after the mutation worker has exited.
2. `FreshObservationProofV1` binds the new sequence and observation ID to the
   same logical process/session/window or browser-session/origin, while also
   retaining the fresh activation and transport hashes.
3. `VerificationSpecAdapterV1` accepts only the closed grammar
   `element:<element_id>:{exists|value|kind}`. It performs no fuzzy, label, or
   model-based targeting.
4. `VerificationGuardProfileV1` requires at least one exact expected, allowed,
   protected, or explicitly reviewed volatile target. Empty and ignore-all
   profiles are rejected. The Windows fixture protects a second UI field.
5. `ObservationDeltaV1` joins by exact element ID, records hashes and JSON
   types rather than old/new raw values, and separates expected, allowed,
   protected, unexpected, security-relevant, and ignored volatile changes.
6. A protected security invariant, target binding change, unexpected change,
   or unexpected-change limit breach is `unsafe`, even when execution failed
   or another postcondition passed.
7. UIA observation-status metrics may vary between independent collections.
   They may be ignored only as the exact `observation.status:value` target with
   a reason code and evidence ID. Process/session/window identity is never
   ignored.
8. Verification v2 scalar equality is preserved. For an observed JSON object
   or array and a valid lowercase `sha256:` expected string, equality means
   equality with the canonical observed-value digest. This avoids raw input or
   locator-bearing objects in Goal or Action artifacts.
9. `VerifiedActionResultV1` binds all proof hashes. It is not case closure,
   recovery authority, retry authority, or a complete `WorkReport`.
10. A process-local receipt-consumption ledger rejects duplicate begin and
    duplicate terminal verification. Protected audit failure prevents a
    successful terminal result.

All new serialized artifacts use strict JSON, bounded collections, canonical
ordering, self-hash exclusion, and the shared lowercase SHA-256 convention.

## Alternatives Rejected

- Reusing the mutation worker: retains mutation authority during verification.
- Treating adapter `succeeded` or state-hash inequality as verification:
  cannot prove the intended value or absence of collateral change.
- Verification Contract v3: duplicates an existing sufficient contract.
- Label/fuzzy target matching: lets untrusted UI text redirect authority.
- Default ignore-all delta policy: hides collateral changes.
- A standalone verifier module as the runtime boundary: does not own Windows
  activation, worker cleanup, or protected audit.

## Consequences

The local WinForms SetValue fixture is independently re-observed and
classified. UIA and WebDriver use the same one-shot read-only coordinator;
live WebDriver execution still depends on deployment-provided pinned Edge and
EdgeDriver artifacts. Recovery, retry, replan, clarification, escalation,
case closure, and production `CognitiveExecutor` integration remain outside
KRN-300.
