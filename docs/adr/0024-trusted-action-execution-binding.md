# ADR 0024: Trusted Action Execution Binding v1

## Status

Accepted

## Context

`PolicyReadyActionV1` is an exact selected action and
`CognitiveActivationAdmissionV1` proves a policy outcome. Neither is an
adapter token. Windows separately admits a signed runtime binding through a
persistent activation ledger and yields one non-cloneable
`ActivatedWindowsBinding`.

The system needs one boundary that joins those authorities without letting
Cognitive data mint Windows authority, without copying raw locators or input
into durable artifacts, and without changing the existing Decision Envelope,
Human Approval, Desktop Executor, Verification v2, Runtime ABI, or Cognitive
IR contracts.

## Decision

Add the side-effect-free Core crate `d2i-trusted-action-execution` and an
additive Windows integration in `d2i-desktop`.

The Core crate owns canonical, audit-safe contracts:

- `TrustedExecutionSessionV1`
- `TrustedExecutionBindingRequestV1`
- `TrustedPlatformActivationV1`
- `TargetResolutionProofV1`
- `InputMaterialProofV1`
- `BoundDesktopActionV1`
- `PreparedBoundActionV1`
- `TrustedActionExecutionReceiptV1`

The request embeds the exact policy-ready action, Cognitive admission,
activation eligibility, execution session, source observation identities, and
a projection of the actual Windows activation. It validates their complete
hash, lifecycle, integration, adapter, ledger, observation, and capability
intersection.

The product-side `CognitiveTrustedExecutionCoordinator` consumes the complete
`WindowsActivationAdmission`. It starts exactly one certified UIA or WebDriver
adapter, resolves the selected target using the existing read-only worker
snapshot command, prepares without mutation, mints a separate Cognitive permit
digest, commits at most once, emits a terminal receipt, and drops the worker
and ephemeral material.

## Closed Mapping

v1 supports only:

| Cognitive capability | Desktop operation |
| --- | --- |
| `uia.invoke` | UIA Invoke |
| `uia.set_value` | UIA SetText |
| `uia.toggle` | UIA Toggle |
| `webdriver.click` | WebDriver Click |
| `webdriver.type` | WebDriver TypeText |
| `webdriver.select` | WebDriver Select |

Each mapping requires an exact typed `CandidateActionInput`, source kind,
adapter kind, selected element, capability binding, policy admission, and
Windows adapter capability. There is no string-prefix fallback, coordinate
fallback, label-derived locator, arbitrary XPath, JavaScript, navigation,
file, process, clipboard, credential, or irreversible action path.

## Target and Input Ownership

`ResolvedTargetMaterial`, `TrustedTargetResolverInput`,
`TrustedDesktopExecutionPlan`, and `EphemeralActionPayload` do not implement
serialization or cloning. Debug output redacts raw target and payload values.

UIA resolution requires the exact process, Windows session, executable hash,
window title hash, AutomationId, enabled state, and operation-specific
read-only pattern state. Web resolution requires the exact activated browser
session, loopback origin, Edge and EdgeDriver pins, live WFP binding, and one
reviewed CSS ID locator that has exactly one matching observation hint.

Durable artifacts contain only canonical SHA-256 digests and bounded IDs.
Input is accepted only as bounded UTF-8 from an explicitly trusted non-secret
source. Credential-like input and `secret_ref` are rejected. The buffer is
overwritten and released when execution becomes terminal or the coordinator
is dropped.

## Prepare and Commit

`bind` and `prepare` may perform identity checks, read-only snapshots, hash
checks, and protected audit appends. They cannot perform the requested action.
The precondition hash from adapter preparation must equal the fresh target
resolution snapshot.

`commit` checks the pending binding and one-shot identities, appends the
pre-commit audit record, creates a Cognitive-specific permit digest, poisons
the coordinator before adapter execution, and calls the adapter once. Success,
adapter failure, cancellation, and abort all consume or destroy the available
execution material. A terminal audit failure is returned as failure and does
not turn an adapter result into a successful coordinator result.

The existing Human Approval permit digest and Decision Envelope path are
unchanged. A `ConfirmationGrantV1` is not converted into `HumanApproval`.

## Receipt Semantics

`TrustedActionExecutionReceiptV1::status = succeeded` means only that the
adapter reported a successful action attempt. It does not mean that a
postcondition passed, the goal completed, or verified closure was reached.

`to_verification_bound_execution_v2` performs a closed projection into the
existing `BoundActionExecutionV2`. It creates no verification verdict.
Re-observation and postcondition verification belong to D2I-KRN-300.

## Audit

The existing protected Windows deployment audit records binding creation,
target resolution, preparation, permit minting, commit start, success,
failure, cancellation, and abort. Records contain IDs, hashes, status, and
bounded result codes only. Raw locators, AutomationIds, input, adapter output,
credentials, and secrets are excluded.

## Alternatives

### Treat Cognitive Admission as an Adapter Token

Rejected. Policy authority and platform activation are independent trust
boundaries.

### Reuse DecisionEnvelope and HumanApproval

Rejected. Synthesizing either artifact would falsify provenance and alter the
legacy execution contract.

### Serialize Resolved Targets

Rejected. Durable locators and handles expand replay and leakage surfaces.

### Verify Postconditions During Commit

Rejected. It would collapse execution and independent verification. KRN-300
owns re-observation and verification.

## Security Consequences

- the Core crate has no filesystem, process, network, UI, or adapter authority
- strict JSON rejects duplicate and unknown fields
- all lifetimes, strings, collections, and input bytes are bounded
- substitutions across proposal, observation, policy, admission, ledger,
  activation, adapter, target, input, and preparation fail closed
- Windows activation is consumed exactly once by the adapter constructor
- the worker is job-owned and removed with terminal execution material
- adapter success is explicitly not a verified completion claim

## Rollback

The feature is additive. Removing the new crate, schema, product integration,
tests, and documentation restores the prior Desktop paths without changing
their hashes or behavior.
