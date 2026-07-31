# Trusted Action Execution Binding v1

## Purpose

KRN-200 connects one exact policy-admitted Cognitive action to one exact
one-shot Windows UIA or WebDriver execution:

```text
PolicyReadyActionV1
+ CognitiveActivationAdmissionV1
+ ActivationEligibilityContextV1
+ exact source ObservationSnapshot
+ TrustedExecutionSessionV1
+ actual WindowsActivationAdmission
  -> fresh read-only target resolution
  -> BoundDesktopActionV1
  -> PreparedBoundActionV1
  -> Cognitive-bound ExecutionPermit
  -> one adapter commit
  -> TrustedActionExecutionReceiptV1
```

The Core contract is implemented by `d2i-trusted-action-execution`. Platform
objects, raw target material, payload bytes, adapters, workers, and the opaque
permit remain in `d2i-desktop`.

## Authority Separation

- `PolicyReadyActionV1` selects an action but has no policy authority.
- `CognitiveActivationAdmissionV1` proves policy admission but is not a
  Windows token.
- `ActivationEligibilityContextV1` is read-only eligibility data.
- `WindowsActivationAdmission` contains the persistent ledger verification and
  the one-shot `ActivatedWindowsBinding`.
- `ExecutionPermit` is minted only after exact preparation and is checked again
  by the adapter at commit.

No Decision Envelope or Human Approval is synthesized. A Cognitive
confirmation grant remains distinct from Desktop `HumanApproval`.

## Durable Contracts

All public artifacts use Draft 2020-12 schema
`schemas/cognitive/trusted-action-execution-binding-v1.schema.json`, reject
unknown fields, use recursive canonical JSON SHA-256, and contain only bounded
IDs, hashes, times, statuses, and evidence IDs.

`TargetResolutionProofV1` contains no AutomationId, selector, accessible name,
DOM, coordinates, or handle. `InputMaterialProofV1` contains the expected and
supplied content hashes and byte length, never the bytes.

`TrustedActionExecutionReceiptV1` records the exact policy, proposal,
observation, admission, activation, preparation, permit, adapter descriptor,
target, input, and output hashes. Its successful status is an adapter-attempt
status only.

## In-Memory Material

`ResolvedTargetMaterial` holds the exact UIA window and AutomationId or the
exact WebDriver session, loopback origin, and reviewed CSS ID locator.
`EphemeralActionPayload` holds bounded non-secret bytes and clears its buffer
on drop. Neither type is cloneable or serializable, and Debug output is
redacted.

The coordinator exposes only whether live execution material remains and the
PID of its currently owned isolated worker. It exposes no process handle,
target, or payload.

## Lifecycle

1. `bind` validates all Cognitive artifacts and the source observation.
2. It projects and compares the actual Windows admission and configuration.
3. It consumes the activation to start one isolated capability adapter.
4. It resolves exactly one target and obtains a fresh read-only worker hash.
5. It validates optional non-secret input by exact content hash.
6. It creates the Desktop operation and intent through a closed six-action
   table.
7. `prepare` performs another read-only snapshot and requires the same
   precondition hash.
8. `commit` appends protected audit, mints the exact Cognitive permit, poisons
   before the action call, and executes once.
9. Terminal success, failure, cancellation, or drop releases payload, target,
   adapter, and worker ownership.

## Human Touch

한국어: 위임 범위 안의 가역적 동작은 별도 승인 클릭 없이 기존 정책과
Windows 활성화 증거를 재사용한다. 확인이 필요한 동작은 KRN-100의
구조화된 확인 절차를 그대로 따르며, KRN-200이 임의 승인을 만들지 않는다.

English: routine reversible work within delegated authority requires no new
approval touch. Confirmation remains required when KRN-100 says so, and
KRN-200 never fabricates approval.

## Verification Boundary

The receipt can be projected to existing `BoundActionExecutionV2`, but the
projection is not a verification verdict. The completed KRN-300 path
independently re-observes the target and verifies postconditions before any
verified closure or goal-complete claim.

## Focused Checks

```powershell
cargo test -p d2i-trusted-action-execution --all-features
cargo test -p d2i-desktop --test trusted_execution
cargo test -p d2i-desktop --all-features
```

The Windows fixture starts the repository's local WinForms test surface,
performs one non-secret UIA SetValue through the full signed activation path,
checks bind/prepare side-effect zero, validates the terminal receipt and audit
chain, and verifies that the exact owned worker PID and execution material are
gone.
